#include "NewNTKernelTools.h"

#ifndef HEADER_SIZE
#define HEADER_SIZE 0x1000
#endif

WinCtx* winGlobal = NULL;

// from Aristoteles.c
extern EFI_SMM_SYSTEM_TABLE2		*gSmst2;

/*
  The low stub (if exists), contains PML4 (kernel DirBase) and KernelEntry point.
  Credits: PCILeech
*/
static BOOLEAN CheckLow(UINT64* pml4, UINT64* kernelEntry)
{
	UINT64 o = 0;
	while (o < 0x100000)
	{
		o += 0x1000;

		// Check if address is okay
		if (IsAddressValid(o) == TRUE)
		{
			if (0x00000001000600E9 != (0xffffffffffff00ff & *(UINT64*)(void*)(o + 0x000))) { continue; } // START 
			if (0xfffff80000000000 != (0xfffff80000000003 & *(UINT64*)(void*)(o + 0x070))) { continue; } // KERNEL 
			if (0xffffff0000000fff & *(UINT64*)(void*)(o + 0x0a0)) { continue; }                         // PML4
			*pml4 = *(UINT64*)(void*)(o + 0xa0);
			*kernelEntry = *(UINT64*)(void*)(o + 0x70);

			return TRUE;
		}
	}
	return FALSE;
}


static BOOLEAN findNtosKrnl(UINT64 kernelEntry, UINT64 PML4, UINT64 *ntKernel)
{

	// Check nulled kernelEntry
	SerialPrintStringDebug("  Trying to find Ntos kernel ... \r\n");

	UINT64 physicalFirst = 0;
	physicalFirst = VTOP(kernelEntry & 0xFFFFFFFFFF000000, PML4, FALSE);

	if (IsAddressValid(physicalFirst) == TRUE && physicalFirst != 0)
	{
		if (((kernelEntry & 0xFFFFFFFFFF000000) & 0xfffff) == 0 && *(short*)(void*)(physicalFirst) == IMAGE_DOS_SIGNATURE)
		{
			int kdbg = 0, poolCode = 0;
			for (int u = 0; u < 0x1000; u++)
			{
				kdbg = kdbg || *(UINT64*)(void*)(physicalFirst + u) == 0x4742444b54494e49;
				poolCode = poolCode || *(UINT64*)(void*)(physicalFirst + u) == 0x45444f434c4f4f50;
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
		if ((((kernelEntry & 0xFFFFFFFFFF000000) + 0x2000000) & 0xfffff) == 0 && *(short*)(void*)(physicalSec) == IMAGE_DOS_SIGNATURE)
		{
			int kdbg = 0, poolCode = 0;
			for (int u = 0; u < 0x1000; u++)
			{
				kdbg = kdbg || *(UINT64*)(void*)(physicalSec + u) == 0x4742444b54494e49;
				poolCode = poolCode || *(UINT64*)(void*)(physicalSec + u) == 0x45444f434c4f4f50;
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
					if (((i + p) & mask) == 0 && *(short*)(void*)(physicalP) == IMAGE_DOS_SIGNATURE)
					{
						int kdbg = 0, poolCode = 0;
						for (u = 0; u < 0x1000; u++)
						{
							if (IsAddressValid(p + u) == FALSE)
								continue;

							kdbg = kdbg || *(UINT64*)(void*)(physicalP + u) == 0x4742444b54494e49;
							poolCode = poolCode || *(UINT64*)(void*)(physicalP + u) == 0x45444f434c4f4f50;
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
		free((char*)list.list[i].name);

	free(list.list);
	list.list = NULL;
}


UINT64 GetProcAddress(const WinCtx* ctx, const WinProc* process, UINT64 module, const char* procName)
{
	WinExportList exports;

	if (!GenerateExportList(ctx, process, module, &exports))
		return 0;

	UINT64 ret = FindProcAddress(exports, procName);
	FreeExportList(exports);
	return ret;
}


UINT64 FindProcAddress(const WinExportList exports, const char* procName)
{
	for (UINT32 i = 0; i < exports.size; i++)
		if (!strcmp(procName, exports.list[i].name))
			return exports.list[i].address;
	return 0;
}



static UINT16 GetNTVersion(const WinCtx* ctx)
{
	UINT64 getVersion = FindProcAddress(ctx->ntExports, "RtlGetVersion");

	if (!getVersion)
  {
    SerialPrintString("ERROR: Failed finding RtlGetVersion \r\n");
    return 0;
  }

	char buf[0x100];

  v_memCpy((UINT64)buf, getVersion, 0x100, ctx->initialProcess.dirBase, FALSE);

	char major = 0, minor = 0;

	/* Find writes to rcx +4 and +8 -- those are our major and minor versions */
	for (char* b = buf; b - buf < 0xf0; b++) {
		if (!major && !minor)
			if (*(UINT32*)(void*)b == 0x441c748)
				return ((UINT16)b[4]) * 100 + (b[5] & 0xf);
		if (!major && (*(UINT32*)(void*)b & 0xfffff) == 0x441c7)
			major = b[3];
		if (!minor && (*(UINT32*)(void*)b & 0xfffff) == 0x841c7)
			minor = b[3];
	}

	if (minor >= 100)
		minor = 0;

	return ((UINT16)major) * 100 + minor;
}


static UINT32 GetNTBuild(const WinCtx* ctx)
{
	UINT64 getVersion = FindProcAddress(ctx->ntExports, "RtlGetVersion");

	if (!getVersion)
  {
    SerialPrintString("ERROR: Failed finding RtlGetVersion \r\n");
    return 0;
  }

	char buf[0x100];
  v_memCpy((UINT64)buf, getVersion, 0x100, ctx->initialProcess.dirBase, FALSE);

	/* Find writes to rcx +12 -- that's where the version number is stored. These instructions are not on XP, but that is simply irrelevant. */
	for (char* b = buf; b - buf < 0xf0; b++) {
		UINT32 val = *(UINT32*)(void*)b & 0xffffff;
		if (val == 0x0c41c7 || val == 0x05c01b)
			return *(UINT32*)(void*)(b + 3);
	}

	return 0;
}


static BOOLEAN SetupOffsets(WinCtx* ctx)
{
	switch (ctx->ntVersion) {
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
			  .teb = 0xb0
		  };
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
			  .teb = 0xb8
		  };
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
			  .teb = 0xf0
		  };
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
			  .teb = 0xf0
		  };
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
			  .teb = 0xf0
		  };

		  if (ctx->ntBuild >= 18362) { /* Version 1903 or higher */
			  ctx->offsets.apl = 0x2f0;
			  ctx->offsets.threadListEntry = 0x6b8;
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


	if(winGlobal)
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
	v_memCpy((UINT64)&systemProcess, PsInitialSystemProcess, sizeof(UINT64), PML4, verbose);

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


BOOLEAN ParseExportTable(const WinCtx* ctx, const WinProc* process, UINT64 moduleBase, IMAGE_DATA_DIRECTORY* exports, WinExportList* outList)
{
  BOOLEAN verbose = FALSE;

	if (exports->Size < sizeof(IMAGE_EXPORT_DIRECTORY) || exports->Size > 0x7fffff || exports->VirtualAddress == moduleBase)
		return FALSE;

	UINT64 realSize = exports->Size & 0xFFFFFFFFFFFFF000;
	realSize = realSize + 0x1000;

	EFI_PHYSICAL_ADDRESS physAddr;
	char *buf;
	EFI_STATUS ret = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, (realSize / 0x1000), &physAddr);

	if (ret != EFI_SUCCESS)
	{
		SerialPrintString("  Failed allocating pages while parsing export table! \r\n");
		return FALSE;
	}

	buf = (char *)physAddr;

	IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(void*)buf;

	for (int i = 0; i < (realSize / 0x1000); i++)
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
	UINT32* names = (UINT32*)(void*)(buf + exportDir->AddressOfNames - exportOffset);

	// THIS FAILS FOR KERNEL32.DLL
	// TODO: FIX IT!
	if (exportDir->AddressOfNames - exportOffset + exportDir->NumberOfNames * sizeof(UINT32) > exports->Size)
	{
		gSmst2->SmmFreePages(physAddr, (realSize / 0x1000));
		return FALSE;
	}
	UINT16* ordinals = (UINT16*)(void*)(buf + exportDir->AddressOfNameOrdinals - exportOffset);
	if (exportDir->AddressOfNameOrdinals - exportOffset + exportDir->NumberOfNames * sizeof(UINT16) > exports->Size)
	{
		gSmst2->SmmFreePages(physAddr, (realSize / 0x1000));
		return FALSE;
	}
	UINT32* functions = (UINT32*)(void*)(buf + exportDir->AddressOfFunctions - exportOffset);
	if (exportDir->AddressOfFunctions - exportOffset + exportDir->NumberOfFunctions * sizeof(UINT32) > exports->Size)
	{
		gSmst2->SmmFreePages(physAddr, (realSize / 0x1000));
		return FALSE;
	}

	SerialPrintStringDebug("  Dynamically allocating table ...\r\n");
	outList->size = exportDir->NumberOfNames;
	outList->list = (WinExport*)malloc(sizeof(WinExport) * outList->size);

	if(!outList->list)
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


BOOLEAN GenerateExportList(const WinCtx* ctx, const WinProc* process, UINT64 moduleBase, WinExportList* outList)
{
	UINT8 is64 = 0;
	UINT8 headerBuf[HEADER_SIZE];

	IMAGE_NT_HEADERS64* ntHeader64 = GetNTHeader(ctx, process, moduleBase, headerBuf, &is64);

	if (!ntHeader64)
		return FALSE;

	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)ntHeader64;

	IMAGE_DATA_DIRECTORY* exportTable = NULL;
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


IMAGE_NT_HEADERS* GetNTHeader(const WinCtx* ctx, const WinProc* process, UINT64 address, UINT8* header, UINT8* is64Bit)
{
  v_memCpy((UINT64)header, address, HEADER_SIZE, process->dirBase, FALSE);

	//TODO: Allow the compiler to properly handle alignment
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(void*)header;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(void*)(header + dosHeader->e_lfanew);
	if ((UINT8*)ntHeader - header > HEADER_SIZE - 0x200 || ntHeader->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	if(ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return NULL;

	*is64Bit = ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

	return ntHeader;
}


BOOLEAN FindProcess(WinCtx *ctx, char *processname, BOOLEAN verbose)
{
	UINT64 curProc = ctx->initialProcess.physProcess;
	UINT64 virtProcess = ctx->initialProcess.process;

	if(verbose)
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
			session = (UINT64*)(curProc + ctx->offsets.session);

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
			dirBase = (UINT64*)(curProc + ctx->offsets.dirBase);

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
			pid = (UINT64*)(curProc + ctx->offsets.apl - 8);

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
			char *name;

			if (IsAddressValid(curProc + ctx->offsets.imageFileName) == TRUE)
			{
				name = (char*)(curProc + ctx->offsets.imageFileName);

				if(!strcmp(name, "System"))
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
			tempVirt = (UINT64*)(curProc + ctx->offsets.apl);

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
	if(!foundSystemProcess)
		InitGlobalWindowsContext();

	return FALSE;
}


BOOLEAN DumpSingleProcess(WinCtx *ctx, char *processname, WinProc *process, BOOLEAN verbose)
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
			session = (UINT64*)(curProc + ctx->offsets.session);

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
			dirBase = (UINT64*)(curProc + ctx->offsets.dirBase);

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
			pid = (UINT64*)(curProc + ctx->offsets.apl - 8);

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
			char *name;

			if (IsAddressValid(curProc + ctx->offsets.imageFileName) == TRUE)
			{
				name = (char*)(curProc + ctx->offsets.imageFileName);

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
			tempVirt = (UINT64*)(curProc + ctx->offsets.apl);

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


static BOOLEAN DumpSingleModule64(const WinCtx* ctx, const WinProc* process, WinModule* out_module, BOOLEAN* x86, BOOLEAN verbose)
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

	PEB_LDR_DATA* ldr;

	UINT64 physLdr = VTOP(peb.Ldr, process->dirBase, FALSE);

	if (IsAddressValid(physLdr) == FALSE)
	{
		SerialPrintString("ERROR: Phys Ldr is invalid while dumping module!\r\n");
		return FALSE;
	}

	ldr = (PEB_LDR_DATA*)physLdr;
	UINT64 head = ldr->InMemoryOrderModuleList.f_link;
	
	UINT64 end = head;
	UINT64 prev = head+1;

	BOOLEAN module_found = FALSE;

	do {
		prev = head;

		unsigned char modBuffer[sizeof(LDR_MODULE)];
		LDR_MODULE *mod = (LDR_MODULE*)modBuffer;

		v_memCpy((UINT64)mod, head - sizeof(LIST_ENTRY_WIN), sizeof(LDR_MODULE), process->dirBase, FALSE);
		v_memCpy((UINT64)&head, head, sizeof(head), process->dirBase, FALSE);

		if (!mod->BaseDllName.length || !mod->SizeOfImage)
		{
			continue;
		}


		if (mod->BaseDllName.buffer == 0)
		{
			continue;
		}

		unsigned char oldBuffer[0x28];
		v_memCpy((UINT64)oldBuffer, mod->BaseDllName.buffer, 0x28, process->dirBase, FALSE);

		char newBuffer[0x15];
		for (int i = 0; i < 0x14; i++)
			newBuffer[i] = ((char*)oldBuffer)[i * 2];
		newBuffer[0x15 - 1] = '\0';

		

		if (*(short*)(void*)newBuffer == 0x53)
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
		if(!strcmp("wow64.dll", newBuffer))
		{
			*x86 = TRUE;
			return FALSE;
		}
	} while (head != end && head != prev);

	if(!module_found)
	{
		SerialPrintString("ERROR: Could not find module ");
		SerialPrintString(out_module->name);
		SerialPrintString("\r\n");
	}

	return module_found;
}


static BOOLEAN DumpSingleModule86(const WinCtx* ctx, const WinProc* process, WinModule* out_module, BOOLEAN verbose)
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

	ldr = (PEB_LDR_DATA32*)physLdr;

	SerialPrintStringDebug("  Head Flink: ");
	SerialPrintNumberDebug(ldr->InMemoryOrderModuleList.f_link, 16);
	SerialPrintStringDebug("\r\n");


	UINT32 head = ldr->InMemoryOrderModuleList.f_link;

	UINT32 end = head;

	UINT32 prev = head + 1;

	do
	{
		prev = head;

		unsigned char modBuffer[sizeof(LDR_MODULE32)];
		LDR_MODULE32 *mod = (LDR_MODULE32*)modBuffer;

		v_memCpy((UINT64)mod, head - sizeof(LIST_ENTRY_32_WIN), sizeof(LDR_MODULE32), dirBase, verbose);
		v_memCpy((UINT64)&head, head, sizeof(head), dirBase, verbose);

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

		unsigned char oldBuffer[0x28];
		v_memCpy((UINT64)oldBuffer, mod->BaseDllName.buffer, 0x28, dirBase, verbose);

		char newBuffer[0x15];
		for (int i = 0; i < 0x14; i++)
			newBuffer[i] = ((char*)oldBuffer)[i * 2];
		newBuffer[0x15 - 1] = '\0';

		SerialPrintStringDebug("MN ");
		for (int i = 0; i < 0x15; i++)
		{
			// what the fuck?
			// SerialPrintString(newBuffer[i]);
		}
		SerialPrintStringDebug("\r\n");

		if (*(short*)(void*)newBuffer == 0x53)
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



BOOLEAN DumpSingleModule(const WinCtx* ctx, const WinProc* process, WinModule* out_module, BOOLEAN verbose)
{
	BOOLEAN x86 = FALSE;
	BOOLEAN ret = DumpSingleModule64(ctx, process, out_module, &x86, verbose);

	if(ret == FALSE && x86 == FALSE)
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

PEB GetPeb(const WinCtx* ctx, const WinProc* process)
{
	PEB peb;
	UINT64 ppeb = 0;
	p_memCpy((UINT64)&ppeb, process->physProcess + ctx->offsets.peb, sizeof(UINT64), FALSE);
	v_memCpy((UINT64)&peb, ppeb, sizeof(PEB), process->dirBase, FALSE);
	return peb;
}


PEB32 GetPeb32(const WinCtx* ctx, const WinProc* process)
{
	PEB32 peb;
	UINT64 ppeb = 0;

	p_memCpy((UINT64)&ppeb, process->physProcess + ctx->offsets.peb, sizeof(UINT64), FALSE);
	v_memCpy((UINT64)&peb, ppeb + 0x1000, sizeof(PEB32), process->dirBase, FALSE);

	return peb;
}