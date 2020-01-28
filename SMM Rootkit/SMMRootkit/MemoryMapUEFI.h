#ifndef __smmrootkit_mm_uefi_h__
#define __smmrootkit_mm_uefi_h__

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>



BOOLEAN IsUefiPageNotPresent(IN EFI_MEMORY_DESCRIPTOR  *MemoryMap);


BOOLEAN InitUefiMemoryMap();


BOOLEAN IsAddressValid(UINT64 address);


EFI_MEMORY_DESCRIPTOR* GetUefiMemoryMap();


VOID ShowMemoryMap();


#endif