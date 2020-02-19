#include "MemoryMapUEFI.h"

EFI_EXIT_BOOT_SERVICES gOrigExitBootServices;
EFI_MEMORY_DESCRIPTOR *mUefiMemoryMap;
UINTN mUefiMemoryMapSize;
UINTN mUefiDescriptorSize;
extern EFI_BOOT_SERVICES *lBS; // From SMMRootkit.c

#define NEXT_MEMORY_DESCRIPTOR(MemoryDescriptor, Size) \
  ((EFI_MEMORY_DESCRIPTOR *)((UINT8 *)(MemoryDescriptor) + (Size)))

#define PREVIOUS_MEMORY_DESCRIPTOR(MemoryDescriptor, Size) \
  ((EFI_MEMORY_DESCRIPTOR *)((UINT8 *)(MemoryDescriptor) - (Size)))

BOOLEAN IsUefiPageNotPresent(IN EFI_MEMORY_DESCRIPTOR *MemoryMap)
{
  switch (MemoryMap->Type)
  {
    //case EfiLoaderCode:
    //case EfiLoaderData:
    //case EfiBootServicesCode:
    //case EfiBootServicesData:
    //case EfiUnusableMemory:
    //case EfiACPIReclaimMemory:
    return TRUE;
  default:
    return FALSE;
  }
}

STATIC BOOLEAN CopyMemUnsafe(UINT64 dest, UINT64 src, UINT32 n, BOOLEAN verbose)
{
  // Typecast src and dest addresses to (char *)
  CHAR8 *csrc = (CHAR8 *)src;
  CHAR8 *cdest = (CHAR8 *)dest;

  // Copy contents of src[] to dest[]
  for (UINT32 i = 0; i < n; i++)
    cdest[i] = csrc[i];

  return TRUE;
}

STATIC VOID SortMemoryMap(
    IN OUT EFI_MEMORY_DESCRIPTOR *MemoryMap,
    IN UINTN MemoryMapSize,
    IN UINTN DescriptorSize)
{
  EFI_MEMORY_DESCRIPTOR *MemoryMapEntry;
  EFI_MEMORY_DESCRIPTOR *NextMemoryMapEntry;
  EFI_MEMORY_DESCRIPTOR *MemoryMapEnd;
  EFI_MEMORY_DESCRIPTOR TempMemoryMap;

  MemoryMapEntry = MemoryMap;
  NextMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR(MemoryMapEntry, DescriptorSize);
  MemoryMapEnd = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MemoryMap + MemoryMapSize);
  while (MemoryMapEntry < MemoryMapEnd)
  {
    while (NextMemoryMapEntry < MemoryMapEnd)
    {
      if (MemoryMapEntry->PhysicalStart > NextMemoryMapEntry->PhysicalStart)
      {
        CopyMem(&TempMemoryMap, MemoryMapEntry, sizeof(EFI_MEMORY_DESCRIPTOR));
        CopyMem(MemoryMapEntry, NextMemoryMapEntry, sizeof(EFI_MEMORY_DESCRIPTOR));
        CopyMem(NextMemoryMapEntry, &TempMemoryMap, sizeof(EFI_MEMORY_DESCRIPTOR));
      }

      NextMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR(NextMemoryMapEntry, DescriptorSize);
    }

    MemoryMapEntry = NEXT_MEMORY_DESCRIPTOR(MemoryMapEntry, DescriptorSize);
    NextMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR(MemoryMapEntry, DescriptorSize);
  }
}

STATIC VOID MergeMemoryMapForNotPresentEntry(
    IN OUT EFI_MEMORY_DESCRIPTOR *MemoryMap,
    IN OUT UINTN *MemoryMapSize,
    IN UINTN DescriptorSize)
{
  EFI_MEMORY_DESCRIPTOR *MemoryMapEntry;
  EFI_MEMORY_DESCRIPTOR *MemoryMapEnd;
  UINT64 MemoryBlockLength;
  EFI_MEMORY_DESCRIPTOR *NewMemoryMapEntry;
  EFI_MEMORY_DESCRIPTOR *NextMemoryMapEntry;

  MemoryMapEntry = MemoryMap;
  NewMemoryMapEntry = MemoryMap;
  MemoryMapEnd = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MemoryMap + *MemoryMapSize);
  while ((UINTN)MemoryMapEntry < (UINTN)MemoryMapEnd)
  {
    CopyMem(NewMemoryMapEntry, MemoryMapEntry, sizeof(EFI_MEMORY_DESCRIPTOR));
    NextMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR(MemoryMapEntry, DescriptorSize);

    do
    {
      MemoryBlockLength = (UINT64)(EFI_PAGES_TO_SIZE((UINTN)MemoryMapEntry->NumberOfPages));
      if (((UINTN)NextMemoryMapEntry < (UINTN)MemoryMapEnd) && ((MemoryMapEntry->PhysicalStart + MemoryBlockLength) == NextMemoryMapEntry->PhysicalStart))
      {
        MemoryMapEntry->NumberOfPages += NextMemoryMapEntry->NumberOfPages;
        if (NewMemoryMapEntry != MemoryMapEntry)
        {
          NewMemoryMapEntry->NumberOfPages += NextMemoryMapEntry->NumberOfPages;
        }

        NextMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR(NextMemoryMapEntry, DescriptorSize);
        continue;
      }
      else
      {
        MemoryMapEntry = PREVIOUS_MEMORY_DESCRIPTOR(NextMemoryMapEntry, DescriptorSize);
        break;
      }
    } while (TRUE);

    MemoryMapEntry = NEXT_MEMORY_DESCRIPTOR(MemoryMapEntry, DescriptorSize);
    NewMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR(NewMemoryMapEntry, DescriptorSize);
  }

  *MemoryMapSize = (UINTN)NewMemoryMapEntry - (UINTN)MemoryMap;

  return;
}

BOOLEAN InitUefiMemoryMap()
{
  UINTN MemoryMapSize;
  EFI_MEMORY_DESCRIPTOR *MemoryMap;
  UINTN LocalMapKey;
  UINT32 DescriptorVersion;
  MemoryMapSize = 0;
  MemoryMap = NULL;

  EFI_STATUS Status;

  Status = lBS->GetMemoryMap(
      &MemoryMapSize,
      MemoryMap,
      &LocalMapKey,
      &mUefiDescriptorSize,
      &DescriptorVersion);

  do
  {
    Status = lBS->AllocatePool(EfiBootServicesData, MemoryMapSize, (VOID **)&MemoryMap);

    if (MemoryMap == NULL)
    {
      return FALSE;
    }

    Status = lBS->GetMemoryMap(
        &MemoryMapSize,
        MemoryMap,
        &LocalMapKey,
        &mUefiDescriptorSize,
        &DescriptorVersion);
    if (EFI_ERROR(Status))
    {
      lBS->FreePool(MemoryMap);
      MemoryMap = NULL;
    }
  } while (Status == EFI_BUFFER_TOO_SMALL);

  if (MemoryMap == NULL)
    return FALSE;

  SortMemoryMap(MemoryMap, MemoryMapSize, mUefiDescriptorSize);
  MergeMemoryMapForNotPresentEntry(MemoryMap, &MemoryMapSize, mUefiDescriptorSize);

  mUefiMemoryMapSize = MemoryMapSize;
  EFI_PHYSICAL_ADDRESS NewMemoryMap;
  Status = lBS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &NewMemoryMap);
  CopyMemUnsafe(NewMemoryMap, (UINT64)MemoryMap, MemoryMapSize, FALSE);
  mUefiMemoryMap = (EFI_MEMORY_DESCRIPTOR *)NewMemoryMap;
  lBS->FreePool(MemoryMap);

  return TRUE;
}

BOOLEAN IsAddressValid(UINT64 address)
{
  EFI_MEMORY_DESCRIPTOR *MemoryMap;
  UINTN MemoryMapEntryCount;
  UINTN Index;

  if (mUefiMemoryMap != NULL)
  {
    MemoryMap = mUefiMemoryMap;
    MemoryMapEntryCount = mUefiMemoryMapSize / mUefiDescriptorSize;

    for (Index = 0; Index < MemoryMapEntryCount; Index++)
    {
      if ((address >= MemoryMap->PhysicalStart) && (address < MemoryMap->PhysicalStart + EFI_PAGES_TO_SIZE((UINTN)MemoryMap->NumberOfPages)))
      {
        return TRUE;
      }
      MemoryMap = NEXT_MEMORY_DESCRIPTOR(MemoryMap, mUefiDescriptorSize);
    }
  }
  return FALSE;
}

EFI_MEMORY_DESCRIPTOR *GetUefiMemoryMap()
{
  return mUefiMemoryMap;
}

VOID ShowMemoryMap()
{
  EFI_MEMORY_DESCRIPTOR *MemoryMap;
  UINTN MemoryMapEntryCount;
  UINTN Index;

  if (mUefiMemoryMap != NULL)
  {
    MemoryMap = mUefiMemoryMap;
    MemoryMapEntryCount = mUefiMemoryMapSize / mUefiDescriptorSize;

    for (Index = 0; Index < MemoryMapEntryCount; Index++)
    {
      //SerialPrintString("Map: ");
      //SerialPrintNumber(Index, 10);
      //SerialPrintString("\r\n Type: ");
      //SerialPrintNumber(MemoryMap->Type, 10);
      //SerialPrintString("\r\n PhysStart: ");
      //SerialPrintNumber(MemoryMap->PhysicalStart, 16);
      //SerialPrintString(" PhysEnd: ");
      //SerialPrintNumber(MemoryMap->PhysicalStart + EFI_PAGES_TO_SIZE((UINTN)MemoryMap->NumberOfPages), 16);
      //SerialPrintString("\r\n\r\n");

      MemoryMap = NEXT_MEMORY_DESCRIPTOR(MemoryMap, mUefiDescriptorSize);
    }
  }
}