#include "MemManager.h"

static BOOLEAN memPoolInitialized;
static PMemAllocEntry_t memPool;
static UINT32 pagesInPool;
static UINT64 memAllocated;

// from SMMRootkit.c
extern EFI_SMM_SYSTEM_TABLE2 *gSmst2;

UINT64 GetMemAllocated()
{
  return memAllocated;
}

BOOLEAN InitMemManager(UINT32 pages)
{
  memPoolInitialized = FALSE;
  EFI_PHYSICAL_ADDRESS physAddr;
  if (gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, pages, &physAddr) == EFI_SUCCESS)
  {
    // set pool pointer
    memPool = (PMemAllocEntry_t)physAddr;

    // nullify the pool
    UINT8 *pool = (UINT8 *)memPool;
    for (UINT32 i = 0; i < pages * 4096; i++)
    {
      pool[i] = (UINT8)0x00;
    }

    // set the global vars, needed by malloc
    memPoolInitialized = TRUE;
    pagesInPool = pages;

    // allocate the first block
    malloc(0);
  }
  return memPoolInitialized;
}

VOID *palloc(UINT32 pages)
{
  EFI_PHYSICAL_ADDRESS physAddr;
  if (gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, pages, &physAddr) == EFI_SUCCESS)
  {
    return (VOID *)physAddr;
  }
  return NULL;
}

VOID pfree(VOID *address, UINT32 pages)
{
  gSmst2->SmmFreePages((EFI_PHYSICAL_ADDRESS)address, pages);
}

VOID *malloc(UINT32 size)
{
  // sanity check
  if (!memPoolInitialized)
  {
    SerialPrintStringDebug("FAIL: malloc pool was not set up!\r\n");
    return NULL;
  }

  PMemAllocEntry_t curr = memPool;
  PMemAllocEntry_t newEntry = NULL;

  // find the first allocatable location and return if possible
  while (curr->next)
  {
    if ((UINT8 *)curr + curr->size + 24 + size < (UINT8 *)curr->next)
    {
      newEntry = (PMemAllocEntry_t)((UINT8 *)curr + curr->size);
      newEntry->next = curr->next;
      newEntry->prev = curr;
      newEntry->size = size + 24;
      curr->next->prev = newEntry;
      curr->next = newEntry;
      memAllocated += size + 24;
      return newEntry->data;
    }
    curr = curr->next;
  }

  // we came to the end of the list,
  // check that the allocation will not exceed the slab boundaries
  if ((UINT8 *)curr + curr->size + 24 + size > ((UINT8 *)memPool + (pagesInPool * 4096)))
  {
    SerialPrintStringDebug("FAIL: malloc failed for size ");
    SerialPrintNumberDebug(size, 10);
    SerialPrintStringDebug("\r\n");
    return NULL;
  }

  // Is this the first allocation?
  if (curr->size == 0 && curr == memPool)
  {
    curr->size = 24 + size;
    memAllocated += size + 24;
    return curr->data;
  }

  // normal allocation for normal entries
  newEntry = (PMemAllocEntry_t)((UINT8 *)curr + curr->size);
  newEntry->next = curr->next;
  newEntry->prev = curr;
  newEntry->size = size + 24;
  curr->next = newEntry;
  memAllocated += size + 24;
  return newEntry->data;
}

VOID free(VOID *address)
{
  // sanity check
  if (!memPoolInitialized)
  {
    return;
  }

  PMemAllocEntry_t curr = memPool;

  while (curr->next)
  {
    curr = curr->next;
    if (curr->data == address)
    {
      if (curr->next)
      {
        curr->next->prev = curr->prev;
      }
      curr->prev->next = curr->next;
      curr->prev = NULL;
      curr->next = NULL;
      memAllocated -= curr->size + 24;
      curr->size = 0;
    }
  }
}