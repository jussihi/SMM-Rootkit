#ifndef __smmrootkit_memory_manager_h__
#define __smmrootkit_memory_manager_h__

#include <Uefi.h>
#include <Base.h>
#include <Protocol/SmmBase2.h>
#include <Library/MemoryAllocationLib.h>
#include "serial.h"

/*
 * A very simple malloc implementation
 * 
 * The dynamically allocatable memory is first initialized with 
 * gSmst2->SmmAllocatePages, then given as requested, until the 
 * memory in firstly allocated efi runtime mem runs out
 * 
 * The implementation uses a simple linked list, with first entry 
 * starting from byte 0 of the allocated efi memory page area.
 * 
 * If area[0].next = nullptr, there are no allocs currently. 
 * If area[0] = &area[0], there is at least one allocation
 * PMemAllocEntry_t->next points to the next entry, if it is null, 
 * there are no more entries in the list.
 */

typedef struct memallocentry MemAllocEntry_t, *PMemAllocEntry_t;

#ifdef __GNUC__
struct memallocentry
{
  PMemAllocEntry_t prev;
  PMemAllocEntry_t next;
  UINT64 size;
  UINT8 data[];
} __attribute__((packed));
#endif

#ifdef _MSC_VER
#define PACK(__Declaration__) __pragma(pack(push, 1)) __Declaration__ __pragma(pack(pop))
PACK(struct memallocentry {
  PMemAllocEntry_t prev;
  PMemAllocEntry_t next;
  UINT64 size;
  UINT8 data[];
});
#endif

/*
 * Initializes the memory manager with pages number of pages.
 * @return TRUE if succeeded, FALSE otherwise
 */
BOOLEAN InitMemManager(UINT32 pages);

/*
 * Allocates number of pages, returns the physical address to allocated memory
 */
VOID *palloc(UINT32 pages);

/*
 * Frees number of pages from the physical address allocated by palloc
 */
VOID pfree(VOID *address, UINT32 pages);

/*
 * Tries to dynamically allocate memory
 * 
 * @return pointer to allocated memory if succeeded, NULL otherwise
 */
VOID *malloc(UINT32 size);

/*
 * Tries to free a memory address from before dynamically 
 * allocated memory
 */
VOID free(VOID *address);

/*
 * Returns the total amount of bytes allocated from the pool
 * 
 */
UINT64 GetMemAllocated();

#endif