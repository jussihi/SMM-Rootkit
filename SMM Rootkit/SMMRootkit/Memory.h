#ifndef __smmrootkit_memory_h__
#define __smmrootkit_memory_h__

#include <Uefi.h>
#include <Protocol/SmmBase2.h>

#include "MemoryMapUEFI.h" // IsAddressValid
#include "serial.h"

/*
 * We use windows size of PAGE_OFFSET_SIZE
 * and PMASK2
 */
#include "windows.h"

typedef struct _Cache
{
  UINT64 vAddress;
  UINT64 pAddress;
} Cache, PCache;

#ifdef __GNUC__
typedef UINT32 size_t;
#endif

BOOLEAN p_memCpy(UINT64 dest, UINT64 src, size_t n, BOOLEAN verbose);

UINT64 VTOP(UINT64 address, UINT64 directoryBase, BOOLEAN verbose);

BOOLEAN PTOV(UINT64 qwAddrPhys, UINT64 *pqwAddrVirt, UINT64 *pqwPTE, UINT64 *pqwPDE, UINT64 *pqwPDPTE, UINT64 *pqwPML4E, BOOLEAN verbose);

BOOLEAN v_memWrite(UINT64 dest, UINT64 src, size_t n, UINT64 directoryBase, BOOLEAN verbose);

BOOLEAN v_memReadMultiPage(UINT64 dest, UINT64 src, size_t n, UINT64 directoryBase, BOOLEAN verbose);

BOOLEAN v_memRead(UINT64 dest, UINT64 src, size_t n, UINT64 directoryBase, BOOLEAN verbose);

#endif