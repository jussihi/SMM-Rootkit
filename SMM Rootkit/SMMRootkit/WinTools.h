/*
 * This file and the corresponding .c file 
 * contains a set of needed Windows-related 
 * functions for both reading & writing its 
 * virtual memory. 
 * 
 * These files are imported and ported to work 
 * in SMM. The original libraries are 
 * 
 * - MemProcFS/pcileech by Ulf Frisk
 * - vmread by Heep042
 * 
 */

#ifndef __smmrootkit_wintools_h__
#define __smmrootkit_wintools_h__

#include <Uefi.h>
#include <Base.h>
#include <Protocol/SmmBase2.h>

#include "windows.h"
#include "serial.h"
#include "string.h"
#include "Memory.h" // VTOP, p_memCpy, v_memCpy
#include "MemManager.h"

#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_WRITE 0x80000000

typedef struct ProcessData
{
  UINT64 mapsStart;
  UINT64 mapsSize;
  INT32 pid;
} ProcessData;

typedef struct WinOffsets
{
  INT64 apl;
  INT64 session;
  INT64 imageFileName;
  INT64 dirBase;
  INT64 peb;
  INT64 peb32;
  INT64 threadListHead;
  INT64 threadListEntry;
  INT64 teb;
} WinOffsets;

typedef struct WinProc
{
  UINT64 process;
  UINT64 physProcess;
  UINT64 dirBase;
  UINT64 pid;
  char name[16];
} WinProc;

typedef struct WinProcList
{
  WinProc *list;
  size_t size;
} WinProcList;

typedef struct WinExport
{
  char *name;
  UINT64 address;
} WinExport;

typedef struct WinExportList
{
  WinExport *list;
  size_t size;
} WinExportList;

typedef struct WinModule
{
  UINT64 baseAddress;
  UINT64 entryPoint;
  UINT64 sizeOfModule;
  char *name;
  short loadCount;
} WinModule;

typedef struct WinModuleList
{
  WinModule *list;
  size_t size;
} WinModuleList;

typedef struct WinCtx
{
  ProcessData process;
  WinOffsets offsets;
  UINT64 ntKernel;
  UINT16 ntVersion;
  UINT32 ntBuild;
  WinExportList ntExports;
  WinProc initialProcess;
} WinCtx;

typedef struct tdPE_THUNKINFO_IAT
{
  UINT32 fValid;
  UINT32 f32;            // if TRUE fn is a 32-bit/4-byte entry, otherwise 64-bit/8-byte entry.
  UINT64 vaThunk;        // address of import address table 'thunk'.
  UINT64 vaFunction;     // value if import address table 'thunk' == address of imported function.
  UINT64 vaNameModule;   // address of name string for imported module.
  UINT64 vaNameFunction; // address of name string for imported function.
} PE_THUNKINFO_IAT, *PPE_THUNKINFO_IAT;

typedef struct tdPE_THUNKINFO_EAT
{
  UINT32 fValid;
  UINT32 valueThunk;     // value of export address table 'thunk'.
  UINT64 vaThunk;        // address of import address table 'thunk'.
  UINT64 vaNameFunction; // address of name string for exported function.
  UINT64 vaFunction;     // address of exported function (module base + value parameter).
} PE_THUNKINFO_EAT, *PPE_THUNKINFO_EAT;

typedef struct _IMAGE_IMPORT_DESCRIPTOR
{
  union {
    UINT32 Characteristics;    //0 for terminating null import descriptor
    UINT32 OriginalFirstThunk; // RVA to original unbound IAT
  };
  UINT32 TimeDateStamp;
  UINT32 ForwarderChain; // -1 if no forwarders
  UINT32 Name;           // RVA of imported DLL name (null-terminated SCII)
  UINT32 FirstThunk;     // RVA to IAT (if bound this IAT has addresses )

} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;



BOOLEAN InitGlobalWindowsContext();
IMAGE_NT_HEADERS *GetNTHeader(const WinCtx *ctx, const WinProc *process, UINT64 address, UINT8 *header, UINT8 *is64Bit);
BOOLEAN ParseExportTable(const WinCtx *ctx, const WinProc *process, UINT64 moduleBase, IMAGE_DATA_DIRECTORY *exports, WinExportList *outList);
BOOLEAN GenerateExportList(const WinCtx *ctx, const WinProc *process, UINT64 moduleBase, WinExportList *outList);
VOID FreeExportList(WinExportList list);
UINT64 GetProcAddress(const WinCtx *ctx, const WinProc *process, UINT64 module, const CHAR8 *procName);
UINT64 FindProcAddress(const WinExportList exports, const CHAR8 *procName);
PEB GetPeb(const WinCtx *ctx, const WinProc *process);
PEB32 GetPeb32(const WinCtx *ctx, const WinProc *process);
BOOLEAN FindProcess(WinCtx *ctx, CHAR8 *processname, BOOLEAN verbose);
BOOLEAN DumpSingleProcess(WinCtx *ctx, CHAR8 *processname, WinProc *process, BOOLEAN verbose);
BOOLEAN DumpSingleModule(const WinCtx *ctx, const WinProc *process, WinModule *out_module, BOOLEAN verbose);

BOOLEAN ProcessGetThunkInfoIAT(WinProc *process, WinModule *basemodule, CHAR8 *szImportModuleName, CHAR8 *szImportProcName, PPE_THUNKINFO_IAT pThunkInfoIAT);

BOOLEAN ProcessGetSections(WinProc *process, WinModule *basemodule, PIMAGE_SECTION_HEADER pSections, UINT32 cSections, UINT32 *pcSections);

UINT64 ProcessGetProcAddress(WinProc *process, WinModule *basemodule, CHAR8 *procName);

#endif