#ifndef __smmrootkit_newntkernel_h__
#define __smmrootkit_newntkernel_h__

#include <Uefi.h>
#include <Base.h>
#include <Protocol/SmmBase2.h>

#include "windows.h"
#include "serial.h"
#include "string.h"
#include "Memory.h"           // VTOP, p_memCpy, v_memCpy
#include "MemManager.h"


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
	WinProc* list;
	size_t size;
} WinProcList;

typedef struct WinExport
{
	char* name;
	UINT64 address;
} WinExport;

typedef struct WinExportList
{
	WinExport* list;
	size_t size;
} WinExportList;

typedef struct WinModule
{
	UINT64 baseAddress;
	UINT64 entryPoint;
	UINT64 sizeOfModule;
	char* name;
	short loadCount;
} WinModule;

typedef struct WinModuleList
{
	WinModule* list;
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

BOOLEAN InitGlobalWindowsContext();
int FreeContext(WinCtx* ctx);
IMAGE_NT_HEADERS* GetNTHeader(const WinCtx* ctx, const WinProc* process, UINT64 address, UINT8* header, UINT8* is64Bit);
BOOLEAN ParseExportTable(const WinCtx* ctx, const WinProc* process, UINT64 moduleBase, IMAGE_DATA_DIRECTORY* exports, WinExportList* outList);
BOOLEAN GenerateExportList(const WinCtx* ctx, const WinProc* process, UINT64 moduleBase, WinExportList* outList);
VOID FreeExportList(WinExportList list);
UINT64 GetProcAddress(const WinCtx* ctx, const WinProc* process, UINT64 module, const char* procName);
UINT64 FindProcAddress(const WinExportList exports, const char* procName);
WinProcList GenerateProcessList(const WinCtx* ctx);
WinModuleList GenerateModuleList(const WinCtx* ctx, const WinProc* process);
WinModuleList GenerateKernelModuleList(const WinCtx* ctx);
void FreeModuleList(WinModuleList list);
const WinModule* GetModuleInfo(const WinModuleList list, const char* moduleName);
PEB GetPeb(const WinCtx* ctx, const WinProc* process);
PEB32 GetPeb32(const WinCtx* ctx, const WinProc* process);
BOOLEAN FindProcess(WinCtx *ctx, char *processname, BOOLEAN verbose);
BOOLEAN DumpSingleProcess(WinCtx *ctx, char *processname, WinProc *process, BOOLEAN verbose);
BOOLEAN DumpSingleModule(const WinCtx* ctx, const WinProc* process, WinModule* out_module, BOOLEAN verbose);

#endif