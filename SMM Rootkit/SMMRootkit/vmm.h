#ifndef __smmrootkit_vmm_h__
#define __smmrootkit_vmm_h__

#include <Base.h>
#include "NewNTKernelTools.h"

#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_WRITE 0x80000000


typedef struct tdPE_THUNKINFO_IAT {
    UINT32 fValid;
    UINT32 f32;               // if TRUE fn is a 32-bit/4-byte entry, otherwise 64-bit/8-byte entry.
    UINT64 vaThunk;        // address of import address table 'thunk'.
    UINT64 vaFunction;     // value if import address table 'thunk' == address of imported function.
    UINT64 vaNameModule;   // address of name string for imported module.
    UINT64 vaNameFunction; // address of name string for imported function.
} PE_THUNKINFO_IAT, *PPE_THUNKINFO_IAT;

typedef struct tdPE_THUNKINFO_EAT {
    UINT32 fValid;
    UINT32 valueThunk;       // value of export address table 'thunk'.
    UINT64 vaThunk;        // address of import address table 'thunk'.
    UINT64 vaNameFunction; // address of name string for exported function.
    UINT64 vaFunction;     // address of exported function (module base + value parameter).
} PE_THUNKINFO_EAT, *PPE_THUNKINFO_EAT;


typedef enum tdVMMDLL_MEMORYMODEL_TP {
    VMMDLL_MEMORYMODEL_NA       = 0,
    VMMDLL_MEMORYMODEL_X86      = 1,
    VMMDLL_MEMORYMODEL_X86PAE   = 2,
    VMMDLL_MEMORYMODEL_X64      = 3
} VMMDLL_MEMORYMODEL_TP;

typedef enum tdVMMDLL_SYSTEM_TP {
    VMMDLL_SYSTEM_UNKNOWN_X64   = 1,
    VMMDLL_SYSTEM_WINDOWS_X64   = 2,
    VMMDLL_SYSTEM_UNKNOWN_X86   = 3,
    VMMDLL_SYSTEM_WINDOWS_X86   = 4
} VMMDLL_SYSTEM_TP;

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct tdVMMDLL_PROCESS_INFORMATION {
    UINT64 magic;
    UINT16 wVersion;
    UINT16 wSize;
    VMMDLL_MEMORYMODEL_TP tpMemoryModel;    // as given by VMMDLL_MEMORYMODEL_* enum
    VMMDLL_SYSTEM_TP tpSystem;              // as given by VMMDLL_SYSTEM_* enum
    UINT32 fUserOnly;                         // WAS BOOL
    UINT32 dwPID;
    UINT32 dwPPID;
    UINT32 dwState;
    CHAR8 szName[16];
    CHAR8 szNameLong[64];
    UINT64 paDTB;
    UINT64 paDTB_UserOpt;                  // may not exist
    union {
        struct {
            UINT64 vaEPROCESS;
            UINT64 vaPEB;
            UINT64 _Reserved1;
            UINT32 fWow64;              // WAS BOOL
            UINT32 vaPEB32;                  // WoW64 only
        } win;
    } os;
} VMMDLL_PROCESS_INFORMATION, *PVMMDLL_PROCESS_INFORMATION;


typedef struct tdVMMDLL_WIN_THUNKINFO_IAT {
    UINT32 fValid;          // WAS BOOL
    UINT32 f32;             // if TRUE fn is a 32-bit/4-byte entry, otherwise 64-bit/8-byte entry.
    UINT64 vaThunk;        // address of import address table 'thunk'.
    UINT64 vaFunction;     // value if import address table 'thunk' == address of imported function.
    UINT64 vaNameModule;   // address of name string for imported module.
    UINT64 vaNameFunction; // address of name string for imported function.
} VMMDLL_WIN_THUNKINFO_IAT, *PVMMDLL_WIN_THUNKINFO_IAT;

typedef struct tdVMMDLL_WIN_THUNKINFO_EAT {
    UINT32 fValid;          // WAS BOOL
    UINT32 valueThunk;      // value of export address table 'thunk'.
    UINT64 vaThunk;        // address of import address table 'thunk'.
    UINT64 vaNameFunction; // address of name string for exported function.
    UINT64 vaFunction;     // address of exported function (module base + value parameter).
} VMMDLL_WIN_THUNKINFO_EAT, *PVMMDLL_WIN_THUNKINFO_EAT;


typedef struct tdOB {
    // internal object manager functionality below: (= do not use unless absolutely necessary)
    UINT32 _magic;                        // magic value - OB_HEADER_MAGIC
    union {
        UINT32 _tag;                      // tag - 2 chars, no null terminator
        CHAR8 _tagCh[4];
    };
    VOID(*_pfnRef_0)(VOID* pOb);    // callback - object specific cleanup before free
    VOID(*_pfnRef_1)(VOID* pOb);    // callback - when object reach refcount 1 (not initial)
    UINT32 _count;                        // reference count
    // external object manager functionality below: (= ok to use)
    UINT32 cbData;
} OB, *POB;

typedef struct tdOB_CONTAINER {
    OB ObHdr;
    // CRITICAL_SECTION Lock;
    POB pOb;
} OB_CONTAINER, *POB_CONTAINER;

typedef struct tdVMM_MAP_PTEENTRY {
    UINT64 vaBase;
    UINT64 cPages;
    UINT64 fPage;
    UINT32  fWoW64;
    UINT32 cwszText;
    UINT16* wszText;      // wchar
    UINT32 _Reserved1[2];
} VMM_MAP_PTEENTRY, *PVMM_MAP_PTEENTRY;

typedef struct tdVMMOB_MAP_PTE {
    OB ObHdr;
    UINT16* wszMultiText;            // NULL or multi-wstr pointed into by VMM_MAP_PTEENTRY.wszText
    UINT32 cbMultiText;
    UINT32 fTagScan;                  // map contains tags from modules and scan.
    UINT32 cMap;                     // # map entries.
    VMM_MAP_PTEENTRY pMap[];        // map entries.
} VMMOB_MAP_PTE, *PVMMOB_MAP_PTE;

typedef struct tdVMM_MAP_VADENTRY {
    UINT64 vaStart;
    UINT64 vaEnd;
    UINT64 vaVad;
    union {
        struct {
            // DWORD 0
            UINT32 VadType           : 3;   // Pos 0
            UINT32 Protection        : 5;   // Pos 3
            UINT32 fImage            : 1;   // Pos 8
            UINT32 fFile             : 1;   // Pos 9
            UINT32 fPageFile         : 1;   // Pos 10
            UINT32 fPrivateMemory    : 1;   // Pos 11
            UINT32 fTeb              : 1;   // Pos 12
            UINT32 fStack            : 1;   // Pos 13
            UINT32 fSpare            : 10;  // Pos 14
            UINT32 HeapNum           : 7;   // Pos 24
            UINT32 fHeap             : 1;   // Pos 31
            // DWORD 1
            UINT32 CommitCharge      : 31;   // Pos 0
            UINT32 MemCommit         : 1;    // Pos 31
            // DWORD 2
            UINT32 FileOffset        : 24;   // Pos 0
            UINT32 Large             : 1;    // Pos 24
            UINT32 TrimBehind        : 1;    // Pos 25
            UINT32 Inherit           : 1;    // Pos 26
            UINT32 CopyOnWrite       : 1;    // Pos 27
            UINT32 NoValidationNeeded : 1;   // Pos 28
            UINT32 _Spare2           : 3;    // Pos 29
        };
        UINT32 flags[3];
    };
    UINT32 cbPrototypePte;
    UINT64 vaPrototypePte;
    UINT64 vaSubsection;
    UINT16* wszText;                 // optional LPWSTR pointed into VMMOB_MAP_VAD.wszMultiText
    UINT32 cwszText;                 // WCHAR count not including terminating null
    UINT32 _Reserved1;
} VMM_MAP_VADENTRY, *PVMM_MAP_VADENTRY;

typedef struct tdVMMOB_MAP_VAD {
    OB ObHdr;
    UINT32 fSpiderPrototypePte;
    UINT16* wszMultiText;            // NULL or multi-wstr pointed into by VMM_MAP_VADENTRY.wszText
    UINT32 cbMultiText;
    UINT32 cMap;                     // # map entries.
    VMM_MAP_VADENTRY pMap[];        // map entries.
} VMMOB_MAP_VAD, *PVMMOB_MAP_VAD;

typedef struct tdVMM_MAP_MODULEENTRY {
    UINT64 vaBase;
    UINT64 vaEntry;
    UINT32 cbImageSize;
    UINT32  fWoW64;
    UINT16* wszText;                 // LPWSTR pointed into VMM_MAP_MODULE.wszMultiText
    UINT32 cwszText;                 // WCHAR count not including terminating null
    // optional internal fields lazy loaded due to perfomance reasons
    UINT32  fLoadedEAT;
    UINT32  fLoadedIAT;
    UINT32 cbDisplayBufferSections;
    union {
        struct {
            UINT32 cbDisplayBufferIAT;
            UINT32 cbDisplayBufferEAT;
        };
        UINT64 _Reserved1;
    };
    UINT32 cbFileSizeRaw;
    UINT32 _Reserved2;
} VMM_MAP_MODULEENTRY, *PVMM_MAP_MODULEENTRY;


typedef struct tdVMMOB_MAP_MODULE {
    OB ObHdr;
    UINT64* pHashTableLookup;
    UINT16* wszMultiText;            // multi-wstr pointed into by VMM_MAP_MODULEENTRY.wszText
    UINT32 cbMultiText;
    UINT32 cMap;                     // # map entries.
    VMM_MAP_MODULEENTRY pMap[];     // map entries.
} VMMOB_MAP_MODULE, *PVMMOB_MAP_MODULE;

typedef struct tdVMM_MAP_HEAPENTRY {
    UINT64 vaHeapSegment;
    union {
        struct {
            UINT32 cPages;
            UINT32 cPagesUnCommitted : 24;
            UINT32 HeapId : 7;
            UINT32 fPrimary : 1;
        };
        UINT64 qwHeapData;
    };
} VMM_MAP_HEAPENTRY, *PVMM_MAP_HEAPENTRY;

typedef struct tdVMMOB_MAP_HEAP {
    OB ObHdr;
    UINT32 cMap;                      // # map entries.
    VMM_MAP_HEAPENTRY pMap[];        // map entries.
} VMMOB_MAP_HEAP, *PVMMOB_MAP_HEAP;

typedef struct tdVMM_MAP_THREADENTRY {
    UINT32 dwTID;
    UINT32 dwPID;
    UINT32 dwExitStatus;
    UINT8 bState;
    UINT8 bRunning;
    UINT8 bPriority;
    UINT8 bBasePriority;
    UINT64 vaETHREAD;
    UINT64 vaTeb;
    UINT64 ftCreateTime;
    UINT64 ftExitTime;
    UINT64 vaStartAddress;
    UINT64 vaStackBaseUser;          // value from _NT_TIB / _TEB
    UINT64 vaStackLimitUser;         // value from _NT_TIB / _TEB
    UINT64 vaStackBaseKernel;
    UINT64 vaStackLimitKernel;
    UINT32 _FutureUse[10];
} VMM_MAP_THREADENTRY, *PVMM_MAP_THREADENTRY;

typedef struct tdVMMOB_MAP_THREAD {
    OB ObHdr;
    UINT32 cMap;                      // # map entries.
    VMM_MAP_THREADENTRY pMap[];      // map entries.
} VMMOB_MAP_THREAD, *PVMMOB_MAP_THREAD;

typedef struct tdVMM_MAP_HANDLEENTRY {
    UINT64 vaObject;
    UINT32 dwHandle;
    UINT32 dwGrantedAccess : 24;
    UINT32 iType : 8;
    UINT64 qwHandleCount;
    UINT64 qwPointerCount;
    UINT64 vaObjectCreateInfo;
    UINT64 vaSecurityDescriptor;
    UINT16* wszText;                 // optional LPWSTR pointed into VMMOB_MAP_HANDLE.wszMultiText
    UINT32 cwszText;                 // WCHAR count not including terminating null
    UINT32 dwPID;
    UINT32 dwPoolTag;
    UINT32 _FutureUse[4];
    UINT32 _Reserved1;
    UINT64 _Reserved2;
} VMM_MAP_HANDLEENTRY, *PVMM_MAP_HANDLEENTRY;

typedef struct tdVMMOB_MAP_HANDLE {
    OB ObHdr;
    UINT16* wszMultiText;            // multi-wstr pointed into by VMM_MAP_HANDLEENTRY.wszText
    UINT32 cbMultiText;
    UINT32 cMap;                     // # map entries.
    VMM_MAP_HANDLEENTRY pMap[];     // map entries.
} VMMOB_MAP_HANDLE, *PVMMOB_MAP_HANDLE;

typedef struct tdVMMWIN_USER_PROCESS_PARAMETERS {
    UINT32 fProcessed;
    UINT32 cchImagePathName;
    UINT32 cchCommandLine;
    CHAR8* szImagePathName;
    CHAR8* szCommandLine;
} VMMWIN_USER_PROCESS_PARAMETERS, *PVMMWIN_USER_PROCESS_PARAMETERS;

typedef struct tdVMMOB_PROCESS_PERSISTENT {
    OB ObHdr;
    UINT32 fIsPostProcessingComplete;
    POB_CONTAINER pObCMapVadPrefetch;
    POB_CONTAINER pObCLdrModulesPrefetch32;
    POB_CONTAINER pObCLdrModulesPrefetch64;
    POB_CONTAINER pObCMapThreadPrefetch;
    VMMWIN_USER_PROCESS_PARAMETERS UserProcessParams;
    // kernel path and long name (from EPROCESS.SeAuditProcessCreationInfo)
    UINT16 cchNameLong;
    UINT16 cchPathKernel;
    CHAR8* szNameLong;
    CHAR8 szPathKernel[128];
    // plugin functionality below:
    struct {
        UINT64 vaVirt2Phys;
        UINT64 paPhys2Virt;
    } Plugin;
} VMMOB_PROCESS_PERSISTENT, *PVMMOB_PROCESS_PERSISTENT;


typedef struct tdVMM_PROCESS {
    OB ObHdr;
    // CRITICAL_SECTION LockUpdate;
    UINT32 dwPID;
    UINT32 dwPPID;
    UINT32 dwState;          // state of process, 0 = running
    UINT64 paDTB;
    UINT64 paDTB_UserOpt;
    CHAR8 szName[16];
    UINT32 fUserOnly;
    UINT32 fTlbSpiderDone;
    UINT32 fFileCacheDisabled;
    struct {
        PVMMOB_MAP_PTE pObPte;
        PVMMOB_MAP_VAD pObVad;
        PVMMOB_MAP_MODULE pObModule;
        PVMMOB_MAP_HEAP pObHeap;
        PVMMOB_MAP_THREAD pObThread;
        PVMMOB_MAP_HANDLE pObHandle;
        // separate locks from main process lock to avoid deadlocks
        // but also for increased parallelization for slow tasks.
        // CRITICAL_SECTION LockUpdateExtendedInfo;
        // CRITICAL_SECTION LockUpdateThreadMap;
    } Map;
    PVMMOB_PROCESS_PERSISTENT pObPersistent;     // Always exists
    struct {
        UINT64 vaPEB;
        UINT32 vaPEB32;      // WoW64 only
        UINT32 fWow64;
        struct {
            UINT64 va;
            UINT32 cb;
            UINT8 pb[0x800];
        } EPROCESS;
    } win;
    struct {
        POB_CONTAINER pObCLdrModulesDisplayCache;
        POB_CONTAINER pObCPeDumpDirCache;
        POB_CONTAINER pObCPhys2Virt;
    } Plugin;
} VMM_PROCESS, *PVMM_PROCESS;

typedef struct tdVMMDLL_MAP_MODULEENTRY {
    UINT64 vaBase;
    UINT64 vaEntry;
    UINT32 cbImageSize;
    UINT32  fWoW64;
    UINT16* wszText;
    UINT32 cwszText;                 // wchar count not including terminating null
    UINT32 _Reserved1[7];
} VMMDLL_MAP_MODULEENTRY, *PVMMDLL_MAP_MODULEENTRY;


typedef struct _IMAGE_IMPORT_DESCRIPTOR
{
    union
    {
         UINT32 Characteristics;  //0 for terminating null import descriptor
         UINT32 OriginalFirstThunk;   // RVA to original unbound IAT
     };
     UINT32 TimeDateStamp;
     UINT32 ForwarderChain;      // -1 if no forwarders
     UINT32 Name;                     // RVA of imported DLL name (null-terminated SCII)
     UINT32 FirstThunk;            // RVA to IAT (if bound this IAT has addresses )
 
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;


BOOLEAN ProcessGetThunkInfoIAT(WinProc* process, WinModule* basemodule, CHAR8* szImportModuleName, CHAR8* szImportFunctionName, PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT);

BOOLEAN ProcessGetSections(WinProc* process, WinModule* basemodule, PIMAGE_SECTION_HEADER pSections, UINT32 cSections, UINT32* pcSections);

UINT64 PE_GetProcAddress(WinProc* process, WinModule* basemodule, CHAR8* procName);

#endif