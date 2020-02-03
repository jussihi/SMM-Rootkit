#ifndef __smmrootkit_cheat_rootkittest_h__
#define __smmrootkit_cheat_rootkittest_h__


#include <Base.h>

#include "windows.h"
#include "NewNTKernelTools.h"
#include "serial.h"
#include "Memory.h"


typedef enum _WinUmdIATState {
  NO_PROCESS,
  WAITING_EXECUTION,
  SUCCESS
} WinUmdIATState;

// struct shared with wx64_umd_exec_c.c
typedef struct tdUMD_EXEC_CONTEXT_LIMITED {
	INT64 CMPXCHG;
	CHAR8 Status;
	VOID* ProcessHandle;
	struct {
		UINT64 CloseHandle;
		UINT64 CreateFileA;
		UINT64 CreateProcessA;
		UINT64 CreateThread;
		UINT64 GetExitCodeProcess;
		UINT64 ReadFile;
		UINT64 WriteFile;
		UINT64 LocalAlloc;
	} fn;
  // These strings are used to transfer needed information
  // to the userspace process
	CHAR8 ParamString1[100];
	CHAR8 ParamString2[100];
} UMD_EXEC_CONTEXT_LIMITED, *PUMD_EXEC_CONTEXT_LIMITED;


BOOLEAN WindowsUmdIATHook();

VOID InitWindowsUmdIATHook();

#endif