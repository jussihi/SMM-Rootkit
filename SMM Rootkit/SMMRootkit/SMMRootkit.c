// Basic UEFI Libraries
#include <Uefi.h>

// Protocols
#include <Protocol/SmmCpu.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/SmmSwDispatch2.h>
#include <Protocol/SerialIo.h>
#include <Library/PcdLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/PciIo.h>
#include <Library/PciLib.h>

// 3rd party protocols
#include "SmmCpuService.h"
#include "SmmCpuPlatformHookLib.h"
#include "SmmMemoryAttribute.h"

// Our includes
#include "MemoryMapUEFI.h"
#include "TimerRTC.h"
#include "config.h"
#include "serial.h"
#include "CheatSmmRootkitTest.h"
#include "Memory.h"
#include "NewNTKernelTools.h"


/* 
 * Just a workaround for stupid MVSC pragmas
 * and other GCC-only warnings treated as errors.
 */
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-value"
#endif



EFI_CPU_ARCH_PROTOCOL  *mCpu = NULL;
EFI_SMM_SYSTEM_TABLE2		*gSmst2;
EFI_SMM_CPU_PROTOCOL		*gSmmCpu = NULL;
EFI_SMM_CPU_IO2_PROTOCOL	*gSmmIo = NULL;

// UEFI Tables (will be gone after exiting DXE stage) 
extern EFI_SYSTEM_TABLE *gST;
extern EFI_BOOT_SERVICES *gBS;
extern EFI_RUNTIME_SERVICES *gRT;

// NTKernelTools.c
extern WinCtx *winGlobal;
BOOLEAN setupWindows;

// For storing target-specific data
static struct TargetInfo {
	BOOLEAN setup;
	VOID (*TargetMain)();
	BOOLEAN (*IsRunning)();
} targetInfo;


BOOLEAN FindTarget()
{
	// setup for our test program
	if(FindProcess(winGlobal, "smm_rootkit_te", FALSE))
	{
		SerialPrintStringDebug("\r\n== Found target: smm_rootkit_test! ==\r\n");
		if(InitCheatTest())
		{
			targetInfo.setup = TRUE;
			targetInfo.TargetMain = CheatTestMain;
			// TODO: also fill IsRunning!
			return TRUE;
		}
	}
	// setup for something else?
	else if(FindProcess(winGlobal, "TlsGame.exe", FALSE))
	{
		// setup for other game
		// return TRUE;
	}
	return FALSE;
}

UINT32 start_time;
UINT32 last_time;
BOOLEAN os_ctx_initialized;

VOID SmmCallHandle()
{
	if(!os_ctx_initialized)
	{
		os_ctx_initialized = InitGlobalWindowsContext();
		// give the target PC a bit more time to open up
		if(!os_ctx_initialized)
		{
			start_time = last_time;
			return;
		}
		return;
	}

	// if the context has been initialized
	if (targetInfo.setup == FALSE)
	{
		FindTarget();
	}
	else
	{
		targetInfo.TargetMain();
	}

	return;
}



EFI_STATUS EFIAPI SmmHandler(IN EFI_HANDLE  DispatchHandle, IN CONST VOID  *Context         OPTIONAL, IN OUT VOID    *CommBuffer      OPTIONAL, IN OUT UINTN   *CommBufferSize  OPTIONAL)
{
	if(os_ctx_initialized)
	{
		SerialPortInitialize(SERIAL_PORT_0, SERIAL_BAUDRATE);
		//delayer = 0;
		SmmCallHandle();
		return EFI_SUCCESS;
	}

	// else, count more seconds
	UINT16 curr_time = CmosGetCurrentTime();

	// did we overflow the UINT16?
	if(curr_time < last_time)
		last_time += curr_time;
	else
		last_time = curr_time;

	// here we just need to assume something, so we assume 30 seconds
	if(last_time - start_time > 10)
	{
		SerialPortInitialize(SERIAL_PORT_0, SERIAL_BAUDRATE);
		//delayer = 0;
		SmmCallHandle();
	}
	return EFI_SUCCESS;
}



EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable)
{
	// Write to serial port
	SerialPortInitialize(SERIAL_PORT_0, SERIAL_BAUDRATE);

	// Save the system tables etc. in global variable for further usage
	gST = SystemTable;
	gBS = SystemTable->BootServices;
	gRT = SystemTable->RuntimeServices;

	SerialPrintString("--------------------------------------------\r\n");
	SerialPrintString("|                                          |\r\n");
	SerialPrintString("|          S M M    R O O T K I T          |\r\n");
	SerialPrintString("|                                          |\r\n");
	SerialPrintString("--------------------------------------------\r\n");
	SerialPrintString("                                              \r\n");

	EFI_STATUS					Res;
	EFI_SMM_BASE2_PROTOCOL		*SmmBase2;

	EFI_GUID					SmmBase2Guid = EFI_SMM_BASE2_PROTOCOL_GUID;
	EFI_GUID					SmmDispatch = EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID;
	EFI_GUID					SmmCpuIo = EFI_SMM_CPU_IO2_PROTOCOL_GUID;
	EFI_GUID					SmmCpuProt = EFI_SMM_CPU_PROTOCOL_GUID;

	EFI_SMM_SW_DISPATCH2_PROTOCOL *SwDispatch = NULL;

	// need EFI_SMM_BASE2_PROTOCOL
	Res = SystemTable->BootServices->LocateProtocol(&SmmBase2Guid, NULL, (void**)&SmmBase2);
	if (Res != EFI_SUCCESS) return Res;

	// get EFI_SMM_SYSTEM_TABLE2 in global var
	Res = SmmBase2->GetSmstLocation(SmmBase2, &gSmst2);

	if (Res != EFI_SUCCESS) return Res;

	Res = gSmst2->SmmLocateProtocol(&SmmCpuIo, NULL, (void**)&gSmmIo);

	Res = SystemTable->BootServices->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (void**)&mCpu);

	void *Registration = NULL;

	EFI_STATUS Status = EFI_SUCCESS;

	Res = gSmst2->SmmLocateProtocol(&SmmCpuProt, NULL, (void**)&gSmmCpu);

	// Register an SMM Root Handler
	EFI_HANDLE					hSmmHandler;
	Res = gSmst2->SmiHandlerRegister(&SmmHandler, NULL, &hSmmHandler);

	// Get memory map
	SerialPrintStringDebug("Initializing UEFI Memory Map \r\n");
	if(InitUefiMemoryMap() == FALSE)
	{
		SerialPrintStringDebug("Failed dumping Memory Map \r\n");
		return EFI_ERROR_MAJOR;
	}
	SerialPrintStringDebug("Successfully dumped Memory Map \r\n");

	SerialPrintStringDebug("Memory Map at: ");
	SerialPrintNumberDebug((UINT64)GetUefiMemoryMap(), 16);
	SerialPrintStringDebug("\r\n");

	// allocate memory for windows context (useless)
	os_ctx_initialized = FALSE;
	EFI_PHYSICAL_ADDRESS physAddr;
	gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &physAddr);
	winGlobal = (WinCtx *)physAddr;
	SerialPrintStringDebug("WinGlobal: 0x");
	SerialPrintNumberDebug((UINT64)winGlobal, 16);
	SerialPrintStringDebug("\r\n");

	// Set the start time of the PC
	start_time = CmosGetCurrentTime();
	SerialPrintStringDebug("Start time was: ");
	SerialPrintNumberDebug(start_time, 10);
	SerialPrintStringDebug("\r\n");

	if(InitMemManager(100))
	{
		SerialPrintStringDebug("memory manager successfully initialized!\r\n");
	}

	return EFI_SUCCESS;
}


#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif