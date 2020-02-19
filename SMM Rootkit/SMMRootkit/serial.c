#include "serial.h"

/*
 * UART Register Offsets
 */
#define BAUD_LOW_OFFSET 0x00
#define BAUD_HIGH_OFFSET 0x01
#define IER_OFFSET 0x01
#define LCR_SHADOW_OFFSET 0x01
#define FCR_SHADOW_OFFSET 0x02
#define IR_CONTROL_OFFSET 0x02
#define FCR_OFFSET 0x02
#define EIR_OFFSET 0x02
#define BSR_OFFSET 0x03
#define LCR_OFFSET 0x03
#define MCR_OFFSET 0x04
#define LSR_OFFSET 0x05
#define MSR_OFFSET 0x06

/*
 * UART Register Bit Defines
 */
#define LSR_TXRDY 0x20
#define LSR_RXDA 0x01
#define DLAB 0x01

/*
 * UART Settings
 */
UINT8 m_Data = 8;
UINT8 m_Stop = 1;
UINT8 m_Parity = 0;
UINT8 m_BreakSet = 0;

VOID SerialPortInitialize(UINT16 Port, UINTN Baudrate)
{
  // Map 5..8 to 0..3
  UINT8 Data = (UINT8)(m_Data - (UINT8)5);

  // Calculate divisor for baud generator
  UINTN Divisor = SERIAL_BAUDRATE_MAX / Baudrate;

  // Set communications format
  UINT8 OutputData = (UINT8)((DLAB << 7) | (m_BreakSet << 6) | (m_Parity << 3) | (m_Stop << 2) | Data);
  IoWrite8((UINTN)(Port + LCR_OFFSET), OutputData);

  // Configure baud rate
  IoWrite8((UINTN)(Port + BAUD_HIGH_OFFSET), (UINT8)(Divisor >> 8));
  IoWrite8((UINTN)(Port + BAUD_LOW_OFFSET), (UINT8)(Divisor & 0xff));

  // Switch back to bank 0
  OutputData = (UINT8)((~DLAB << 7) | (m_BreakSet << 6) | (m_Parity << 3) | (m_Stop << 2) | Data);
  IoWrite8((UINTN)(Port + LCR_OFFSET), OutputData);
}

VOID SerialPortWrite(UINT16 Port, UINT8 Data)
{
  UINT8 Status = 0;

  do
  {
    // Wait for the serail port to be ready
    Status = IoRead8(Port + LSR_OFFSET);

  } while ((Status & LSR_TXRDY) == 0);

  IoWrite8(Port, Data);
}

UINT8 SerialPortRead(UINT16 Port)
{
  UINT8 Status = 0;

  do
  {
    // Wait for the serail port to be ready
    Status = IoRead8(Port + LSR_OFFSET);

  } while ((Status & LSR_RXDA) == 0);

  return IoRead8(Port);
}

VOID SerialPrintString(const char *text)
{
  SerialPortInitialize(SERIAL_PORT_0, SERIAL_BAUDRATE);

  while (*text)
  {
    // send single byte via serial port
    SerialPortWrite(SERIAL_PORT_0, *text++);
  }
}

VOID SerialPrintStringDebug(const char *text)
{
#ifdef ROOTKIT_VERBOSE
  SerialPrintString(text);
#endif
}

VOID SerialTest()
{
  // Send 0xA 8 times

  for (int i = 0; i < 8; i++)
  {
    SerialPortWrite(SERIAL_PORT_0, 0xA);
  }
}

VOID SerialSendData(const VOID *buf, UINT8 len)
{
  for (UINT64 i = 0; i < len; i++)
  {
    SerialPortWrite(SERIAL_PORT_0, ((const char *)buf)[i]);
  }
}

VOID SerialPrintNumber(INT64 _v, INT64 _b)
{
  char _r[100];
  // check validity
  if (_b < 2 || _b > 36)
  {
    *_r = 0;
    return;
  }

  char *ptr = _r;
  char *ptr1 = _r;
  char tmp_char;
  INT64 tmp_value;

  do
  {
    tmp_value = _v;
    _v /= _b;
    *ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"[35 + (tmp_value - _v * _b)];
  } while (_v);

  // is the value neg?
  if (tmp_value < 0 && _b == 10)
  {
    *ptr++ = '-';
  }
  *ptr-- = '\0';
  while (ptr1 < ptr)
  {
    tmp_char = *ptr;
    *ptr-- = *ptr1;
    *ptr1++ = tmp_char;
  }

  SerialPrintString(_r);
}

VOID SerialPrintNumberDebug(UINT64 _v, UINT64 _b)
{
#ifdef ROOTKIT_VERBOSE
  SerialPrintNumber(_v, _b);
#endif
}
