#include "TimerRTC.h"


UINT8 cmos_read(UINT8 index)
{
  IoWrite8(CMOS_PORT_ADDRESS, index);
  return IoRead8(CMOS_PORT_DATA);
}

VOID cmos_write(UINT8 index, UINT8 val)
{
  IoWrite8(CMOS_PORT_ADDRESS, index);
  IoWrite8(CMOS_PORT_DATA, val);
}

VOID read_statusc()
{
  // Has to be done after every interrupt else timer stops
  IoWrite8(CMOS_PORT_ADDRESS, 0xC);
  IoRead8(CMOS_PORT_DATA);
}

VOID cmos_enable()
{
  // Read current Status A
  UINT8 regA = cmos_read(0xA);

  // Set timer to 500ms
  regA = (regA & 0xF0) | 0x5;

  // Write Status A
  cmos_write(0xA, regA);

  // Read current Status B
  UINT8 regB = cmos_read(0xB);

  // Enable periodic timer
  regB = regB | 0x40;

  // Write Status B
  cmos_write(0xB, regB);
}

UINT8 get_RTC_register(INT32 reg)
{
  IoWrite8(CMOS_PORT_ADDRESS, reg);
  return IoRead8(CMOS_PORT_DATA);
}

UINT16 CmosGetCurrentTime()
{
  // Read Seconds and minutes
  UINT8 second = get_RTC_register(0x00);
  UINT8 minute = get_RTC_register(0x02);

  UINT8 registerB = cmos_read(0xB);
  if (!(registerB & 0x04))
  {
    second = (second & 0x0F) + ((second / 16) * 10);
    minute = (minute & 0x0F) + ((minute / 16) * 10);
  }

  return (UINT16)minute * 60 + second;
}