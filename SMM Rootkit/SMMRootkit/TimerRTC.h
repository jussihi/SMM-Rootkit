#ifndef __smmrootkit_timer_rtc_h__
#define __smmrootkit_timer_rtc_h__

#include <Uefi.h>
#include <Library/IoLib.h>

#define CMOS_PORT_ADDRESS 0x70
#define CMOS_PORT_DATA    0x71

UINT8 cmos_read(UINT8 index);

VOID cmos_write(UINT8 index, UINT8 val);

VOID read_statusc();

VOID cmos_enable();

UINT8 get_RTC_register(INT32 reg);

UINT16 CmosGetCurrentTime();

#endif