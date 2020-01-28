#define BACKDOOR_DEBUG
#define BACKDOOR_DEBUG_SERIAL_BUILTIN

// read MSR_SMM_MCA_CAP register value
#define USE_MSR_SMM_MCA_CAP

/*
 * Serial port configuration.
 * For EFI_DEBUG_SERIAL_BUILTIN and EFI_DEBUG_SERIAL_PROTOCOL.
 * Port 0 is the default port on the motherboard
 */
#define SERIAL_BAUDRATE 115200
#define SERIAL_PORT_0 0x3F8 