/*
 * This file has originally been supplied from 
 * vmread by Heep042
 */

#ifndef __smmrootkit_windows_h__
#define __smmrootkit_windows_h__

#ifdef __GNUC__
typedef unsigned int size_t;
#endif

#define HEADER_SIZE 0x1000
#define PAGE_OFFSET_SIZE 12
static const UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull;
static const UINT64 PMASK2 = (~0xfull << 8) & 0xfffffffffull;

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0 /* Export Directory */
#define IMAGE_DOS_SIGNATURE 0x5a4d     /* MZ */
#define IMAGE_NT_SIGNATURE 0x4550      /* PE00 */
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_DOS_HEADER
{
  UINT16 e_magic;
  UINT16 e_cblp;
  UINT16 e_cp;
  UINT16 e_crlc;
  UINT16 e_cparhdr;
  UINT16 e_minalloc;
  UINT16 e_maxalloc;
  UINT16 e_ss;
  UINT16 e_sp;
  UINT16 e_csum;
  UINT16 e_ip;
  UINT16 e_cs;
  UINT16 e_lfarlc;
  UINT16 e_ovno;
  UINT16 e_res[4];
  UINT16 e_oemid;
  UINT16 e_oeminfo;
  UINT16 e_res2[10];
  int e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
  UINT32 Characteristics;
  UINT32 TimeDateStamp;
  UINT16 MajorVersion;
  UINT16 MinorVersion;
  UINT32 Name;
  UINT32 Base;
  UINT32 NumberOfFunctions;
  UINT32 NumberOfNames;
  UINT32 AddressOfFunctions;
  UINT32 AddressOfNames;
  UINT32 AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER
{
  UINT16 Machine;
  UINT16 NumberOfSections;
  UINT32 TimeDateStamp;
  UINT32 PointerToSymbolTable;
  UINT32 NumberOfSymbols;
  UINT16 SizeOfOptionalHeader;
  UINT16 Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
  UINT32 VirtualAddress;
  UINT32 Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
  UINT16 Magic;
  UINT8 MajorLinkerVersion;
  UINT8 MinorLinkerVersion;
  UINT32 SizeOfCode;
  UINT32 SizeOfInitializedData;
  UINT32 SizeOfUninitializedData;
  UINT32 AddressOfEntryPoint;
  UINT32 BaseOfCode;
  UINT64 ImageBase;
  UINT32 SectionAlignment;
  UINT32 FileAlignment;
  UINT16 MajorOperatingSystemVersion;
  UINT16 MinorOperatingSystemVersion;
  UINT16 MajorImageVersion;
  UINT16 MinorImageVersion;
  UINT16 MajorSubsystemVersion;
  UINT16 MinorSubsystemVersion;
  UINT32 Win32VersionValue;
  UINT32 SizeOfImage;
  UINT32 SizeOfHeaders;
  UINT32 CheckSum;
  UINT16 Subsystem;
  UINT16 DllCharacteristics;
  UINT64 SizeOfStackReserve;
  UINT64 SizeOfStackCommit;
  UINT64 SizeOfHeapReserve;
  UINT64 SizeOfHeapCommit;
  UINT32 LoaderFlags;
  UINT32 NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64
{
  UINT32 Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_OPTIONAL_HEADER32
{
  UINT16 Magic;
  UINT8 MajorLinkerVersion;
  UINT8 MinorLinkerVersion;
  UINT32 SizeOfCode;
  UINT32 SizeOfInitializedData;
  UINT32 SizeOfUninitializedData;
  UINT32 AddressOfEntryPoint;
  UINT32 BaseOfCode;
  UINT32 BaseOfData;
  UINT32 ImageBase;
  UINT32 SectionAlignment;
  UINT32 FileAlignment;
  UINT16 MajorOperatingSystemVersion;
  UINT16 MinorOperatingSystemVersion;
  UINT16 MajorImageVersion;
  UINT16 MinorImageVersion;
  UINT16 MajorSubsystemVersion;
  UINT16 MinorSubsystemVersion;
  UINT32 Win32VersionValue;
  UINT32 SizeOfImage;
  UINT32 SizeOfHeaders;
  UINT32 CheckSum;
  UINT16 Subsystem;
  UINT16 DllCharacteristics;
  UINT32 SizeOfStackReserve;
  UINT32 SizeOfStackCommit;
  UINT32 SizeOfHeapReserve;
  UINT32 SizeOfHeapCommit;
  UINT32 LoaderFlags;
  UINT32 NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS32
{
  UINT32 Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_SECTION_HEADER
{
  UINT8 Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    UINT32 PhysicalAddress;
    UINT32 VirtualSize;
  } Misc;
  UINT32 VirtualAddress;
  UINT32 SizeOfRawData;
  UINT32 PointerToRawData;
  UINT32 PointerToRelocations;
  UINT32 PointerToLinenumbers;
  UINT16 NumberOfRelocations;
  UINT16 NumberOfLinenumbers;
  UINT32 Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _LIST_ENTRY_WIN
{
  UINT64 f_link;
  UINT64 b_link;
} LIST_ENTRY_WIN;

typedef struct _UNICODE_STRING
{
  UINT16 length;
  UINT16 maximum_length;
  UINT64 buffer;
} UNICODE_STRING;

typedef struct _LDR_MODULE
{
  LIST_ENTRY_WIN InLoadOrderModuleList;
  LIST_ENTRY_WIN InMemoryOrderModuleList;
  LIST_ENTRY_WIN InInitializationOrderModuleList;
  UINT64 BaseAddress;
  UINT64 EntryPoint;
  UINT64 SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  UINT64 Flags;
  short LoadCount;
  short TlsIndex;
  LIST_ENTRY_WIN HashTableEntry;
  UINT64 TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA
{
  UINT64 Length;
  UINT8 Initialized;
  UINT64 SsHandle;
  LIST_ENTRY_WIN InLoadOrderModuleList;
  LIST_ENTRY_WIN InMemoryOrderModuleList;
  LIST_ENTRY_WIN InInitializationOrderModuleList;
  UINT64 EntryInProgress;
} PEB_LDR_DATA;

typedef struct _PEB
{
  UINT8 InheritedAddressSpace;
  UINT8 ReadImageFileExecOptions;
  UINT8 BeingFebugged;
  UINT8 BitField;
  UINT8 Padding0[4];
  UINT64 Mutant;
  UINT64 ImageBaseAddress;
  UINT64 Ldr;
} PEB, PEB64;

typedef struct _LIST_ENTRY_32_WIN
{
  UINT32 f_link;
  UINT32 b_link;
} LIST_ENTRY_32_WIN;

typedef struct _UNICODE_STRING32
{
  UINT16 length;
  UINT16 maximum_length;
  UINT32 buffer;
} UNICODE_STRING32;

typedef struct _LDR_MODULE32
{
  LIST_ENTRY_32_WIN InLoadOrderModuleList;
  LIST_ENTRY_32_WIN InMemoryOrderModuleList;
  LIST_ENTRY_32_WIN InInitializationOrderModuleList;
  UINT32 BaseAddress;
  UINT32 EntryPoint;
  UINT32 SizeOfImage;
  UNICODE_STRING32 FullDllName;
  UNICODE_STRING32 BaseDllName;
  UINT32 Flags;
  short LoadCount;
  short TlsIndex;
  LIST_ENTRY_32_WIN HashTableEntry;
  UINT32 TimeDateStamp;
} LDR_MODULE32, *PLDR_MODULE32;

typedef struct _PEB_LDR_DATA32
{
  UINT32 Length;
  UINT8 Initialized;
  UINT32 SsHandle;
  LIST_ENTRY_32_WIN InLoadOrderModuleList;
  LIST_ENTRY_32_WIN InMemoryOrderModuleList;
  LIST_ENTRY_32_WIN InInitializationOrderModuleList;
  UINT32 EntryInProgress;
} PEB_LDR_DATA32;

typedef struct _PEB32
{
  UINT8 InheritedAddressSpace;
  UINT8 ReadImageFileExecOptions;
  UINT8 BeingFebugged;
  UINT8 BitField;
  UINT32 Mutant;
  UINT32 ImageBaseAddress;
  UINT32 Ldr;
} PEB32;

#endif