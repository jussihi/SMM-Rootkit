# SMM Rootkit

## Table of contents
- [Repository Contents](#repository-contents)
  * [SMM Rootkit](#smm-rootkit-1)
  * [shellcode](#shellcode)
  * [target_tests](#target_tests)
- [Compiling](#compiling)
  * [First time setup](#first-time-setup)
  * [Building](#building)
- [Running the OVMF inside QEMU/KVM](#running-the-ovmf-inside-qemukvm)
  * [VM setup](#vm-setup)
  * [Running](#running)
- [FAQ](#faq)
  * [How to patch PiSmmCpuDxeSmm](#how-to-patch-pismmcpudxesmm)
  * [No serial output after boot](#no-serial-output-after-boot)

## Intro

This System Management Mode (SMM) rootkit is a PoC to demonstrate how injecting shellcode to a ring0/ring3 context can be achieved from the SMM. 

If you want to read about SMM rootkits in general and about how this SMM rootkit was implemented, please read my recent [blog post](https://jussihi.kapsi.fi/2022-09-08-smmrootkit/) about it! Also please check our newest SMM-related project, [Hermes](https://github.com/pRain1337/Hermes), which enables SMM-level privilege escalation with interactive usermode application!

Created by Jussi Hietanen (Aalto University, Espoo FI) and Diego Caminada (HF-ICT, Muttenz CH).

## Repository Contents

#### SMM Rootkit
This folder contains the files & folders to be copied to the edk2 root dir to compile the SMM Rootkit with the rest of the OVMF. It includes ready-made configuration files and modified source files to allow the rootkit to access the whole 64-bit memory address space with on-demand paging.

#### shellcode
Contains shellcode to be generated for the SMM rootkit. This shellcode is then injected from the SMM to whatever process/operating system is targeted. You can read more about different types of attacks from their subfolders. Currently there is only Windows x64 usermode IAT hooking, but more should be added!

#### target_tests
Contains test programs to test the Rootkit functionality. For more information, check the subfolders' readmes.

## Compiling

### First time setup

Skip to "Building" if you have done the first-time setup already.

1. Clone the EDK2 inside this repo and checkout the right tag (vUDK2018, see step 3 for why this tag). 
```
$ git clone git@github.com:tianocore/edk2.git
$ cd edk2
$ git checkout vUDK2018
```

2. Start docker build env and setup BaseTools
```
# ./run_docker.sh
```
Inside docker, 
```
# cd edk2 
# make -C BaseTools
# . edksetup.sh
```

3. Exit docker, and copy the contents of SMM Rootkit folder to edk2 folder **(It is important to use the tag vUDK2018, otherwise the ready-patched files inside the SMM Rootkit folder won't match and the OVMF may not build successfully)**, in repo root run
```
# cp -r SMM\ Rootkit/* edk2/
```

First time setup is done!

### Building

Run
```
# ./run_docker.sh
```

Then, inside the docker,
```
# cd edk2
# . edksetup.sh
# build -DSMM_REQUIRE
```

The resulting OVMF firmware will be inside `edk2/Build/OvmfX64/RELEASE_GCC5/FV`.

## Running the OVMF inside QEMU/KVM

### VM Setup

Needed packages:
```
qemu libvirt virt-manager ebtables dnsmasq
```

For qemu to show the custom OVMF binary, you need to create a file `/usr/share/qemu/firmware/60-ovmf-rootkit-x86_64.json` and inside it add our FV entry:
```
{
  "description": "UEFI SMM rootkit OVMF firmware for x86_64",
  "interface-types": [
    "uefi"
  ],
  "mapping": {
    "device": "flash",
    "executable": {
      "filename": "/your/path/to-git/SMM-Rootkit/edk2/Build/OvmfX64/RELEASE_GCC5/FV/OVMF_CODE.fd",
      "format": "raw"
    },
    "nvram-template": {
      "filename": "/your/path/to-git/SMM-Rootkit/edk2/Build/OvmfX64/RELEASE_GCC5/FV/OVMF_VARS.fd",
      "format": "raw"
    }
  },
  "targets": [
    {
      "architecture": "x86_64",
      "machines": [
        "pc-i440fx-*",
        "pc-q35-*"
      ]
    }
  ],
  "features": [
    "acpi-s3",
    "amd-sev",
    "verbose-dynamic"
  ],
  "tags": [
    
  ]
}
```

Now you may create a new virtual machine. During setup, in the last state, check the box "Customize configuration before install" before clicking "Finish". From the next window, change the Firmware to the *UEFI SMM rootkit OVMF firmware for x86_64* configured earlier.

### Running

To start the vm, enable service `libvirtd` and enable default network; 
```
# virsh net-start default
```

To check the serial output (the VM must be powered on)
```
# virsh list
/* win10 is the name of the libvirt instance */
# virsh console win10
```

## FAQ

### How to patch PiSmmCpuDxeSmm

If you are trying to run this SMM rootkit on real hardware, you need to patch your motherboard's `PiSmmCpuDxeSmm` module from the UEFI firmware. You can mimick [our patch](https://github.com/jussihi/SMM-Rootkit/tree/master/SMM%20Rootkit/UefiCpuPkg) by 

Patching this variable initialization out and hard code the variable itself to 0 with your favorite disassembler (IDA or similar):
https://github.com/tianocore/edk2/blob/master/UefiCpuPkg/PiSmmCpuDxeSmm/X64/PageTbl.c#L352

Easiest way to find that function (SmmInitPageTable) is to search for the strings of the error messages:
https://github.com/tianocore/edk2/blob/master/UefiCpuPkg/Library/CpuExceptionHandlerLib/X64/ArchExceptionHandler.c#L265

Which is referenced multiple times in the SMI Page fault handler:
https://github.com/tianocore/edk2/blob/master/UefiCpuPkg/PiSmmCpuDxeSmm/X64/PageTbl.c#L1003

And the page fault handler is initialized in the same function as the variable initialization (SmmInitPageTable):
https://github.com/tianocore/edk2/blob/master/UefiCpuPkg/PiSmmCpuDxeSmm/X64/PageTbl.c#L442

### No serial output after boot

Sometimes the serial traffic is blocked as the operating system's own serial driver. This is at least the case in Windows systems when not booting inside a (QEMU/KVM) virtual machine.

#### There are two ways to get serial working on this sort of situation:

- Block the Operating System from loading the driver.

On GNU+Linux, you can disable the driver completely if one is loaded. On Windows systems, you might need to rename/delete the system's serial driver. The default path to the driver executable is  `C:\Windows\System32\drivers\serial.sys`

- Open an SSH client locally

You can also open the connection to the local serial port using your favorite serial client. At least on Windows this will prevent Windows' own driver from suppressing the serial output.
