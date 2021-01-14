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

## Intro

This System Management Mode (SMM) rootkit is a PoC to demonstrate how injecting shellcode to a ring0/ring3 context can be achieved from the SMM. 

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
