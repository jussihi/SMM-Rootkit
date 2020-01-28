### First time setup

Skip to "Building" if you have done the first-time setup already.

1. Clone the EDK2 inside this repo and checkout the right tag (vUDK2018)
```
git clone git@github.com:tianocore/edk2.git
cd edk2
git checkout vUDK2018
```

2. Start docker build env and setup BaseTools (comprehensive instructions can be found from https://github.com/tianocore/tianocore.github.io/wiki/Common-instructions-for-Unix)
```
./run_docker.sh
```
Inside docker, 
```
cd edk2 
make -C edk2/BaseTools
. edksetup.sh
```

3. Exit docker, and copy the contents of SMMRootkit folder to edk2 folder, in repo root run
```
cp -r SMM\ Rootkit/* edk2/
```

First time setup is done!

### Building

Run
```
# ./run_docker.sh
```

Then, inside the docker,
```
cd edk2
. edksetup.sh
build -DSMM_REQUIRE
```

The resulting OVMF firmware will be inside `edk2/Build/OvmfX64/RELEASE_GCC5/FV`.

### Running the OVMF inside QEMU/KVM

Needed packages:
```
qemu
libvirt
virt-manager
ebtables
dnsmasq
```

To start the vm, enable service `libvirtd` and enable default network; 
```
# virsh net-start default
```

From VM settings, choose the `edk2/Build/OvmfX64/RELEASE_GCC5/FV/OVMF.fd` as the UEFI firmware. You are good to go!

To check the serial output
```
sudo virsh list
/* win10 is the name of the libvirt instance */
sudo virsh console win10
```