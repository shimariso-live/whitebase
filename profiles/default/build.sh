#!/bin/sh
set -e

pushd /var/db/repos/localrepo && repoman manifest || exit 1
popd

build-kernel

if ! equery -q l xen-tools && ! equery -q l qemu; then
	USE="-system-qemu -ipxe -pam -pygrub -python -qemu-traditional -rombios" emerge -1 -k xen-tools
fi

emerge -uDN -bk --binpkg-respect-use=y --exclude='sys-kernel/*' world @all @genpack-install

g++ -std=c++2a -static-libgcc -static-libstdc++ -o /init /init.cpp /init-overrides.cpp -lmount -lblkid -liniparser4
rm -f /boot/initramfs
/init > /boot/initramfs
