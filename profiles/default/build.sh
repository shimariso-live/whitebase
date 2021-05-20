#!/bin/sh
set -e

pushd /var/db/repos/localrepo && repoman manifest || exit 1
popd

build-kernel

emerge -uDN -bk --binpkg-respect-use=y --exclude='sys-kernel/*' world @common @walbrix

g++ -std=c++2a -static-libgcc -static-libstdc++ -o /init /init.cpp /init-overrides.cpp -lmount -lblkid -liniparser4
rm -f /boot/initramfs
/init > /boot/initramfs
