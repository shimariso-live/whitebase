#!/bin/sh
set -e

find /var/db/repos/localrepo -name '*.ebuild' -type f -exec ebuild {} manifest \;

build-kernel --config /kernel-config.`uname -m`

emerge -uDN -bk --binpkg-respect-use=y --exclude='sys-kernel/*' world @all

g++ -std=c++2a -static-libgcc -static-libstdc++ -o /init /init.cpp /init-overrides.cpp -lmount -lblkid -liniparser4
rm -f /boot/initramfs
/init > /boot/initramfs
