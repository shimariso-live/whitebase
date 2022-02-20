#!/bin/sh
set -e

build-kernel

emerge -uDN -bk --binpkg-respect-use=y pixman # needed by xen-tools
emerge -uDN -bk --binpkg-respect-use=y --exclude='sys-kernel/*' --buildpkg-exclude='www-servers/apache' world @all

g++ -std=c++2a -static-libgcc -static-libstdc++ -o /init /init.cpp -lmount -lxenstore -lblkid -DPARAVIRT
rm -f /boot/initramfs
/init > /boot/initramfs

rm -f /sbin/init
cp -a /linuxrc /sbin/init

