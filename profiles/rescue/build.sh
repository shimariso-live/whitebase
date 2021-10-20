#!/bin/sh
set -e

build-kernel

emerge -uDN -bk --binpkg-respect-use=y --exclude='sys-kernel/*' world @all

g++ -std=c++2a -static-libgcc -static-libstdc++ -o /init /init.cpp -lmount -lblkid -liniparser4
rm -f /boot/initramfs
/init > /boot/initramfs
