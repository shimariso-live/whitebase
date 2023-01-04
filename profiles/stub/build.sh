#!/bin/sh
set -e

build-kernel

emerge -uDN -bk --binpkg-respect-use=y --exclude='sys-kernel/*' world @all

#cp -a /linuxrc /sbin/init

