#!/bin/sh
set -e

find /var/db/repos/localrepo -name '*.ebuild' -type f -exec ebuild {} manifest \;

build-kernel --config /kernel-config.`uname -m`

emerge -uDN -bk --binpkg-respect-use=y --exclude='sys-kernel/*' world @all

g++ -std=c++2a -static-libgcc -static-libstdc++ -o /init /init.cpp /init-overrides.cpp -lmount -lblkid -liniparser4
rm -f /boot/initramfs
/init > /boot/initramfs

mkdir -p /var/cache/repos

if [ -d /var/cache/repos/vm ]; then
	cd /var/cache/repos/vm
	git pull
else
	git clone https://github.com/shimarin/vm.git /var/cache/repos/vm
	cd /var/cache/repos/vm
fi
make vm
cp -a vm /usr/bin/

if [ -d /var/cache/repos/wghub ]; then
	cd /var/cache/repos/wghub
	git pull
else
	git clone  https://github.com/shimarin/wghub.git /var/cache/repos/wghub
	cd /var/cache/repos/wghub
fi
make libwghub.a
make install

if [ -d /var/cache/repos/wb ]; then
	cd /var/cache/repos/wb
	git pull
else
	git clone https://github.com/wbrxcorp/wb.git /var/cache/repos/wb
	cd /var/cache/repos/wb
fi
make wb
cp -a wb /usr/bin/

