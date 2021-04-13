#!/bin/sh
set -e

pushd /var/db/repos/localrepo && repoman manifest || exit 1
popd

build-kernel

emerge -uDN -bk --binpkg-respect-use=y --exclude='sys-kernel/*' world @all

mkdir -p /tmp/initramfs

cat << EOS > /tmp/initramfs.lst
bin/cat
bin/cp
bin/mv
bin/sed
bin/umount
lib64/libacl.so.1
lib64/libattr.so.1
lib64/libc.so.6
lib64/ld-linux-x86-64.so.2
lib64/libblkid.so.1
lib64/libuuid.so.1
lib64/libmount.so.1
lib64/librt.so.1
lib64/libpthread.so.0
lib64/liblzo2.so.2
lib64/libsmartcols.so.1
lib64/libz.so.1
lib64/libdevmapper-event.so.1.02
lib64/libdl.so.2
lib64/libdevmapper.so.1.02
lib64/libaio.so.1
lib64/libm.so.6
lib64/libsystemd.so.0
lib64/libudev.so.1
lib64/libcap.so.2
sbin/btrfs
sbin/switch_root
sbin/mkfs.btrfs
sbin/mkswap
sbin/swapon
sbin/vgchange
usr/lib64/libiniparser4.so.1
usr/lib64/libzstd.so.1
usr/lib64/liblz4.so.1
usr/lib64/libgcrypt.so.20
usr/lib64/libgpg-error.so.0
usr/sbin/fsck.fat
EOS

mkdir -p /tmp/initramfs/usr/lib64
cp -L `gcc -print-file-name=libgcc_s.so.1` /tmp/initramfs/usr/lib64/
cp -L `gcc -print-file-name=libstdc++.so.6` /tmp/initramfs/usr/lib64/
g++ -std=c++2a -lblkid -lmount -liniparser4 /init.cpp /initlib.cpp -o /tmp/initramfs/init
tar cf - -C / -T /tmp/initramfs.lst -h | tar xvf - -C /tmp/initramfs
rm -f /boot/initramfs
cd /tmp/initramfs && find . | cpio -H newc -o > /boot/initramfs

