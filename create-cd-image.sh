#!/bin/sh
SUDO=
USERID=`id -u`
GROUPID=`id -g`
if [[ "$USERID" -ne 0 ]]; then
	SUDO=sudo
fi
$SUDO genpack-install --disk=walbrix.iso --cdrom --label=WBINSTALL --system-cfg=artifacts/whitebase/boot/grub/installer.cfg whitebase-x86_64.squashfs
[ -n "$SUDO" ] && $SUDO chown $USERID.$GROUPID walbrix.iso
xorriso -as mkisofs -f -J -r -V WBSOURCE -o walbrix-source.iso work/x86_64/profiles/*/cache/distfiles -graft-points profiles=profiles portage=work/portage

# qemu-system-x86_64 --enable-kvm -cdrom walbrix.iso -m 1024 -hda disk.img -monitor stdio -no-shutdown
