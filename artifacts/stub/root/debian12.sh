#!/bin/sh
set -e
/sbin/mkfs.xfs -f /dev/vdb
mkdir -p /mnt
mount /dev/vdb /mnt

ARCH=amd64
/usr/sbin/debootstrap --include="initramfs-tools,openssh-server,linux-image-$ARCH,dbus,systemd-resolved,qemu-guest-agent,locales-all" --components=main,universe --arch=$ARCH bookworm /mnt https://linux.yz.yamagata-u.ac.jp/pub/linux/debian

sed -i 's/^\(root:\)[^:]*\(:.*\)$/\1\2/' /mnt/etc/shadow
echo -e '/dev/vdb /                       xfs     defaults        1 1' > /mnt/etc/fstab
echo -e '[Match]\nName=eth0 host0\n[Network]\nDHCP=yes\nMulticastDNS=yes\nLLMNR=yes\n' > /mnt/etc/systemd/network/50-eth0.network

[ -f /etc/localtime ] && cp -a /etc/localtime /mnt/etc/

[ -d /root/.ssh ] && cp -a /root/.ssh /mnt/root/
[ -d /etc/ssh -a -d /mnt/etc/ssh ] && cp -a /etc/ssh/*_key /etc/ssh/*_key.pub /mnt/etc/ssh/

chroot /mnt systemctl enable systemd-networkd systemd-resolved

umount /mnt
reboot
