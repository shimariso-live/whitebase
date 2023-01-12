#!/bin/sh
set -e
/sbin/mkfs.btrfs -f /dev/vdb
mkdir -p /mnt
mount /dev/vdb /mnt

/usr/sbin/debootstrap --include="ubuntu-minimal,initramfs-tools,openssh-server,linux-generic,avahi-daemon,llmnrd,qemu-guest-agent,locales-all" --components=main,universe --arch=amd64 jammy /mnt https://linux.yz.yamagata-u.ac.jp/pub/linux/ubuntu/archives

sed -i 's/^\(root:\)[^:]*\(:.*\)$/\1\2/' /mnt/etc/shadow
echo -e '/dev/vdb /                       btrfs     defaults        1 1' > /mnt/etc/fstab
echo -e 'network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    eth0:\n      dhcp4: true\n      dhcp6: true' > /mnt/etc/netplan/99_config.yaml

[ -f /etc/localtime ] && cp -a /etc/localtime /mnt/etc/

[ -d /root/.ssh ] && cp -a /root/.ssh /mnt/root/
[ -d /etc/ssh -a -d /mnt/etc/ssh ] && cp -a /etc/ssh/*_key /etc/ssh/*_key.pub /mnt/etc/ssh/

umount /mnt
reboot
