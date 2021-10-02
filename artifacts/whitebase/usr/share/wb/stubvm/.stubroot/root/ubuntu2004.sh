#!/bin/sh
set -e
/sbin/mkfs.btrfs -f /dev/vda
mkdir -p /mnt
mount /dev/vda /mnt

/usr/sbin/debootstrap --include="ubuntu-minimal,initramfs-tools,openssh-server,linux-generic,avahi-daemon,llmnrd,qemu-guest-agent,locales-all" --components=main,universe --arch=amd64 focal /mnt http://ubuntutym.u-toyama.ac.jp/ubuntu

hostname > /mnt/etc/hostname
mkdir -p /mnt/boot/grub
echo -e 'linux /boot/vmlinuz root=/dev/vda net.ifnames=0 console=ttyS0,115200n8r systemd.hostname=$hostname systemd.firstboot=0\ninitrd /boot/initrd.img\nboot' > /mnt/boot/grub/grub.cfg

sed -i 's/^\(root:\)[^:]*\(:.*\)$/\1\2/' /mnt/etc/shadow
echo -e '/dev/vda /                       btrfs     defaults        1 1' > /mnt/etc/fstab
echo -e 'network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    eth0:\n      dhcp4: true\n      dhcp6: true' > /mnt/etc/netplan/99_config.yaml

[ -f /etc/localtime ] && cp -a /etc/localtime /mnt/etc/

cp -a /root/.ssh /mnt/root/

umount /mnt/proc
umount /mnt
rm -rf /.real_root/boot /.real_root/etc

poweroff
