#!/bin/sh
set -e
BASE_URL=http://ftp.iij.ad.jp/pub/linux/centos/8-stream/BaseOS/x86_64/os/
RPM_DIR=/rpm-centos8-stream
mkdir -p /mnt $RPM_DIR 

rpmbootstrap $BASE_URL get-packages-data | rpmbootstrap $BASE_URL download --dependency-exclude=/usr/libexec/platform-python $RPM_DIR "yum" "passwd" "vim-minimal" "strace" "less" "kernel" "tar" "openssh-server" "openssh-clients" "avahi" "NetworkManager" "xfsprogs"

/sbin/mkfs.xfs -f /dev/vda
mount /dev/vda /mnt
mkdir /mnt/dev /mnt/proc
mount -t proc proc /mnt/proc
cp -a /dev/null /dev/urandom /mnt/dev/

mkdir -p /mnt/etc/dracut.conf.d
echo 'add_drivers+=" xfs "' > /mnt/etc/dracut.conf.d/xfs.conf
echo 'add_drivers+=" virtiofs "' > /mnt/etc/dracut.conf.d/virtiofs.conf

rpm -Uvh --root=/mnt $RPM_DIR/*.rpm
rm -rf $RPM_DIR

echo -e 'DEVICE="eth0"\nBOOTPROTO=dhcp\nONBOOT=yes\nTYPE="Ethernet"' > /mnt/etc/sysconfig/network-scripts/ifcfg-eth0
echo -e 'search local\nnameserver 8.8.8.8\nnameserver 8.8.4.4' > /mnt/etc/resolv.conf
sed -i 's/^\(root:\)[^:]*\(:.*\)$/\1\2/' /mnt/etc/shadow
sed -i 's/^use-ipv6=no$/use-ipv6=yes/' /mnt/etc/avahi/avahi-daemon.conf
echo 'LANG=ja_JP.utf8' > /mnt/etc/locale.conf
[ -f /etc/localtime ] && cp -a /etc/localtime /mnt/etc/

echo -e '/dev/vda /                       xfs     defaults        1 1' > /mnt/etc/fstab
hostname > /mnt/etc/hostname
touch /mnt/etc/sysconfig/network
mkdir -p /mnt/boot/grub
echo -e 'linux /boot/vmlinuz root=/dev/vda ro crashkernel=auto net.ifnames=0 console=ttyS0,115200n8r systemd.hostname=$hostname systemd.firstboot=0\ninitrd /boot/initramfs\nboot' > /mnt/boot/grub/grub.cfg

[ -d /root/.ssh ] && cp -a /root/.ssh /mnt/root/

oldpath=`pwd`
cd /mnt/boot
ln -s */*/linux vmlinuz
ln -s */*/initrd initramfs
cd $oldpath
chroot /mnt dnf install -y qemu-guest-agent
chroot /mnt systemctl enable sshd avahi-daemon qemu-guest-agent

umount /mnt/proc
umount /mnt

poweroff
