#!/bin/sh
set -e
/lib/systemd/systemd-networkd-wait-online
BASE_URL=http://ftp.iij.ad.jp/pub/linux/centos-vault/6.10/os/x86_64/

if /sbin/mkfs.xfs -m crc=0 -n ftype=0 -i nrext64=0 -f /dev/vdb; then
	mount /dev/vdb /mnt
else
	mount -t virtiofs fs /mnt
fi
mkdir /mnt/dev /mnt/proc
mount -t proc proc /mnt/proc
cp -a /dev/null /dev/urandom /mnt/dev/

mkdir -p /mnt/etc/dracut.conf.d
echo 'add_drivers+=" xfs "' > /mnt/etc/dracut.conf.d/xfs.conf

rpmbootstrap --no-signature $BASE_URL /mnt yum centos-release

echo -e 'search local\nnameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 2001:4860:4860::8888\nnameserver 2001:4860:4860::8844' > /mnt/etc/resolv.conf


rm /mnt/var/lib/rpm/*
chroot /mnt /bin/rpm --rebuilddb

sed -i -e "s/^mirrorlist=http:\/\/mirrorlist.centos.org/#mirrorlist=http:\/\/mirrorlist.centos.org/g" /mnt/etc/yum.repos.d/CentOS-Base.repo
sed -i -e "s/^#baseurl=http:\/\/mirror.centos.org/baseurl=http:\/\/ftp.iij.ad.jp\/pub\/linux\/centos-vault/g" /mnt/etc/yum.repos.d/CentOS-Base.repo
echo 6.10 > /mnt/etc/yum/vars/releasever

chroot /mnt yum install -y "yum" "passwd" "vim-minimal" "strace" "less" "kernel" "xfsprogs" "tar" "dhclient" "openssh-server" "openssh-clients" "avahi" "qemu-guest-agent" "acpid"

echo -e '/dev/vdb\t/\txfs\tdefaults\t1 1' > /mnt/etc/fstab
echo -e 'DEVICE="eth0"\nBOOTPROTO=dhcp\nONBOOT=yes\nTYPE="Ethernet"' > /mnt/etc/sysconfig/network-scripts/ifcfg-eth0
echo -e 'search local\nnameserver 8.8.8.8\nnameserver 8.8.4.4' > /mnt/etc/resolv.conf
sed -i 's/^\(root:\)[^:]*\(:.*\)$/\1\2/' /mnt/etc/shadow
sed -i 's/^use-ipv6=no$/use-ipv6=yes/' /mnt/etc/avahi/avahi-daemon.conf
echo 'LANG=ja_JP.utf8' > /mnt/etc/locale.conf
[ -f /etc/localtime ] && cp -a /etc/localtime /mnt/etc/

echo -e 'NETWORKING=yes\nHOSTNAME="'`hostname`'"' > /mnt/etc/sysconfig/network
sed -i 's/^ACTIVE_CONSOLES=.*/ACTIVE_CONSOLES=/' /mnt/etc/sysconfig/init

[ -d /root/.ssh ] && cp -a /root/.ssh /mnt/root/
[ -d /etc/ssh -a -d /mnt/etc/ssh ] && cp -a /etc/ssh/*_key /etc/ssh/*_key.pub /mnt/etc/ssh/

cp -a /sbin/llmnrd /mnt/usr/sbin/

chroot /mnt /sbin/chkconfig sshd on
chroot /mnt /sbin/chkconfig qemu-ga on
chroot /mnt /sbin/chkconfig avahi-daemon on
chroot /mnt /sbin/chkconfig acpid on

umount /mnt/proc
umount /mnt

echo "kexec-2.0.28 may not be able to load CentOS6's kernel"

reboot
