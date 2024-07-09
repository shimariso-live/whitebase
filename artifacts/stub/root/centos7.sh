#!/bin/sh
set -e
/lib/systemd/systemd-networkd-wait-online
BASE_URL=http://ftp.iij.ad.jp/pub/linux/centos-vault/7.9.2009/os/x86_64/

if /sbin/mkfs.xfs -m crc=0 -n ftype=0 -i nrext64=0 -f /dev/vdb; then
	mount /dev/vdb /mnt
else
	mount -t virtiofs fs /mnt
	echo "WARNING: virtiofs is not supported by CentOS 7. the system won't boot."
fi
mkdir /mnt/dev /mnt/proc
mount -t proc proc /mnt/proc
cp -a /dev/null /dev/urandom /mnt/dev/

mkdir -p /mnt/etc/dracut.conf.d
echo 'filesystems+=" xfs "' > /mnt/etc/dracut.conf.d/xfs.conf

rpmbootstrap $BASE_URL /mnt yum

echo -e 'search local\nnameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 2001:4860:4860::8888\nnameserver 2001:4860:4860::8844' > /mnt/etc/resolv.conf

rm /mnt/var/lib/rpm/*
chroot /mnt rpm --rebuilddb
echo 7 > /mnt/etc/yum/vars/releasever
sed -i 's/^mirrorlist=/#mirrorlist=/g' /mnt/etc/yum.repos.d/CentOS-Base.repo
sed -i 's/^#baseurl=http:\/\/mirror\.centos\.org/baseurl=http:\/\/vault\.centos\.org/g' /mnt/etc/yum.repos.d/CentOS-Base.repo
chroot /mnt yum install -y "yum" "passwd" "vim-minimal" "strace" "less" "kernel" "tar" "openssh-server" "openssh-clients" "avahi" "NetworkManager" "xfsprogs" "qemu-guest-agent"

hostname > /mnt/etc/hostname
echo -e 'DEVICE="eth0"\nBOOTPROTO=dhcp\nONBOOT=yes\nTYPE="Ethernet"' > /mnt/etc/sysconfig/network-scripts/ifcfg-eth0
sed -i 's/^\(root:\)[^:]*\(:.*\)$/\1\2/' /mnt/etc/shadow
sed -i 's/^use-ipv6=no$/use-ipv6=yes/' /mnt/etc/avahi/avahi-daemon.conf
echo 'LANG=ja_JP.utf8' > /mnt/etc/locale.conf
[ -f /etc/localtime ] && cp -a /etc/localtime /mnt/etc/
touch /mnt/etc/sysconfig/network

[ -d /root/.ssh ] && cp -a /root/.ssh /mnt/root/
[ -d /etc/ssh -a -d /mnt/etc/ssh ] && cp -a /etc/ssh/*_key /etc/ssh/*_key.pub /mnt/etc/ssh/

cp -a /sbin/llmnrd /mnt/usr/sbin/
cat <<EOF > /mnt/etc/systemd/system/llmnrd.service
[Unit]
Description=Link-Local Multicast Name Resolution Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/llmnrd -6
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

chroot /mnt systemctl enable sshd avahi-daemon llmnrd qemu-guest-agent

umount /mnt/proc
umount /mnt

reboot
