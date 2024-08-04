#!/bin/sh
set -e
/lib/systemd/systemd-networkd-wait-online

RELEASEVER=9
BASE_URL=http://ftp.iij.ad.jp/pub/linux/almalinux/$RELEASEVER/BaseOS/$(uname -m)/os/

if /sbin/mkfs.xfs -f -i nrext64=0 /dev/vdb; then
	mount /dev/vdb /mnt
else
	mount -t virtiofs fs /mnt
fi

mkdir -p /mnt/dev /mnt/proc /mnt/sys
mount -o bind /proc /mnt/proc
mount -o bind /sys /mnt/sys
mount -o bind /dev /mnt/dev

mkdir -p /mnt/etc/dracut.conf.d
echo 'add_drivers+=" virtiofs "' > /mnt/etc/dracut.conf.d/virtiofs.conf

rpmbootstrap -x /usr/libexec/platform-python $BASE_URL /mnt "dnf"

echo -e 'search local\nnameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 2001:4860:4860::8888\nnameserver 2001:4860:4860::8844' > /mnt/etc/resolv.conf

rm /mnt/var/lib/rpm/*
chroot /mnt rpm --rebuilddb
echo $RELEASEVER > /mnt/etc/dnf/vars/releasever
chroot /mnt dnf install -y "dnf" "passwd" "vim-minimal" "strace" "less" "kernel" "tar" "openssh-server" "openssh-clients" "avahi" "NetworkManager" "iproute" "qemu-guest-agent" "grub2-common" "almalinux-gpg-keys"

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

umount /mnt/dev
umount /mnt/sys
umount /mnt/proc
umount /mnt

reboot
