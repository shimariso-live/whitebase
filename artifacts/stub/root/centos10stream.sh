#!/bin/sh
set -e
/lib/systemd/systemd-networkd-wait-online

BASE_URL=http://ftp.iij.ad.jp/pub/linux/centos-stream/10-stream/BaseOS/$(uname -m)/os/

if /sbin/mkfs.xfs -f -i nrext64=0 /dev/vdb; then
        mount /dev/vdb /mnt
else
        mount -t virtiofs fs /mnt
fi

mkdir /mnt/dev /mnt/proc /mnt/sys
mount -o bind /proc /mnt/proc
mount -o bind /sys /mnt/sys
mount -o bind /dev /mnt/dev

mkdir -p /mnt/etc/dracut.conf.d
echo 'add_drivers+=" virtiofs "' > /mnt/etc/dracut.conf.d/virtiofs.conf
echo -e 'add_dracutmodules+=" crypt "\nadd_drivers+=" dm-crypt dm-mod "' > /mnt/etc/dracut.conf.d/crypt.conf

rpmbootstrap $BASE_URL /mnt "dnf" "vim-minimal" "strace" "less" "policycoreutils" "grubby" "kernel" "tar" "openssh-server" "openssh-clients" "avahi" "NetworkManager" "iproute" "iputils" "cryptsetup"

echo -e 'search local\nnameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 2001:4860:4860::8888\nnameserver 2001:4860:4860::8844' > /mnt/etc/resolv.conf
sed -i 's/^\(root:\)[^:]*\(:.*\)$/\1\2/' /mnt/etc/shadow
sed -i 's/^use-ipv6=no$/use-ipv6=yes/' /mnt/etc/avahi/avahi-daemon.conf
echo 'LANG=ja_JP.utf8' > /mnt/etc/locale.conf
[ -f /etc/localtime ] && cp -a /etc/localtime /mnt/etc/

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
chroot /mnt dnf install -y qemu-guest-agent
chroot /mnt systemctl enable sshd avahi-daemon llmnrd qemu-guest-agent

umount /mnt/dev
umount /mnt/sys
umount /mnt/proc
umount /mnt

reboot
