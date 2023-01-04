#!/bin/sh
set -e
BASE_URL=http://ftp.iij.ad.jp/pub/linux/centos/7/os/x86_64/
RPM_DIR=/rpm-centos7
mkdir -p /mnt $RPM_DIR

rpmbootstrap $BASE_URL get-packages-data | rpmbootstrap $BASE_URL download --dependency-exclude=/usr/libexec/platform-python $RPM_DIR "yum" "passwd" "vim-minimal" "strace" "less" "kernel" "tar" "openssh-server" "openssh-clients" "avahi" "NetworkManager" "xfsprogs"

/sbin/mkfs.xfs -m crc=0 -n ftype=0 -f /dev/vda
mount /dev/vda /mnt
mkdir /mnt/dev /mnt/proc
mount -t proc proc /mnt/proc
cp -a /dev/null /dev/urandom /mnt/dev/

mkdir -p /mnt/etc/dracut.conf.d
echo 'filesystems+=" xfs "' > /mnt/etc/dracut.conf.d/xfs.conf

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

oldpath=`pwd`
cd /mnt/boot
ln -s vmlinuz-* vmlinuz
ln -s initramfs-* initramfs
cd $oldpath
chroot /mnt yum install -y qemu-guest-agent https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
chroot /mnt systemctl enable sshd avahi-daemon llmnrd qemu-guest-agent

umount /mnt/proc
umount /mnt
rm -rf /.real_root/boot /.real_root/etc

poweroff
