#!/bin/sh
set -e

ROOTFS_DEVICE=/dev/vdb
ROOTFS_TYPE=xfs

if /sbin/mkfs.$ROOTFS_TYPE -f $ROOTFS_DEVICE; then
        mount $ROOTFS_DEVICE /mnt
else
        ROOTFS_DEVICE=fs
        ROOTFS_TYPE=virtiofs
        mount -t $ROOTFS_TYPE $ROOTFS_DEVICE /mnt
fi

case "$(uname -m)" in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64)
        ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture"
        exit 1
        ;;
esac

/usr/sbin/debootstrap --include="initramfs-tools,openssh-server,linux-image-$ARCH,dbus,systemd-resolved,qemu-guest-agent,locales-all" --components=main,universe --arch=$ARCH bookworm /mnt https://linux.yz.yamagata-u.ac.jp/pub/linux/debian

sed -i 's/^\(root:\)[^:]*\(:.*\)$/\1\2/' /mnt/etc/shadow
echo -e "$ROOTFS_DEVICE /                       $ROOTFS_TYPE     defaults        1 1" > /mnt/etc/fstab
echo -e '[Match]\nName=eth0 host0\n[Network]\nDHCP=yes\nMulticastDNS=yes\nLLMNR=yes\n' > /mnt/etc/systemd/network/50-eth0.network
echo 'deb http://security.debian.org/debian-security bookworm-security main' >> /mnt/etc/apt/sources.list

[ -f /etc/localtime ] && cp -a /etc/localtime /mnt/etc/

[ -d /root/.ssh ] && cp -a /root/.ssh /mnt/root/
[ -d /etc/ssh -a -d /mnt/etc/ssh ] && cp -a /etc/ssh/*_key /etc/ssh/*_key.pub /mnt/etc/ssh/

chroot /mnt systemctl enable systemd-networkd systemd-resolved
echo 'virtiofs' >> /mnt/etc/initramfs-tools/modules
PATH=$PATH:/usr/sbin chroot /mnt /usr/sbin/update-initramfs -u

umount /mnt
reboot
