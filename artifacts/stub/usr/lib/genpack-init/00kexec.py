#!/usr/bin/python
import os,subprocess,glob,tempfile,logging

def decompress_kernel_if_necessary(kernel):
    kernel_bin = None
    with open(kernel, "rb") as f:
        kernel_bin = f.read()
        if kernel_bin[0:8] != b"MZ\x00\x00zimg" or kernel_bin[24:28] != b"gzip": return kernel
    #else
    gzip_offset = kernel_bin.find(b"\x1f\x8b\x08\x00\x00\x00\x00\x00")
    if gzip_offset < 0:
        logging.info("Gzip header not found in kernel %s" % kernel)
        return kernel
    #else
    logging.info("Decompressing compressed kernel %s..." % kernel)
    decompressed_kernel = tempfile.mktemp()
    with open(decompressed_kernel, "wb") as f:
        subprocess.Popen(["gunzip", "-c"], stdin=subprocess.PIPE, stdout=f).communicate(input=kernel_bin[gzip_offset:])

    return decompressed_kernel

def kexec_boot(root):
    if not os.path.isdir(root): return False

    fstype = None
    device = None
    with open("/proc/mounts") as f:
        for line in f:
            #if line[0] != '/': continue
            cols = line.split(' ', 3)
            if len(cols) < 3 or cols[1] != os.path.realpath(root): continue
            #else
            device = cols[0]
            fstype = cols[2]
            break

    if device is None or fstype is None: 
        logging.debug("Could not determine device/fstype")
        return False

    bootdir = os.path.join(root, "boot")
    kernel = None
    initramfs = None
    for candidate in ["kernel", "vmlinuz"]:
        path = os.path.join(root, candidate)
        if not os.path.exists(path): path = os.path.join(bootdir, candidate)
        if os.path.exists(path):
            kernel = path
            logging.info("Kernel found: %s" % kernel)
            break
    if kernel is not None:
        for candidate in ["initramfs", "initrd.img"]:
            path = os.path.join(root, candidate)
            if not os.path.exists(path): path = os.path.join(bootdir, candidate)
            if os.path.exists(path):
                initramfs = path
                logging.info("Initramfs found: %s" % initramfs)
                break
    if kernel is None:
        latest = 0
        for candidate in ["kernel-*", "vmlinuz-*"]:
            for e in glob.glob(os.path.join(bootdir, candidate)):
                if e.endswith(".old"): continue
                mtime = os.path.getmtime(e)
                if mtime < latest: continue
                kernel = e
                latest = mtime
                logging.info("Kernel found: %s" % kernel)
        if kernel is not None:
            initramfs = os.path.join(bootdir, "initramfs-") + os.path.basename(kernel).split('-', 1)[1] + ".img"
            if not os.path.isfile(initramfs): initramfs = os.path.join(bootdir, "initrd-") + os.path.basename(kernel).split('-', 1)[1] + ".img"
            if not os.path.isfile(initramfs): initramfs = None
            else: logging.info("Initramfs found: %s" % initramfs)

    if kernel is None:
        logging.info("Kernel not found")
        return False
    
    kernel = decompress_kernel_if_necessary(kernel)

    with open("/proc/cmdline") as f:
        cmdline = f.read()
    logging.debug("cmdline=%s" % cmdline)
    cmdline_args = cmdline.split()
    has_fstab = False
    fstab = os.path.join(root, "etc/fstab")
    if os.path.isfile(fstab):
        with open(fstab) as f:
            for line in f:
                cols = line.split('#', 1)[0].split(None, 2)
                if len(cols) < 2: continue
                if cols[1] == "/":
                    has_fstab = True
                    break
    logging.debug("root entry %s in fstab" % ("found" if has_fstab else "not found"))
    has_rw = False
    new_cmdline = ""
    for arg in cmdline_args:
        if arg.startswith("root=") or arg.startswith("rootfstype="): continue
        if not has_fstab and arg == "ro": continue
        if arg == "rw": has_rw = True
        if new_cmdline != "": new_cmdline += ' '
        new_cmdline += arg

    new_cmdline += " root=" + device + " rootfstype=" + fstype
    if not has_fstab and not has_rw: new_cmdline += " rw" # always mount root filesystem r/w when fstab is missing
    logging.debug("new cmdline=%s" % new_cmdline)

    kexec_cmdline = ["/usr/sbin/kexec", "-l", "--append=" + new_cmdline]
    if initramfs is not None: kexec_cmdline.append("--initrd=" + initramfs)
    kexec_cmdline.append(kernel)

    logging.debug("kexec cmdline", kexec_cmdline)
    return subprocess.call(kexec_cmdline) == 0

def configure(ini):
    kexec_success = False
    if subprocess.call(["/usr/bin/mount", "-o", "ro", "/dev/vdb", "/mnt"]) == 0:
        try:
            kexec_success = kexec_boot("/mnt")
        finally:
            subprocess.call(["/usr/bin/umount", "/mnt"])
    if not kexec_success and subprocess.call(["/usr/bin/mount", "-t", "virtiofs", "-o", "ro", "fs", "/mnt"]) == 0:
        try:
            kexec_success = kexec_boot("/mnt")
        finally:
            subprocess.call(["/usr/bin/umount", "/mnt"])
    if kexec_success: 
        logging.info("Booting with new root filesystem...")
        os.execl("/usr/sbin/kexec", "/usr/sbin/kexec", "-e")

if __name__ == "__main__":
    configure(None)
