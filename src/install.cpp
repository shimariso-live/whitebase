
#include <pty.h>
#include <glob.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>

#include <iostream>
#include <fstream>

#include <libmount/libmount.h>
#include <blkid/blkid.h>

#include <argparse/argparse.hpp>

#include "disk.h"
#include "install.h"
#include "messages.h"
#include "common.h"

static const std::filesystem::path run_initramfs_boot("/run/initramfs/boot");
static const std::filesystem::path system_img = run_initramfs_boot / "system.img";

static void exec_command(const std::string& cmd, const std::vector<std::string>& args)
{
    if (geteuid() != 0) { // just print command if not root
        std::cout << cmd;
        for (auto arg : args) {
            std::cout << " '" << arg << "'";
        }
        std::cout << std::endl;
        return;
    }
    //else
    pid_t pid = fork();
    if (pid < 0) std::runtime_error("fork");
    //else
    if (pid == 0) { //child
        char* argv[args.size() + 2];
        int i = 0;
        argv[i++] = strdup(cmd.c_str());
        for (auto arg : args) {
            argv[i++] = strdup(arg.c_str());
        }
        argv[i] = NULL;
        if (execvp(cmd.c_str(), argv) < 0) _exit(-1);
    }
    // else {
    int status;
    waitpid(pid, &status, 0);
    if (status != 0) throw std::runtime_error(cmd);
}

static int glob(const char* pattern, int flags, int errfunc(const char *epath, int eerrno), std::list<std::filesystem::path>& match)
{
  glob_t globbuf;
  match.clear();
  int rst = glob(pattern, GLOB_NOESCAPE, NULL, &globbuf);
  if (rst == GLOB_NOMATCH) return 0;
  if (rst != 0) throw std::runtime_error("glob");
  //else
  for (int i = 0; i < globbuf.gl_pathc; i++) {
    match.push_back(std::filesystem::path(globbuf.gl_pathv[i]));
  }
  globfree(&globbuf);
  return match.size();
}

static std::optional<std::filesystem::path> get_partition(const std::filesystem::path& disk, uint8_t num)
{
  if (!std::filesystem::is_block_file(disk)) throw std::runtime_error("Not a block device");

  struct stat s;
  if (stat(disk.c_str(), &s) < 0) throw std::runtime_error("stat");

  char pattern[128];
  sprintf(pattern, "/sys/dev/block/%d:%d/*/partition",
    major(s.st_rdev), minor(s.st_rdev));

  std::list<std::filesystem::path> match;
  glob(pattern, GLOB_NOESCAPE, NULL, match);
  for (auto& path: match) {
    std::ifstream part(path);
    uint16_t partno;
    part >> partno;
    if (partno == num) {
      std::ifstream dev(path.replace_filename("dev"));
      std::string devno;
      dev >> devno;
      std::filesystem::path devblock("/dev/block/");
      auto devspecial = std::filesystem::read_symlink(devblock.replace_filename(devno));
      return devspecial.is_absolute()? devspecial : std::filesystem::canonical(devblock.replace_filename(devspecial));
    }
  }
  return std::nullopt;
}

template <typename T> T with_tempmount(const std::filesystem::path& device, const char* fstype, int flags, const char* data,
    std::function<T(const std::filesystem::path&)> func)
{
    struct libmnt_context *ctx = mnt_new_context();
    if (!ctx) throw std::runtime_error("mnt_new_context");
    // else

    auto path = std::filesystem::temp_directory_path() /= std::string("mount-") + std::to_string(getpid());
    std::filesystem::create_directory(path);
    mnt_context_set_fstype_pattern(ctx, fstype);
    mnt_context_set_source(ctx, device.c_str());
    mnt_context_set_target(ctx, path.c_str());
    mnt_context_set_mflags(ctx, flags);
    mnt_context_set_options(ctx, data);
    auto rst = mnt_context_mount(ctx);
    auto status1 = mnt_context_get_status(ctx);
    auto status2 = mnt_context_get_helper_status(ctx);
    mnt_free_context(ctx);
    if (rst > 1) throw std::runtime_error("mnt_context_mount");
    if (rst != 0) throw std::runtime_error("mnt_context_mount");
    //else
    if (status1 != 1) throw std::runtime_error("mnt_context_get_status");
    if (status2 != 0) throw std::runtime_error("mnt_context_get_helper_status");
    //else
    try {
        auto rst = func(path);
        umount(path.c_str());
        std::filesystem::remove(path);
        return rst;
    }
    catch (...) {
        umount(path.c_str());
        std::filesystem::remove(path);
        throw;
    }
}

static std::optional<std::string> get_partition_uuid(const std::filesystem::path& partition)
{
  blkid_cache cache;
  if (blkid_get_cache(&cache, "/dev/null") != 0) return std::nullopt;
  // else
  std::optional<std::string> rst = std::nullopt;
  if (blkid_probe_all(cache) == 0) {
    auto tag_value = blkid_get_tag_value(cache, "UUID", partition.c_str());
    if (tag_value) rst = tag_value;
  }
  blkid_put_cache(cache);
  return rst;
}

int grub_mkimage(const std::filesystem::path& boot_partition_dir)
{
    auto efi_boot = boot_partition_dir / "efi/boot";
    std::filesystem::create_directories(efi_boot);
    // install EFI bootloader
    return call({"grub-mkimage", "-p", "/boot/grub", "-o", (efi_boot / "bootx64.efi").string(), "-O", "x86_64-efi", 
        "xfs","btrfs","fat","part_gpt","part_msdos","normal","linux","echo","all_video","test","multiboot","multiboot2","search","sleep","iso9660","gzio",
        "lvm","chain","configfile","cpuid","minicmd","gfxterm_background","png","font","terminal","squash4","serial","loopback","videoinfo","videotest",
        "blocklist","probe","efi_gop","efi_uga"/*, "keystatus"*/});
}

int grub_install(const std::filesystem::path& boot_partition_dir, const std::filesystem::path& disk)
{
    return call({"grub-install", "--target=i386-pc", "--recheck", std::string("--boot-directory=") + (boot_partition_dir / "boot").string(),
        "--modules=xfs btrfs fat part_msdos normal linux linux16 echo all_video test multiboot multiboot2 search sleep gzio lvm chain configfile cpuid minicmd font terminal serial squash4 loopback videoinfo videotest blocklist probe gfxterm_background png keystatus",
        disk.string()});
}

bool install_bootloader(const std::filesystem::path& disk, const std::filesystem::path& boot_partition_dir, bool bios_compatible = true)
{
    if (grub_mkimage(boot_partition_dir) != 0) return false;
    //else
    if (bios_compatible) {
        // install BIOS bootloader
        if (grub_install(boot_partition_dir, disk) != 0) return false;
    }
    // create boot config file
    auto grub_dir = boot_partition_dir / "boot/grub";
    std::filesystem::create_directories(grub_dir);
    {
        std::ofstream grubcfg(grub_dir / "grub.cfg");
        if (grubcfg) {
            grubcfg << "insmod echo\ninsmod linux\ninsmod cpuid\n"
                << "set BOOT_PARTITION=$root\n"
                << "loopback loop /system.img\n"
                << "set root=loop\nset prefix=($root)/boot/grub\nnormal"
                << std::endl;
        } else {
            std::cout << "Writing grub.cfg failed." << std::endl;
            return false;
        }
    }
    return true;
}

bool do_install(const std::filesystem::path& disk, uint64_t size, uint16_t log_sec, const std::map<std::string,std::string>& grub_vars/*={}*/, 
    std::stop_token st/* = std::stop_token()*/, std::function<void(double)> progress/* = [](double){}*/)
{
    std::cout << MSG("Stopping LVM") << std::endl;
    exec_command("vgchange", {"-an"});

    progress(0.01);
    if (st.stop_requested()) return false;

    std::vector<std::string> parted_args = {"--script", disk.string()};
    bool bios_compatible = (size <= 2199023255552L/*2TiB*/ && log_sec == 512);
    parted_args.push_back(bios_compatible? "mklabel msdos" : "mklabel gpt");
    bool has_secondary_partition = size >= 9000000000L; // more than 8GiB

    if (has_secondary_partition) {
        parted_args.push_back("mkpart primary fat32 1MiB 8GiB");
        parted_args.push_back("mkpart primary btrfs 8GiB -1");
    } else {
        std::cout << MSG("Warning: Data area won't be created due to too small disk") << std::endl;
        parted_args.push_back("mkpart primary fat32 1MiB -1");
    }
    parted_args.push_back("set 1 boot on");
    if (bios_compatible) {
        parted_args.push_back("set 1 esp on");
    }

    std::cout << MSG("Creating partitions...");
    std::flush(std::cout);
    exec_command("parted", parted_args);
    exec_command("udevadm", {"settle"});
    std::cout << MSG("Done") << std::endl;

    progress(0.03);
    if (st.stop_requested()) return false;

    auto _boot_partition = get_partition(disk, 1);
    if (!_boot_partition) {
        std::cerr << MSG("Error: Unable to determine boot partition") << std::endl;
        throw std::runtime_error("No boot partition");
    }
    //else
    auto boot_partition = _boot_partition.value();

    std::cout << MSG("Formatting boot partition with FAT32") << std::endl;
    exec_command("mkfs.vfat",{"-F","32",boot_partition});

    progress(0.05);
    if (st.stop_requested()) return false;

    std::cout << MSG("Mouning boot partition...");
    std::flush(std::cout);
    bool done = with_tempmount<bool>(boot_partition, "vfat", MS_RELATIME, "fmask=177,dmask=077", [&disk,&grub_vars,bios_compatible,&st,&progress](auto mnt) {
        std::cout << MSG("Done") << std::endl;

        progress(0.07);
        if (st.stop_requested()) return false;

        std::cout << MSG("Installing UEFI bootloader") << std::endl;
        grub_mkimage(mnt);
        if (bios_compatible) {
            std::cout << MSG("Installing BIOS bootloader") << std::endl;
            grub_install(mnt, disk);
        } else {
            std::cout << MSG("This system will be UEFI-only as this disk cannot be treated by BIOS") << std::endl;
        }

        progress(0.09);
        if (st.stop_requested()) return false;

        auto grub_dir = mnt / "boot/grub";
        std::filesystem::create_directories(grub_dir);
        std::cout << MSG("Creating boot configuration file") << std::endl;
        {
            std::ofstream grubcfg(grub_dir / "grub.cfg");
            if (grubcfg.fail()) throw std::runtime_error("ofstream('/boot/grub/grub.cfg')");
            grubcfg << "insmod echo\ninsmod linux\ninsmod cpuid\n"
                << "set BOOT_PARTITION=$root\n"
                << "loopback loop /system.img\n"
                << "set root=loop\nset prefix=($root)/boot/grub\nnormal"
                << std::endl;
        }
        if (grub_vars.size() > 0) {
            std::ofstream systemcfg(mnt / "system.cfg");
            if (systemcfg.fail()) throw std::runtime_error("ofstream('/system.cfg')");
            for (const auto& [k,v] : grub_vars) {
                systemcfg << "set " << k << '=' << v << std::endl;
            }
        }

        progress(0.10);
        if (st.stop_requested()) return false;

        std::cout << MSG("Copying system file") << std::endl;
        char buf[1024 * 1024]; // 1MB buffer
        FILE* f1 = fopen(system_img.c_str(), "r");
        if (!f1) throw std::runtime_error("Unable to open system file");
        //else
        struct stat statbuf;
        if (fstat(fileno(f1), &statbuf) < 0 || statbuf.st_size == 0) {
            fclose(f1);
            throw std::runtime_error("Unable to stat system file");
        }
        FILE* f2 = fopen((mnt / "system.img").c_str(), "w");
        size_t r;
        size_t cnt = 0;
        uint8_t percentage = 0;
        bool done = true;
        do {
            if (st.stop_requested()) {
                done = false;
                break;
            }
            r = fread(buf, 1, sizeof(buf), f1);
            fwrite(buf, 1, r, f2);
            fflush(f2);
            fdatasync(fileno(f2));
            cnt += r;
            std::flush(std::cout);
            uint8_t new_percentage = cnt * 100 / statbuf.st_size;
            if (new_percentage > percentage) {
                percentage = new_percentage;
                std::cout << '\r' << MSG("Copying...") << (int)percentage << "%";
                std::flush(std::cout);
            }
            progress((double)cnt / statbuf.st_size * 0.8 + 0.1);
        } while (r == sizeof(buf));
        std::cout << std::endl;
        fclose(f1);
        fclose(f2);
        std::cout << MSG("Unmounting boot partition...");
        std::flush(std::cout);
        return done;
    });
    std::cout << MSG("Done") << std::endl;
    if (!done) return false;
    //else

    progress(0.90);
    if (st.stop_requested()) return false;

    if (has_secondary_partition) {
        std::cout << MSG("Constructing data area") << std::endl;
        auto secondary_partition = get_partition(disk, 2);
        if (secondary_partition) {
            auto boot_partition_uuid = get_partition_uuid(boot_partition);
            if (boot_partition_uuid) {
                auto label = std::string("data-") + boot_partition_uuid.value();
                auto partition_name = secondary_partition.value();
                std::cout << MSG("Formatting partition for data area with BTRFS...");
                std::flush(std::cout);
                exec_command("mkfs.btrfs", {"-q", "-L", label, "-f", partition_name.string()});
                std::cout << MSG("Done") << std::endl;
            } else {
                std::cout << MSG("Warning: Unable to get UUID of boot partition. Data area won't be created") << std::endl;
            }
        } else {
            std::cout << MSG("Warning: Unable to determine partition for data area. Data area won't be created") << std::endl;
        }
    }
    progress(1.00);

    return true;
}

int install_cmdline(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program(args[0]);
    program.add_argument("device_path").help("Path of disk device");
    program.add_argument("--text-mode").help("Make text mode as default").default_value(false).implicit_value(true);
    program.add_argument("--installer").help("Create installer").default_value(false).implicit_value(true);

    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }

    auto device_path = program.get<std::string>("device_path");
    auto text_mode = program.get<bool>("--text-mode");
    auto installer = program.get<bool>("--installer");

    std::map<std::string,std::string> grub_vars;
    if (text_mode) grub_vars["default"] = "text";
    if (installer) grub_vars["systemd_unit"] = "installer.target";

    try {
        auto disk = get_unused_disk(device_path);
        do_install(device_path, disk.size, disk.log_sec.value(), grub_vars);
    }
    catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}

int create_install_media(const std::filesystem::path& disk_path)
{
    auto disk = get_unused_disk(disk_path, 1024L * 1024 * 1024 * 3/*3GB*/);

    if (disk.size > 2199023255552L/*2TiB*/) throw std::runtime_error("Disk is too large for FAT32.");
    if (!std::filesystem::exists(system_img)) throw std::runtime_error("System image file does not exist.");

    std::vector<std::string> parted_args = {"parted", "--script", disk_path.string()};
    bool bios_compatible = (disk.log_sec == 512);
    parted_args.push_back(bios_compatible? "mklabel msdos" : "mklabel gpt");
    parted_args.push_back("mkpart primary fat32 1MiB -1");
    parted_args.push_back("set 1 boot on");
    if (bios_compatible) parted_args.push_back("set 1 esp on");
    check_call(parted_args);
    call({"udevadm", "settle"});
    auto boot_partition_path = get_partition(disk_path, 1);
    if (!boot_partition_path) throw std::runtime_error("Unable to determine created boot partition");
    check_call({"mkfs.vfat", "-F", "32", "-n", "WBINSTALL", boot_partition_path.value()});

    return with_tempmount<int>(boot_partition_path.value(), "vfat", MS_RELATIME, "fmask=177,dmask=077", [&disk_path,&boot_partition_path,bios_compatible](const std::filesystem::path& mnt) {
        std::filesystem::copy(system_img, mnt / "system.img");
        std::ofstream f(mnt / "system.cfg");
        if (!f) throw std::runtime_error("system.cfg cannot be opened");
        f << "set systemd_unit=\"installer.target\"" << std::endl;

        return install_bootloader(disk_path, mnt, bios_compatible);
    });
}

static int _main(int,char*[])
{
    return install_cmdline({"install", "--text-mode", "/dev/null"});
}

#ifdef __MAIN_MODULE__
int main(int argc, char* argv[]) { return _main(argc, argv); }
#endif

