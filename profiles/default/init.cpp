#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <iostream>
#include <fstream>
#include <regex>
#include <set>
#include <ext/stdio_filebuf.h> // for __gnu_cxx::stdio_filebuf

#include <libmount/libmount.h>
#include <blkid/blkid.h>

//#define PARAVIRT

#include "init.h"

int init::lib::exec(const std::string& cmd, const std::vector<std::string>& args, 
  const std::filesystem::path& rootdir/* = "/"*/,
  const std::variant<std::monostate,std::function<void(std::istream&)>,std::function<void(std::ostream&)>>& data/* = {}*/)
{
  int fd[2];
  if (std::holds_alternative<std::function<void(std::istream&)>>(data) || std::holds_alternative<std::function<void(std::ostream&)>>(data)) {
    if (pipe(fd) < 0) RUNTIME_ERROR_WITH_ERRNO("pipe");
  }

  pid_t pid = fork();
  if (pid < 0) RUNTIME_ERROR_WITH_ERRNO("fork");
  //else
  int rst;
  if (pid == 0) { //child
    if (rootdir != "/") {
      if (chroot(rootdir.c_str()) < 0) _exit(-1);
    }
    if (std::holds_alternative<std::function<void(std::istream&)>>(data)) {
      close(fd[0]);
      dup2(fd[1], STDOUT_FILENO);
    } else if (std::holds_alternative<std::function<void(std::ostream&)>>(data)) {
      close(fd[1]);
      dup2(fd[0], STDIN_FILENO);
    }
    // create argv
    size_t args_len = 0;
    args_len += cmd.length() + 1;
    for (auto arg:args) {
      args_len += arg.length() + 1;
    }
    char* argv_buf = (char*)malloc(args_len);
    char* argv[args.size() + 2];
    char* pt = argv_buf;
    int argc = 0;
    strcpy(pt, cmd.c_str());
    pt[cmd.length()] = '\0';
    argv[argc++] = pt;
    pt += cmd.length() + 1;
    for (auto arg:args) {
      strcpy(pt, arg.c_str());
      pt[arg.length()] = '\0';
      argv[argc++] = pt;
      pt += arg.length() + 1;
    }
    argv[argc] = NULL;
    auto rst = execv(cmd.c_str(), argv);
    free(argv_buf);
    if (rst < 0) _exit(-1);
  } else { // parent
    if (std::holds_alternative<std::function<void(std::istream&)>>(data)) {
      close(fd[1]);
      {
        __gnu_cxx::stdio_filebuf<char> filebuf(fd[0], std::ios::in);
        std::istream f(&filebuf);
        std::get<std::function<void(std::istream&)>>(data)(f);
      }
      close(fd[0]);
    } else if (std::holds_alternative<std::function<void(std::ostream&)>>(data)) {
      close(fd[0]);
      {
        __gnu_cxx::stdio_filebuf<char> filebuf(fd[1], std::ios::out);
        std::ostream f(&filebuf);
        std::get<std::function<void(std::ostream&)>>(data)(f);
      }
      close(fd[1]);
    }
    waitpid(pid, &rst, 0);
  }
  return WIFEXITED(rst)? WEXITSTATUS(rst) : -1;
}

int init::lib::move_mount(const std::filesystem::path& old, const std::filesystem::path& _new)
{
  return mount(old.c_str(), _new.c_str(), NULL, MS_MOVE, NULL);
}

int init::lib::umount_recursive(const std::filesystem::path& path)
{
  return exec(init::progs::UMOUNT, { "-R", "-n", path.string() });
}

static int unlink(const std::filesystem::path& path)
{
  return unlink(path.c_str());
}

bool init::lib::is_file(const std::filesystem::path& path)
{
  return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

bool init::lib::is_dir(const std::filesystem::path& path)
{
  return std::filesystem::exists(path) && std::filesystem::is_directory(path);
}

bool init::lib::is_block(const std::filesystem::path& path)
{
  return std::filesystem::exists(path) && std::filesystem::is_block_file(path);
}

std::optional<std::pair<std::filesystem::path,std::string/*fstype*/>> init::lib::get_source_device_from_mountpoint(const std::filesystem::path& path)
{
  if (!is_dir(path)) return std::nullopt;
  // else
  std::shared_ptr<libmnt_table> tb(mnt_new_table_from_file("/proc/self/mountinfo"),mnt_unref_table);
  std::shared_ptr<libmnt_cache> cache(mnt_new_cache(), mnt_unref_cache);
  mnt_table_set_cache(tb.get(), cache.get());

  int rst = -1;
  libmnt_fs* fs = mnt_table_find_target(tb.get(), path.c_str(), MNT_ITER_BACKWARD);
  return fs? std::optional(std::make_pair(mnt_fs_get_srcpath(fs), mnt_fs_get_fstype(fs))) : std::nullopt;
}

static int rename(const std::filesystem::path& old, const std::filesystem::path& _new)
{
  return ::rename(old.c_str(), _new.c_str());
}

int init::lib::mount(const std::filesystem::path& source,
  const std::filesystem::path& mountpoint,
  const std::string& fstype/* = "auto"*/, unsigned int mountflags/* = MS_RELATIME*/,
  const std::string& data/* = ""*/)
{
  std::shared_ptr<libmnt_context> ctx(mnt_new_context(), mnt_free_context);
  mnt_context_set_fstype_pattern(ctx.get(), fstype.c_str());
  mnt_context_set_source(ctx.get(), source.c_str());
  mnt_context_set_target(ctx.get(), mountpoint.c_str());
  mnt_context_set_mflags(ctx.get(), mountflags);
  mnt_context_set_options(ctx.get(), data.c_str());

  int rst = mnt_context_mount(ctx.get());
  if (rst != 0) {
    if (rst > 1) perror("mnt_context_mount");
    return rst;
  }
  //else
  return mnt_context_get_status(ctx.get()) == 1? 0 : -1;
}

int init::lib::bind_mount(std::filesystem::path source, std::filesystem::path mountpoint)
{
  return mount(source, mountpoint, "none", MS_BIND);
}

int init::lib::mount_loop(std::filesystem::path source, std::filesystem::path mountpoint,
  const std::string& fstype/* = "auto"*/, unsigned int mountflags/* = MS_RELATIME*/,
  const std::string& data/* = ""*/, int offset/* = 0*/)
{
  auto data_loop = data == "" ? std::string("") : data + ",";
  data_loop += "loop,offset=";
  data_loop += std::to_string(offset);
  return mount(source, mountpoint, fstype, mountflags, data_loop);
}

bool init::lib::is_mounted(const std::filesystem::path& path)
{
  return get_source_device_from_mountpoint(path) != std::nullopt;
}

std::optional<std::tuple<std::filesystem::path,std::optional<std::string/*uuid*/>,std::optional<std::string/*fstype*/>>> 
  init::lib::search_partition(const std::string& name, const std::string& value)
{
  class BlkidDevIterate {
    blkid_dev_iterate iter;
    blkid_cache cache;
  public:
    BlkidDevIterate() {
      blkid_get_cache(&cache, "/dev/null");
      blkid_probe_all(cache);
      iter = blkid_dev_iterate_begin(cache);
    }
    ~BlkidDevIterate() {
      blkid_dev_iterate_end(iter);
      blkid_put_cache(cache);
    }
    operator blkid_dev_iterate() { return iter; }
    blkid_dev verify(blkid_dev dev) { return blkid_verify(cache, dev); }
  };

  class BlkIdTagIterate {
    blkid_tag_iterate iter;
  public:
    BlkIdTagIterate(blkid_dev dev) {
      iter = blkid_tag_iterate_begin(dev);
    }
    ~BlkIdTagIterate() {
      blkid_tag_iterate_end(iter);
    }
    operator blkid_tag_iterate() { return iter; }
  };

  BlkidDevIterate iter;
  blkid_dev_set_search(iter, name.c_str(), value.c_str());
  blkid_dev dev = NULL;
  while (blkid_dev_next(iter, &dev) == 0) {
    dev = iter.verify(dev);
    if (dev) break;
  }
  if (!dev) return std::nullopt;
  //else
  BlkIdTagIterate tag_iter(dev);
  const char *_type, *_value;
  const char * fstype = NULL;
  const char * uuid = NULL;
  while (blkid_tag_next(tag_iter, &_type, &_value) == 0) {
    if (strcmp(_type,"TYPE") == 0) {
      fstype = _value;
    } else if (strcmp(_type, "UUID") == 0) {
      uuid = _value;
    }
  }
  return std::make_tuple(blkid_dev_devname(dev), uuid? std::optional(uuid) : std::nullopt, fstype? std::optional(fstype) : std::nullopt);
}

std::optional<std::tuple<std::filesystem::path,std::optional<std::string/*uuid*/>,std::optional<std::string/*fstype*/>>>
  init::lib::get_partition_by_uuid(const std::string& uuid, int max_retry/* = 3*/)
{
  for (int i = 0; i <= max_retry; i++) {
    if (i > 0) sleep(i);
    auto boot_partition = search_partition("UUID", uuid);
    if (boot_partition) return boot_partition;
  }

  return std::nullopt;
}

std::map<std::filesystem::path,std::tuple<std::optional<std::string>/*uuid*/,std::optional<std::string>/*fstype*/>> init::lib::get_all_partitions()
{
  blkid_cache cache;
  if (blkid_get_cache(&cache, "/dev/null") < 0) throw std::runtime_error("blkid_get_cache(/dev/null) failed");

  std::map<std::filesystem::path,std::tuple<std::optional<std::string>/*uuid*/,std::optional<std::string>/*fstype*/>> partitions;
  try {
    if (blkid_probe_all(cache) < 0) throw std::runtime_error("blkid_probe_all() failed");

    blkid_dev_iterate dev_iter = blkid_dev_iterate_begin(cache);
    if (!dev_iter) throw std::runtime_error("blkid_dev_iterate_begin() failed");
    try {
      blkid_dev dev = NULL;
      while (blkid_dev_next(dev_iter, &dev) == 0) {
        dev = blkid_verify(cache, dev);
        if (dev) {
          blkid_tag_iterate tag_iter = blkid_tag_iterate_begin(dev);
          if (!tag_iter) throw std::runtime_error("blkid_tag_iterate_begin() failed");
          try {
            const char *_type, *_value;
            const char * uuid = NULL;
            const char * fstype = NULL;
            while (blkid_tag_next(tag_iter, &_type, &_value) == 0) {
              if (strcmp(_type,"TYPE") == 0) {
                fstype = _value;
              } else if (strcmp(_type, "UUID") == 0) {
                uuid = _value;
              }              
            }
            partitions[blkid_dev_devname(dev)] = std::make_tuple(uuid? std::optional(uuid) : std::nullopt, fstype? std::optional(fstype) : std::nullopt);
          }
          catch (...) {
            blkid_tag_iterate_end(tag_iter);
            throw;
          }
          blkid_tag_iterate_end(tag_iter);
        }
      }
    }
    catch (...) {
      blkid_dev_iterate_end(dev_iter);
      throw;
    }
    blkid_dev_iterate_end(dev_iter);
  }
  catch (...) {
    blkid_put_cache(cache);
    throw;
  }
  blkid_put_cache(cache);
  return partitions;
}

bool init::lib::is_block_readonly(const std::filesystem::path& path)
{
  if (!std::filesystem::is_block_file(path)) {
    RUNTIME_ERROR(path.string() + " is not a block device");
  }
  //else
  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0) RUNTIME_ERROR_WITH_ERRNO("open");
  //else
  int readonly;
  if (ioctl(fd, BLKROGET, &readonly) < 0) RUNTIME_ERROR_WITH_ERRNO("ioctl");
  // else
  if (!readonly) {
    // check if squashfs
    uint8_t buf[4];
    if (read(fd, buf, sizeof(buf)) < 0) RUNTIME_ERROR_WITH_ERRNO("read");
    //else
    if (buf[0] == 0x68 && buf[1] == 0x73 && buf[2] == 0x71 && buf[3] == 0x73) readonly = 1; // it's squashfs
  }
  close(fd);
  return (bool)readonly;
}

std::optional<std::filesystem::path> init::lib::devname_to_sysfs_path(const std::filesystem::path& blockdevice)
{
  struct stat st;
	if (stat(blockdevice.c_str(), &st) < 0) return std::nullopt;
  auto dev = st.st_rdev;

  std::filesystem::path sys_dev_block("/sys/dev/block");
  auto dev_path = sys_dev_block / (std::to_string(major(dev)) + ":" + std::to_string(minor(dev)));
  return init::lib::is_dir(dev_path)? std::make_optional(dev_path) : std::nullopt;
}

bool init::lib::is_removable(const std::filesystem::path& blockdevice)
{
  auto sysfs_path = devname_to_sysfs_path(blockdevice);
  if (!sysfs_path) return false;
  std::filesystem::path removable = sysfs_path.value() / "removable";
  if (!init::lib::is_file(removable)) return false;
  std::ifstream f(removable);
  if (!f) return false;
  std::string tf;
  f >> tf;
  return tf == "1";
}

static bool preserve_previous_system_image(const std::filesystem::path& boot)
{
  auto previous_image = boot / "system.cur";
  if (init::lib::is_file(previous_image)) {
    if (::rename(previous_image, boot / "system.old") == 0) {
      printf("Previous system image preserved.\n");
      sync();
      return true;
    }
  }
  return false;
}

static auto get_data_partition(const std::string& boot_partition_uuid)
{
    auto data_partition = init::lib::search_partition("LABEL", std::string("data-") + boot_partition_uuid);
    if (!data_partition) data_partition = init::lib::search_partition("LABEL", std::string("wbdata-") + boot_partition_uuid); // for compatibility
    return data_partition;
}

int init::lib::cp_a(const std::filesystem::path& src, const std::filesystem::path& dst)
{
  return exec(init::progs::CP, {"-a", src.string(), dst.string()});
}

uint64_t init::lib::get_free_disk_space(const std::filesystem::path& mountpoint)
{
  struct statvfs s;
  if (statvfs(mountpoint.c_str(), &s) < 0) RUNTIME_ERROR_WITH_ERRNO("statvfs");
  //else
  return (uint64_t)s.f_bsize * s.f_bfree;
}

static void setup_proc_dev_sys()
{
  std::filesystem::create_directory("/proc");
  if (init::lib::mount("proc", "/proc", "proc", MS_NOEXEC|MS_NOSUID|MS_NODEV) != 0) RUNTIME_ERROR("mount /proc");
  std::filesystem::create_directory("/dev");
  if (init::lib::mount("udev", "/dev", "devtmpfs", MS_NOSUID, "mode=0755,size=10M") != 0) RUNTIME_ERROR("mount /dev");
  std::filesystem::create_directory("/sys");
  if (init::lib::mount("sysfs", "/sys", "sysfs", MS_NOEXEC|MS_NOSUID|MS_NODEV) != 0) RUNTIME_ERROR("mount /sys");
}

const std::vector<std::string>& init::lib::kernel_cmdline()
{
  static std::vector<std::string> kernel_cmdline;
  static bool loaded = false;

  if (!loaded) {
    std::ifstream cmdline("/proc/cmdline");
    if (!cmdline) RUNTIME_ERROR("/proc/cmdline not found");
    while (!cmdline.eof()) {
      std::string arg;
      cmdline >> arg;
      kernel_cmdline.push_back(arg);
    }
    loaded = true;
  }

  return kernel_cmdline;
}

static std::filesystem::path setup_newroot(
  const std::filesystem::path& mnt_system, const std::filesystem::path& mnt_boot, const std::filesystem::path& mnt_rw,
  const std::optional<std::filesystem::path>& mnt_swap = std::nullopt)
{
  auto mnt_rw_root = init::lib::is_dir(mnt_rw / "rw")? (mnt_rw / "rw")/*compatibility*/ : (mnt_rw / "root");
  auto mnt_rw_work = mnt_rw / "work";
  std::filesystem::create_directories(mnt_rw_root);
  std::filesystem::create_directories(mnt_rw_work);

  std::filesystem::path newroot("/newroot");
  std::filesystem::create_directory(newroot);

  std::stringstream buf;
  buf << "lowerdir=" << mnt_system.c_str()
    << ",upperdir=" << mnt_rw_root.c_str()
    << ",workdir=" << mnt_rw_work.c_str();
  std::cout << "Mounting overlayfs(" << buf.str() << ") on " << newroot << "..." << std::flush;
  if (init::lib::mount("overlay", newroot, "overlay", MS_RELATIME, buf.str().c_str()) != 0) {
    RUNTIME_ERROR("mount -t overlay");
  }
  //else
  std::cout << "done." << std::endl;

  auto newroot_run = newroot / "run";
  std::filesystem::create_directory(newroot_run);
  if (init::lib::mount("tmpfs", newroot_run, "tmpfs", MS_NODEV|MS_NOSUID|MS_STRICTATIME, "mode=755") != 0) {
    RUNTIME_ERROR("mount tmpfs on NEWROOT/run");
  }
  //else
  auto move_mount = [](const std::filesystem::path& old, const std::filesystem::path& _new) {
    std::filesystem::create_directories(_new);
    if (init::lib::move_mount(old, _new) != 0) {
      RUNTIME_ERROR(std::string("move_mount from ") + old.string() + " to " + _new.string());
    }
  };
  std::cout << "Moving mountpoints..." << std::flush;
  auto initramfs = newroot_run / "initramfs";
  move_mount(mnt_boot, initramfs / "boot");
  move_mount(mnt_system, initramfs / "ro");
  move_mount(mnt_rw, initramfs / "rw");
  if (mnt_swap && init::lib::is_mounted(mnt_swap.value())) {
    move_mount(mnt_swap.value(), initramfs / "swap");
  }
  std::cout << "done." << std::endl;

  std::cout << "Setting up shutdown environment..." << std::flush;
  for (auto path:{"bin", "usr/bin", "lib", "usr/lib", "lib64", "usr/lib64", "usr/sbin"}) {
    auto src = std::filesystem::path("/") / path / ".";
    auto dst = initramfs / path;
    if (init::lib::is_dir(src)) {
      std::filesystem::create_directories(dst);
      init::lib::cp_a(src, dst);
    }
  }

  init::lib::cp_a("/init", initramfs / "shutdown");
  std::cout << "done." << std::endl;

  // invalidate ld.so.cache
  auto ld_so_cache = newroot / "etc/ld.so.cache";
  if (init::lib::is_file(ld_so_cache)) {
    unlink(ld_so_cache);
    std::cout << "/etc/ld.so.cache removed" << std::endl; 
  }

  return newroot;
}

static std::string generate_default_hostname()
{
  FILE *f;
  uint16_t randomnumber;
  f = fopen("/dev/urandom", "r");
  if (!f) return std::string("host-XXXX");
  //else
  fread(&randomnumber, sizeof(randomnumber), 1, f);
  fclose(f);
  char hostname[16];
  sprintf(hostname, "host-%04x", randomnumber);
  return hostname;
}

std::optional<std::string> init::lib::set_hostname(const std::filesystem::path& rootdir, const std::optional<std::string>& hostname/* = std::nullopt*/)
{
  std::ofstream f(rootdir / "etc/hostname");
  if (!f) return std::nullopt;
  //else

  auto hostname_to_set = hostname? hostname.value() : generate_default_hostname();

  f << hostname_to_set;
  return hostname_to_set;
}

bool init::lib::set_root_password(const std::filesystem::path& rootdir, const std::string& password)
{
  if (password == "") { // remove password
    return exec("/usr/bin/passwd", {"-d", "root"}, rootdir) == 0;
  }
  // else
  return exec("/usr/sbin/chpasswd", {}, rootdir, [&password](std::ostream& o) {
    o << "root:" << password << std::flush;
  }) == 0;
}

bool init::lib::set_timezone(const std::filesystem::path& rootdir, const std::string& timezone)
{
  std::filesystem::path zoneinfo("../usr/share/zoneinfo");
  std::filesystem::path link(rootdir / "etc/localtime");
  unlink(link.c_str());
  return symlink((zoneinfo / timezone).c_str(), link.c_str()) == 0;
}

bool init::lib::set_locale(const std::filesystem::path& rootdir, const std::string& locale)
{
  std::ofstream f(rootdir / "etc/locale.conf");
  if (!f) return false;
  //else
  f << locale;
  return true;
}

bool init::lib::set_keymap(const std::filesystem::path& rootdir,  const std::string& keymap)
{
  std::ofstream f(rootdir / "etc/vconsole.conf");
  if (!f) return false;
  //else
  f << keymap;
  return true;
}

bool init::lib::set_wifi_config(const std::filesystem::path& rootdir, const std::string& ssid, const std::string& key)
{
  {
    std::ofstream conf(rootdir / "etc/wpa_supplicant/wpa_supplicant-wlan0.conf");
    if (!conf) return false;
    // else
    conf << "network={\n";
    conf << "\tssid=\"" << ssid << "\"\n";
    conf << "\tpsk=\"" << key << "\"\n";
    conf << "}" << std::endl;
  }
  return exec("/bin/systemctl", {"enable", "wpa_supplicant@wlan0"}, rootdir) == 0;
}

bool init::lib::set_network_config(const std::filesystem::path& rootdir,
  const std::optional<std::string>& network_interface,
  const std::optional<std::tuple<std::string/*address*/,std::optional<std::string>/*gateway*/,std::optional<std::string>/*dns*/,std::optional<std::string>/*fallback_dns*/>>& ipv4/* = std::nullopt*/, 
  const std::optional<std::tuple<std::string/*address*/,std::optional<std::string>/*gateway*/,std::optional<std::string>/*dns*/,std::optional<std::string>/*fallback_dns*/>>& ipv6/* = std::nullopt*/)
{
  auto network_config_dir = rootdir / "etc/systemd/network";
  std::filesystem::remove_all(network_config_dir);
  std::filesystem::create_directories(network_config_dir);

  std::ofstream f(network_config_dir / "50-generated-config.network");
  if (!f) return false;
  // else
  f << (std::string("[Match]\nName=") + (network_interface.value_or("eth* en* wl*")) + "\n[Network]") << std::endl;

  if (ipv4) {
    auto address = std::get<0>(ipv4.value());
    if (address != "none") {
      f << "Address=" << address << std::endl;
      auto gateway = std::get<1>(ipv4.value());
      if (gateway) f << "Gateway=" << gateway.value() << std::endl;
      auto dns = std::get<2>(ipv4.value());
      if (dns) {
        f << "DNS=" << dns.value() << std::endl;
        auto fallback_dns = std::get<3>(ipv4.value());
        if (fallback_dns)  f << "FallbackDNS=" << fallback_dns.value() << std::endl;
      } else if (gateway) { // assume reachable to public dns if gateway is there
        f << "DNS=8.8.8.8\nFallbackDNS=8.8.4.4" << std::endl;
      }
    } else {
      f << "DHCP=ipv6" << std::endl;
    }
  } else {
    f << "DHCP=yes" << std::endl;
  }

  if (ipv6) {
    f << "Address=" << std::get<0>(ipv6.value()) << std::endl;
    auto gateway = std::get<1>(ipv6.value());
    if (gateway) f << "Gateway=" << gateway.value() << std::endl;
    auto dns = std::get<2>(ipv6.value());
    if (dns) {
      f << "DNS=" << dns.value() << std::endl;
      auto fallback_dns = std::get<3>(ipv6.value());
      if (fallback_dns) f << "FallbackDNS=" << fallback_dns.value() << std::endl;
    } else if (gateway) { // assume reachable to public dns if gateway is there
      f << "DNS=2001:4860:4860::8888\nFallbackDNS=2001:4860:4860::8844" << std::endl;
    }
  }

  f << "MulticastDNS=yes\nLLMNR=yes" << std::endl;
  return true;
}

bool init::lib::set_ssh_key(const std::filesystem::path& rootdir,  const std::string& ssh_key)
{
  std::regex re( R"(^(.+?\s.+?)(\s.*|$))");
  std::smatch m;
  if (!std::regex_search(ssh_key, m, re)) return false;
  std::string ssh_key_essential = m.str(1);
  auto ssh_dir = rootdir / "root/.ssh";
  std::filesystem::create_directories(ssh_dir);
  auto authorized_keys = ssh_dir / "authorized_keys";
  {
    std::ifstream f(authorized_keys);
    for( std::string line; std::getline( f, line ); ) {
      if (!std::regex_search(line, m, re)) continue;
      //else
      if (m.str(1) == ssh_key_essential) return true/*already there*/;
    }
  }

  std::ofstream f(authorized_keys, std::fstream::app);
  f << ssh_key << std::endl;

  return true;
}

__attribute__((weak)) void init::hooks::print_banner() 
{
  std::cout << "Starting genpack universal initramfs..." << std::endl;
}

__attribute__((weak)) void init::hooks::setup_data_subvolumes(const std::filesystem::path& mnt_path) {}

__attribute__((weak)) void init::hooks::post_init(const std::filesystem::path& newroot, 
  std::optional<std::tuple<std::filesystem::path,std::optional<std::string/*uuid*/>,std::optional<std::string/*fstype*/>>>,
  inifile_t inifile) {}

static void ls(const std::filesystem::path& dir)
{
  for (const std::filesystem::directory_entry& x : std::filesystem::directory_iterator(dir)) {
    std::cout << x.path() << ' ';
  }
  std::cout << std::endl;
}

#ifdef PARAVIRT
__attribute__((weak)) void init::hooks::setup_hostname(const std::filesystem::path& newroot, inifile_t inifile)
{
  unsigned int len;
  char* domname = (char*)xs_read(inifile.first, inifile.second, "name", &len);
  if (domname) {
    std::string hostname(domname, len);
    init::lib::set_hostname(newroot, hostname);
    free(domname);
  } else {
    auto hostname = init::lib::set_hostname(newroot);
    if (hostname) {
      std::cout << "hostname: " << hostname.value() << std::endl;
    } else {
      std::cout << "Hostname setup failed." << std::endl;
    }
  }
}

static std::filesystem::path do_init(bool transient)
{
  init::hooks::print_banner();

  // mount boot partition
  auto partitions = init::lib::get_all_partitions();
  auto boot_partition = std::find_if(partitions.begin(), partitions.end(), [](const auto& i) {
    return (i.first == "/dev/vda" || i.first == "dev/xvda1") && std::get<1>(i.second) != "swap";
  });
  if (boot_partition == partitions.end()) RUNTIME_ERROR("Neither /dev/vda or /dev/xvda1 found");
  auto readonly_boot_partition = init::lib::is_block_readonly(boot_partition->first);

  std::filesystem::path mnt("/mnt");
  auto mnt_boot = mnt / "boot";
  std::filesystem::create_directories(mnt_boot);
  if (init::lib::mount(boot_partition->first, mnt_boot, "auto", readonly_boot_partition? MS_RDONLY : MS_RELATIME) != 0) {
    RUNTIME_ERROR("mount /mnt/boot");
  }
  //else
  std::cout << "Boot partition mounted." << std::endl;

  // mount RO layer
  auto mnt_system = mnt / "system";
  std::filesystem::create_directory(mnt_system);
  if (readonly_boot_partition) {
    if (init::lib::bind_mount(mnt_boot, mnt_system) != 0) RUNTIME_ERROR("mount --bind /mnt/boot /mnt/system");
  } else {
    if (init::lib::mount_loop(mnt_boot / "system.img", mnt_system, "auto", MS_RDONLY) != 0) {
      if (init::lib::mount_loop(mnt_boot / "system", mnt_system, "auto", MS_RDONLY) != 0) {
        RUNTIME_ERROR("mount /mnt/system");
      }
    }
    preserve_previous_system_image(mnt_boot);
  }
  std::cout << "RO Layer mouned." << std::endl;

  // mount RW layer
  auto mnt_rw = mnt / "rw";
  std::filesystem::create_directory(mnt_rw);

  auto rw_partition = std::find_if(partitions.begin(), partitions.end(), [](const auto& i) {
    return (i.first == "/dev/vdb" || i.first == "dev/xvda2") && std::get<1>(i.second) != "swap";
  });

  if (!transient) {
    if (readonly_boot_partition) {
      if (rw_partition != partitions.end()) {
        // data partition
        if (init::lib::mount(rw_partition->first, mnt_rw) != 0) RUNTIME_ERROR("mount /mnt/rw");
      } else {
        // virtiofs
        if (init::lib::mount("fs", mnt_rw, "virtiofs") != 0) RUNTIME_ERROR("mount /mnt/rw via virtiofs");
      }
    } else {
      if (init::lib::bind_mount(mnt_boot, mnt_rw) != 0) RUNTIME_ERROR("mount --bind /mnt/boot /mnt/rw");
    }
    std::cout << "RW Layer mounted." << std::endl;

    // activate swap
    auto swap_partition = std::find_if(partitions.begin(), partitions.end(), [](const auto& i) {
      return std::get<1>(i.second) == "swap";
    });

    if (swap_partition != partitions.end()) {
      init::lib::exec(init::progs::SWAPON, {swap_partition->first});
      std::cout << "Swap partition enabled." << std::endl;
    } else {
      auto swapfile = mnt_boot / "swapfile";
      if (init::lib::is_file(swapfile)) {
        if (init::lib::exec(init::progs::SWAPON, {swapfile.string()}) == 0) {
          std::cout << "Swap file enabled." << std::endl;
        } else {
          if (init::lib::exec(init::progs::MKSWAP, {swapfile.string()}) == 0) {
            if (init::lib::exec(init::progs::SWAPON, {swapfile.string()}) == 0) {
              std::cout << "Swap file initialized and activated." << std::endl;
            }
          }
        }
      }
    }
  } // !transient

  if (!init::lib::is_mounted(mnt_rw)) {
    std::cout << "Using tmpfs as upper layer..." << std::endl;
    if (init::lib::mount("tmpfs", mnt_rw, "tmpfs") != 0) RUNTIME_ERROR("mount rw");
  }

  auto newroot = setup_newroot(mnt_system, mnt_boot, mnt_rw);

  // apply config
  std::shared_ptr<xs_handle> xs(xs_open(XS_OPEN_READONLY), xs_close);
  if (xs) {
    xs_transaction_t txn = xs_transaction_start(xs.get());
    if (txn) {
      auto inifile = std::make_pair(xs.get(), txn);
      init::hooks::setup_hostname(newroot, inifile);
      init::hooks::post_init(newroot, std::nullopt, inifile);
      xs_transaction_end(xs.get(), txn, true);
    } else {
      std::cout << "Failed to open xenstore transaction." << std::endl;
    }
  } else {
    std::cout << "xs_open failed. config wouldn't be applied properly." << std::endl;
  }

  // get hostname from kernel arg
  auto cmdline = init::lib::kernel_cmdline();
  auto i = std::find_if(cmdline.begin() , cmdline.end(), [](const auto& arg) { return arg.starts_with("hostname="); });
  if (i != cmdline.end()) {
    init::lib::set_hostname(newroot, i->substr(9));
  }

  const auto docker = newroot / "var/lib/docker";
  if (init::lib::is_dir(docker) && std::filesystem::is_empty(docker)) {
    const auto data_docker = newroot / "run/initramfs/rw/docker";
    std::filesystem::create_directories(data_docker);
    if (init::lib::bind_mount(data_docker, docker) == 0) {
      std::cout << "Docker data directory mounted." << std::endl;
    }
  }
  const auto mysql = newroot / "var/lib/mysql";
  if (init::lib::is_dir(mysql)) {
    const auto data_mysql = newroot / "run/initramfs/rw/mysql";
    std::filesystem::create_directories(data_mysql);
    if (std::filesystem::is_empty(data_mysql)) {
      std::cout << "Setting up MySQL data directory..." << std::flush;
      if (init::lib::cp_a(mysql / ".", data_mysql) == 0) {
        std::cout << "Done." << std::endl;
      } else {
        std::cout << "Failed." << std::endl;
        std::filesystem::remove_all(data_mysql);
      }
    }
    if (init::lib::is_dir(data_mysql) && init::lib::bind_mount(data_mysql, mysql) == 0) {
      std::cout << "MySQL data directory mounted." << std::endl;
    }
  }

  return newroot;
}
#else

static bool create_btrfs_subvolume(const std::filesystem::path& path)
{
  return init::lib::exec(init::progs::BTRFS, {"subvolume", "create", path.string()}) == 0;
}

__attribute__((weak)) void init::hooks::setup_hostname(const std::filesystem::path& newroot, inifile_t inifile)
{
  auto hostname = iniparser_getstring(inifile, ":hostname", NULL);
  if (hostname) {
    if (init::lib::set_hostname(newroot, hostname)) {
      std::cout << "hostname: " << hostname << std::endl;
      return;
    } else {
      std::cout << "Hostname setup failed." << std::endl;
    }
    return;
  }
}

__attribute__((weak)) void init::hooks::setup_network(const std::filesystem::path& newroot, inifile_t inifile)
{
  auto ip_address = iniparser_getstring(inifile, ":ip_address", NULL);
  auto ipv6_address = iniparser_getstring(inifile, ":ipv6_address", NULL);
  if (!ip_address && !ipv6_address) return;
  //else

  std::optional<
    std::tuple<
      std::string/*address*/,
      std::optional<std::string>/*gateway*/,
      std::optional<std::string>/*dns*/,
      std::optional<std::string>/*fallback_dns*/>> ipv4 = std::nullopt, ipv6 = std::nullopt;

  auto optional = [](const char* value) { return value? std::make_optional(std::string(value)) : std::nullopt; };

  if (ip_address && strcasecmp(ip_address, "dhcp") != 0) {
    ipv4 = std::make_tuple(ip_address, 
      optional(iniparser_getstring(inifile, ":gateway", NULL)), 
      optional(iniparser_getstring(inifile, ":dns", NULL)), 
      optional(iniparser_getstring(inifile, ":fallback_dns", NULL))
    );
  }

  if (ipv6_address) {
    ipv6 = std::make_tuple(ipv6_address, 
      optional(iniparser_getstring(inifile, ":ipv6_gateway", NULL)), 
      optional(iniparser_getstring(inifile, ":ipv6_dns", NULL)), 
      optional(iniparser_getstring(inifile, ":ipv6_fallback_dns", NULL))
    );
  }

  auto network_interface = optional(iniparser_getstring(inifile, ":network_interface", NULL));

  if (init::lib::set_network_config(newroot, network_interface, ipv4, ipv6)) {
    if (ip_address) std::cout << "IP address set to " << ip_address << std::endl;
    if (ipv6_address) std::cout << "IPv6 address set to " << ipv6_address << std::endl;
  } else {
    std::cout << "Setting static IP address failed." << std::endl;
  }
}

__attribute__((weak)) void init::hooks::setup_password(const std::filesystem::path& newroot, inifile_t inifile)
{
  auto password = iniparser_getstring(inifile, ":password", NULL);
  if (!password) return;
  // else
  if (init::lib::set_root_password(newroot, password)) {
    std::cout << "Root password configured." << std::endl;
  } else {
    std::cout << "Failed to set root password." << std::endl;
  }
}

__attribute__((weak)) void init::hooks::setup_timezone(const std::filesystem::path& newroot, inifile_t inifile)
{
  auto timezone = iniparser_getstring(inifile, ":timezone", NULL);
  if (timezone) {
    if (init::lib::set_timezone(newroot, timezone)) {
      std::cout << "Timezone set to " << timezone << "." << std::endl;
    } else {
      std::cout << "Timezone could not be configured." << std::endl;
    }
  }
}

__attribute__((weak)) void init::hooks::setup_locale(const std::filesystem::path& newroot, inifile_t inifile)
{
  auto locale = iniparser_getstring(inifile, ":locale", NULL);
  if (locale) {
    if (init::lib::set_locale(newroot, locale)) {
      std::cout << "System locale set to " << locale << "." << std::endl;
    } else {
      std::cout << "System locale could not be configured." << std::endl;
    }
  }
}

__attribute__((weak)) void init::hooks::setup_keymap(const std::filesystem::path& newroot, inifile_t inifile)
{
  auto keymap = iniparser_getstring(inifile, ":keymap", NULL);
  if (keymap) {
    if (init::lib::set_keymap(newroot, keymap)) {
      std::cout << "Keymap set to " << keymap << "." << std::endl;
    } else {
      std::cout << "Keymap could not be configured." << std::endl;
    }
  }
}

__attribute__((weak)) void init::hooks::setup_ssh_key(const std::filesystem::path& newroot, inifile_t inifile)
{
  auto ssh_key = iniparser_getstring(inifile, ":ssh_key", NULL);
  if (ssh_key) {
    if (init::lib::set_ssh_key(newroot, ssh_key)) {
      std::cout << "SSH key added to authorized_keys(or already there)." << std::endl;
    } else {
      std::cout << "SSH key was not added." << std::endl;
    }
  }
}

__attribute__((weak)) void init::hooks::setup_wifi(const std::filesystem::path& newroot, inifile_t inifile)
{
  auto wifi_ssid = iniparser_getstring(inifile, ":wifi_ssid", NULL);
  auto wifi_key = iniparser_getstring(inifile, ":wifi_key", NULL);

  if (!wifi_ssid) return;
  //else
  if (wifi_key) {
    if (init::lib::set_wifi_config(newroot, wifi_ssid, wifi_key)) {
      init::lib::set_network_config(newroot); // Assume DHCP when WiFi is enabled
      std::cout << "WiFi SSID: " << wifi_ssid << std::endl;
    } else {
      std::cout << "WiFi setup failed." << std::endl;
    }
  } else {
    std::cout << "wifi_key is not set." << std::endl;
  }
}

__attribute__((weak)) void init::hooks::setup_autologin(const std::filesystem::path& newroot, inifile_t inifile)
{
  auto autologin = iniparser_getboolean(inifile, ":autologin", 0) != 0;
  auto service_dir = newroot / "etc/systemd/system/getty@tty1.service.d";
  auto conf_file = service_dir / "autologin-configured-by-initramfs.conf";
  if (autologin) {
    std::filesystem::create_directories(service_dir);
    std::ofstream f(conf_file);
    if (f) {
      f << "[Service]" << std::endl;
      f << "ExecStart=" << std::endl;
      f << "ExecStart=-/sbin/agetty --autologin root --noclear %I 38400 linux" << std::endl;
      std::cout << "Autologin enabled." << std::endl;
    } else {
      std::cout << "Configuring autologin failed." << std::endl;
    }
  } else {
    if (init::lib::is_file(conf_file)) {
      std::filesystem::remove(conf_file);
      std::cout << "Autologin disabled." << std::endl;
    }
  }
}

static std::optional<std::tuple<std::filesystem::path,std::optional<std::string/*uuid*/>,std::optional<std::string/*fstype*/>>>
  determine_boot_partition()
{
  const char *boot_partition_uuid = getenv("boot_partition_uuid");
  if (boot_partition_uuid) {
    auto boot_partition = init::lib::get_partition_by_uuid(boot_partition_uuid);
    if (boot_partition) return boot_partition;
    //else
    std::cout << "Failed to find boot partition by UUID=" << boot_partition_uuid << "." << std::endl;
  } else {
    std::cout << "boot_partition_uuid is not set" << std::endl;
  }

  // search fallback
  for (auto device:{"/dev/vda1", "/dev/sda1", "/dev/mmcblk0p1", "/dev/nvme0n1p1"}) {
    if (init::lib::is_block(device)) {
      std::cout << "Falling back to: " << device << std::endl;
      return std::make_tuple(device, std::nullopt, std::nullopt);
    }
  }

  // no any usable fallbacks
  return std::nullopt;
}

static std::filesystem::path do_init(bool transient)
{
  init::hooks::print_banner();

  std::cout << "Determining boot partition..." << std::flush;

  auto boot_partition = determine_boot_partition();
  if (!boot_partition) RUNTIME_ERROR("Unable to determine boot partition.");

  auto boot_partition_dev_path = std::get<0>(boot_partition.value());
  auto boot_partition_uuid = std::get<1>(boot_partition.value());
  auto boot_partition_fstype = std::get<2>(boot_partition.value());

  std::cout << boot_partition_dev_path << std::endl;

  auto readonly_boot_partition = init::lib::is_block_readonly(boot_partition_dev_path);

  std::filesystem::path mnt("/mnt");
  auto mnt_boot = mnt / "boot";

  std::filesystem::create_directories(mnt_boot);
  auto rst = 
    init::lib::mount(boot_partition_dev_path, mnt_boot, boot_partition_fstype? boot_partition_fstype.value() : "auto", 
    readonly_boot_partition? MS_RDONLY : MS_RELATIME, 
    boot_partition_fstype == "vfat" ? "iocharset=utf8,codepage=437,fmask=177,dmask=077" : "");
  if (rst != 0) {
    RUNTIME_ERROR("Mounting boot partition failed");
  }
  //else
  std::cout << "Boot partition mounted." << std::endl;

  if (!readonly_boot_partition) {
    {
      std::ofstream time_file(mnt_boot / init::TIME_FILE);
      time_file << time(NULL);
    }
    preserve_previous_system_image(mnt_boot);
  }

  auto ini_path = mnt_boot / "system.ini";
  std::shared_ptr<dictionary> inifile = init::lib::is_file(ini_path)? 
    std::shared_ptr<dictionary>(iniparser_load(ini_path.c_str()), iniparser_freedict)
    : std::shared_ptr<dictionary>(dictionary_new(0), iniparser_freedict);

  auto mnt_system = mnt / "system";
  std::filesystem::create_directory(mnt_system);
  if (init::lib::mount_loop(mnt_boot / "system.img", mnt_system, "auto", MS_RDONLY) != 0) RUNTIME_ERROR("mount system_image");
  //else
  std::cout << "RO Layer mouned." << std::endl;

  auto mnt_rw = mnt / "rw";
  std::filesystem::create_directory(mnt_rw);

  auto mnt_swap = mnt / "swap";
  auto data_partition = boot_partition_uuid? get_data_partition(boot_partition_uuid.value()) : std::nullopt;

  if (!transient) {
    auto datafile = mnt_boot / "system.dat";
    if (init::lib::is_file(datafile)) {
      std::cout << "Using system.dat as RW layer." << std::endl;
      if (init::lib::mount_loop(datafile, mnt_rw, "btrfs", MS_RELATIME, "compress=zstd") != 0) {
        std::cout << "Failed to mount RW layer. Attempting repair." << std::endl;
        init::lib::exec(init::progs::BTRFS, {"check", "--repair", "--force", datafile.string()});
        if (init::lib::mount_loop(datafile, mnt_rw, "btrfs", MS_RELATIME, "compress=zstd") != 0) {
          std::cout << "Failed to mount RW layer." << std::endl;
        }
      }
    } else if (boot_partition_dev_path == "/dev/vda1" && init::lib::is_block("/dev/vda2") && init::lib::mount("/dev/vda2", mnt_rw, "xfs") == 0) {
      // compatibility
      std::cout << " Using /dev/vda2 as RW layer." << std::endl;
    }

    if (data_partition) {
      auto mnt_data = mnt / "data";
      std::filesystem::create_directory(mnt_data);
      auto data_partition_dev_path = std::get<0>(data_partition.value());
      auto data_partition_fstype = std::get<2>(data_partition.value());
      //std::cout << data_partition_dev_path << " : " << data_partition_fstype.value_or("-") << std::endl;
      if (data_partition_fstype == "btrfs" && init::lib::mount(data_partition_dev_path, mnt_data, "btrfs") == 0) {
        std::cout << "Data partition " << data_partition_dev_path << " found." << std::endl;
        for (auto name:{"rw","docker","mysql","swap"}) {
          if (!std::filesystem::exists(mnt_data / name)) {
            if (!create_btrfs_subvolume(mnt_data / name)) {
              std::cout << "Failed to create subvolume " << name << " under data partition." << std::endl;
            }
          }
        }
        init::hooks::setup_data_subvolumes(mnt_data);
        umount(mnt_data.c_str());
      } else {
        std::cout << "Failed to mount data partition" << std::endl;
      }

      if (!init::lib::is_mounted(mnt_rw)) {
        if (init::lib::mount(data_partition_dev_path, mnt_rw, "btrfs", MS_RELATIME, "subvol=rw") != 0) {
          std::cout << "Mounting RW layer on btrfs subvolume failed." << std::endl;
        }
      }
      std::filesystem::create_directory(mnt_swap);
      if (init::lib::mount(data_partition_dev_path, mnt_swap, "btrfs", MS_RELATIME, "subvol=swap") == 0) {
        auto swapfile = mnt_swap / "swapfile";
        if (init::lib::is_file(swapfile) && init::lib::exec(init::progs::SWAPON, {swapfile.string()}) == 0) {
          std::cout << "Reusable swapfile found and enabled." << std::endl;
        } else {
          auto free_disk_space = init::lib::get_free_disk_space(mnt_swap);
          if (free_disk_space >= 2ULL * 1024 * 1024 * 1024) {
            uint64_t swap_size = 4ULL * 1024 * 1024 * 1024;
            while (swap_size * 2 > free_disk_space) { swap_size /= 2;}          
            std::cout << "Creating swapfile..." << std::flush;
            int fd = creat(swapfile.c_str(), S_IRUSR | S_IWUSR);
            if (fd >= 0) {
              init::lib::exec(init::progs::CHATTR, {"+C", swapfile.string()});
              int rst = fallocate(fd, 0, 0, swap_size);
              close(fd);
              if (rst == 0) {
                if (init::lib::exec(init::progs::MKSWAP, {swapfile.string()}) == 0) {
                  if (init::lib::exec(init::progs::SWAPON, {swapfile.string()}) == 0) {
                    std::cout << "done." << std::endl;
                  } else {
                    std::cout << "done but not enabled as swapon fail" << std::endl;
                  }
                } else {
                  std::cout << "failed(mkswap)." << std::endl;
                }
              } else {
                std::cout << "failed(ftruncate)." << std::endl;
              }
            } else {
              std::cout << "failed(creat)." << std::endl;
            }
          } else {
            std::cout << "Swapfile not created due to insufficient disk space." << std::endl;
          }
        }
      } else {
        std::cout << "Swap subvolume not mounted." << std::endl;
      }
    } else {// data_partition
      std::cout << "No data partition found. Proceeding without it." << std::endl;
    }
  } // !transient

  if (!init::lib::is_mounted(mnt_rw)) {
    std::cout << "Using tmpfs as upper layer..." << std::endl;
    if (init::lib::mount("tmpfs", mnt_rw, "tmpfs") != 0) RUNTIME_ERROR("mount rw");
  }

  std::cout << "RW Layer mounted." << std::endl;

  auto newroot = setup_newroot(mnt_system, mnt_boot, mnt_rw, 
    init::lib::is_mounted(mnt_swap)? std::make_optional(mnt_swap) : std::nullopt);

  try {
    init::hooks::setup_hostname(newroot, inifile.get());
    init::hooks::setup_wifi(newroot, inifile.get());
    init::hooks::setup_network(newroot, inifile.get());
    init::hooks::setup_password(newroot, inifile.get());
    init::hooks::setup_timezone(newroot, inifile.get());
    init::hooks::setup_locale(newroot, inifile.get());
    init::hooks::setup_keymap(newroot, inifile.get());
    init::hooks::setup_ssh_key(newroot, inifile.get());
    init::hooks::setup_autologin(newroot, inifile.get());

    #if 0
    setup_wireguard(newroot);
    setup_openvpn(newroot);
    setup_zabbix_agent(newroot);
    setup_zram_swap(newroot);
    #endif
  }
  catch (const std::exception& ex) {
    std::cout << "Exception occured during optional configuration. '" << ex.what() << "'." << std::endl;
  }

  if (!init::lib::is_file(newroot / "etc/hostname")) {
    // set generated hostname
    auto hostname = init::lib::set_hostname(newroot);
    if (hostname) {
      std::cout << "hostname(generated): " << hostname.value() << std::endl;
    } else {
      std::cout << "Failed to set hostname." << std::endl;
    }
  }
  
  if (data_partition) {
    auto data_partition_dev_path = std::get<0>(data_partition.value());

    const auto& docker = newroot / "var/lib/docker";
    if (init::lib::is_dir(docker) && std::filesystem::is_empty(docker) 
      && init::lib::mount(data_partition_dev_path, docker, "btrfs", MS_RELATIME, "subvol=docker") == 0) {
      std::cout << "Docker subvolume mounted." << std::endl;
    } else {
      std::cout << "Docker subvolume couldn't be mounted." << std::endl;
    }

    const auto& mysql = newroot / "var/lib/mysql";
    if (init::lib::is_dir(mysql)) {
      const auto& mnt_mysql = mnt / "mysql";
      std::filesystem::create_directories(mnt_mysql);
      if (init::lib::mount(data_partition_dev_path, mnt_mysql, "btrfs", MS_RELATIME, "subvol=mysql") == 0) {
        if (std::filesystem::is_empty(mnt_mysql)) {
          std::cout << "Setting up MySQL data subvolume..." << std::flush;
          if (init::lib::cp_a(mysql / ".", mnt_mysql) == 0) {
            std::cout << "Done." << std::endl;
          } else {
            std::cout << "Failed." << std::endl;
            umount(mnt_mysql.c_str());
          }
        }
      }
      if (init::lib::is_mounted(mnt_mysql) && init::lib::move_mount(mnt_mysql, mysql) == 0) {
        std::cout << "MySQL data subvolume is mounted." << std::endl;
      } else {
        std::cout << "MySQL data subvolume is not mounted." << std::endl;
        umount(mnt_mysql.c_str());
      }
    }
  }

  init::hooks::post_init(newroot, data_partition, inifile.get());

  return newroot;
}
#endif

__attribute__((weak)) void init::hooks::pre_shutdown(const std::optional<std::string>&) {}
__attribute__((weak)) void init::hooks::post_shutdown(const std::optional<std::string>&) {}

static void shutdown(const std::optional<std::string>& arg)
{
  init::hooks::pre_shutdown(arg);

  std::filesystem::path mnt("/mnt"), oldroot("/oldroot");
  auto oldroot_run = oldroot / "run";

  std::filesystem::create_directory(mnt);
  if (init::lib::move_mount(oldroot_run, mnt) != 0) return; // nothing further can be done
  std::cout << "Unmounting filesystems..." << std::flush;
  init::lib::umount_recursive(oldroot);
  auto mnt_initramfs = mnt / "initramfs";
  if (init::lib::umount_recursive(mnt_initramfs / "ro") != 0) std::cout << "Unmount failed: ro";
  if (init::lib::umount_recursive(mnt_initramfs / "rw") != 0) std::cout << "Unmount failed: rw";
  if (init::lib::is_mounted(mnt_initramfs / "swap")) {
    if (init::lib::umount_recursive(mnt_initramfs / "swap") != 0) std::cout << "Unmount failed: swap";
  }
  auto mnt_initramfs_boot = mnt_initramfs / "boot";
  auto time_file = mnt_initramfs_boot / init::TIME_FILE;
  if (init::lib::is_file(time_file)) {
    if (init::lib::mount("none", mnt_initramfs_boot, "auto", MS_RELATIME, "remount,rw") == 0) {
      unlink(time_file);
    }
  }
  auto boot_partition_dev_path = init::lib::get_source_device_from_mountpoint(mnt_initramfs_boot);
  if (init::lib::umount_recursive(mnt) != 0) std::cout << "Unmount failed: run" << std::endl;
  std::cout << "done." << std::endl;
#ifndef PARAVIRT
  // perform fsck if FAT
  if (boot_partition_dev_path && boot_partition_dev_path.value().second == "vfat") {
    init::lib::exec(init::progs::FSCK_FAT, {"-a", "-w", boot_partition_dev_path.value().first});
  }
  // eject if removable
  if (init::lib::is_file("/eject") && boot_partition_dev_path) {
    auto drive = boot_partition_dev_path.value().first;
    if (init::lib::is_removable(drive)) {
      init::lib::exec(init::progs::EJECT, {drive});
    }
  }
#endif // PARAVIRT

  init::hooks::post_shutdown(arg);

  if (arg == "poweroff") {
    reboot(RB_POWER_OFF);
  } else if (arg == "reboot") {
    reboot(RB_AUTOBOOT);
  } else {
    reboot(RB_HALT_SYSTEM);
  }
}

static const char* SWITCH_ROOT = "/sbin/switch_root";

static int print_files(const std::filesystem::path& me)
{
  std::set<std::filesystem::path> files;

  auto canonical_me = std::filesystem::canonical(me);
  auto insert_file = [&files,&canonical_me](const std::string& line) {
    if (canonical_me == line) {
      files.insert(line);
    } else {
      for (auto path = std::filesystem::path(line); path != "/" && path != ""; path = path.parent_path()) {
        files.insert(path);
      }
    }
  };

  std::vector<std::string> args = {"-l", canonical_me};
  for (auto prog:init::progs::ALL) {
    args.push_back(prog);
  }
  args.push_back(SWITCH_ROOT);

  init::lib::exec("/usr/bin/lddtree", args, "/", [&insert_file](std::istream& i) {
    std::string line;
    while (std::getline(i, line)) {
      insert_file(line);
    }
  });

  if (files.find("/usr/sbin/fsck.fat") != files.end()) {
    // fsck.fat needs some codepage modules
    if (init::lib::is_dir("/usr/lib64/gconv") && init::lib::is_file("/usr/lib64/gconv/gconv-modules.cache")) {
      insert_file("/usr/lib64/gconv/gconv-modules.cache");
      insert_file("/usr/lib64/gconv/IBM850.so");
    } else if (init::lib::is_dir("/usr/lib/gconv") && init::lib::is_file("/usr/lib/gconv/gconv-modules.cache")) {
      insert_file("/usr/lib/gconv/gconv-modules.cache");
      insert_file("/usr/lib/gconv/IBM850.so");
    }
  }

  char tempdir_rp[] = "/tmp/genpack-initramfs-XXXXXX";
  auto tempdir = std::shared_ptr<char>(mkdtemp(tempdir_rp), [](char* p) { 
    std::filesystem::remove_all(p);
  });
  if (!tempdir) {
    std::cerr << "Failed to create temporary directory." << std::endl;
    return 1;
  }
  std::filesystem::path tempdir_path(tempdir.get());

  for (auto file:files) {
    if (!std::filesystem::exists(file)) {
      std::cerr << "File " << file << " does not exist." << std::endl;
      return 1;
    }
    //else
    auto dst = tempdir_path / file.string().substr(1);
    if (std::filesystem::is_directory(file)) {
      std::filesystem::create_directory(dst);
    } else if (std::filesystem::is_regular_file(file)) {
      std::filesystem::copy_file(file, file == canonical_me? (tempdir_path / "init") : dst);
    } else {
      std::cerr << "Unknown file type: " << file << std::endl;
      return 1;
    }
  }

  if (std::filesystem::exists(tempdir_path / "init")) {
    std::filesystem::create_symlink("init", tempdir_path / "init-transient");
  }

  std::filesystem::current_path(tempdir_path);
  std::set<std::filesystem::path> files_to_archive;
  for (const auto& path : std::filesystem::recursive_directory_iterator(".")) {
    files_to_archive.insert(path);
  }

  return init::lib::exec("/bin/cpio", {"-H", "newc", "-o"}, "/", [&files_to_archive](std::ostream& o) {
    for (const auto& file:files_to_archive) {
      o << file.string() << std::endl;
    }
  });
}

int main(int argc, char* argv[])
{
  std::filesystem::path progname(argv[0]);
  if ((progname == "/init" || progname == "/init-transient") && getpid() == 1) {
    try {
      setup_proc_dev_sys();
      auto newroot = do_init(progname == "/init-transient");
      std::cout << "Switching to newroot..." << std::endl;
      if (execl(SWITCH_ROOT, SWITCH_ROOT, newroot.c_str(), "/sbin/init"/*TODO: respect init= kernel param*/, NULL) != 0)
        RUNTIME_ERROR("switch_root");
    }
    catch (const std::exception& e) {
      std::cout << e.what() << std::endl;
    }
    reboot(RB_HALT_SYSTEM);
  }
  //else
  if (progname == "/shutdown") {
    try {
      shutdown(argc > 1? std::optional(std::string(argv[1])) : std::nullopt);
    }
    catch (const std::exception& e) {
      std::cout << e.what() << std::endl;
    }
  }
  //else

  return print_files(progname);
}
