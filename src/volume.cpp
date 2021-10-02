#include <sys/statvfs.h>

#include <filesystem>
#include <fstream>

#include <libmount/libmount.h>
#include <blkid/blkid.h>
#include <libsmartcols/libsmartcols.h>

#include <argparse/argparse.hpp>

#include "common.h"
#include "volume.h"

const static std::filesystem::path vm_root("/var/vm");

static std::optional<std::pair<std::filesystem::path,std::string/*fstype*/>> get_source_device_from_mountpoint(const std::filesystem::path& path)
{
    if (!std::filesystem::exists(path) || !std::filesystem::is_directory(path)) return std::nullopt;
    // else
    std::shared_ptr<libmnt_table> tb(mnt_new_table_from_file("/proc/self/mountinfo"),mnt_unref_table);
    std::shared_ptr<libmnt_cache> cache(mnt_new_cache(), mnt_unref_cache);
    mnt_table_set_cache(tb.get(), cache.get());

    int rst = -1;
    libmnt_fs* fs = mnt_table_find_target(tb.get(), path.c_str(), MNT_ITER_BACKWARD);
    return fs? std::optional(std::make_pair(mnt_fs_get_srcpath(fs), mnt_fs_get_fstype(fs))) : std::nullopt;
}

static std::optional<std::string> get_partition_uuid(const std::filesystem::path& partition)
{
  blkid_cache cache;
  if (blkid_get_cache(&cache, "/dev/null") != 0) throw std::runtime_error("blkid_get_cache() failed");
  // else
  std::optional<std::string> rst = std::nullopt;
  if (blkid_probe_all(cache) == 0) {
    auto tag_value = blkid_get_tag_value(cache, "UUID", partition.c_str());
    if (tag_value) rst = tag_value;
  }
  blkid_put_cache(cache);
  return rst;
}

static int mount(const std::string& source,
  const std::filesystem::path& mountpoint,
  const std::string& fstype = "auto", unsigned int mountflags = MS_RELATIME,
  const std::string& data = "")
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

static int add(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program("volume " + args[0]);
    program.add_argument("name").help("Volume name");
    program.add_argument("device").help("Device to add");

    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }

    auto name = program.get<std::string>("name");
    auto device = program.get<std::string>("device");

    if (name == "default") throw std::runtime_error("Default volume cannot be modified");

    if (!std::filesystem::exists(device) || !std::filesystem::is_block_file(device)) {
        throw std::runtime_error(device + " does not exist(or is not a block device)");
    }
    auto uuid = get_partition_uuid(device).value_or("");
    if (uuid == "") throw std::runtime_error(device + " has no UUID(not formatted?)");

    auto volume_path = vm_root / ("@" + name);

    if (get_source_device_from_mountpoint(volume_path)) {
        throw std::runtime_error(name + " has already been mounted");
    }

    auto uuid_file = volume_path / ".uuid";
    if (std::filesystem::exists(uuid_file)) {
        throw std::runtime_error(name + " has already been associated to a partition");
    }

    std::filesystem::create_directories(volume_path);

    auto subvolume_file = volume_path / ".subvolume";

    if (std::filesystem::exists(subvolume_file)) {
        std::filesystem::remove(subvolume_file);
    }

    {
        std::ofstream f(uuid_file);
        if (!f) throw std::runtime_error("Failed to open " + uuid_file.string());
        f << uuid;
        if (f.bad()) throw std::runtime_error("Failed writing to " + uuid_file.string());
        f.close();
        if (f.fail()) throw std::runtime_error("Failed to close " + uuid_file.string());
    }

    if (mount(std::string("UUID=") + uuid, volume_path) != 0) {
        std::filesystem::remove_all(volume_path);
        throw std::runtime_error("Failed to mount UUID=" + uuid + " on " + volume_path.string());
    }

    return 0;

}

static int remove(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program("volume " + args[0]);
    program.add_argument("name").help("Volume name");

    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }

    auto name = program.get<std::string>("name");

    if (name == "default") throw std::runtime_error("Default volume cannot be modified");

    auto volume_path = vm_root / ("@" + name);

    if (!std::filesystem::exists(volume_path)) {
        throw std::runtime_error("Volume " + name + " does not exist");
    }
    if (get_source_device_from_mountpoint(volume_path)) {
        auto rst = umount(volume_path.c_str());
        if (rst < 0) {
            throw std::runtime_error("Unable to unmount " + volume_path.string());
        }
    }
    std::filesystem::remove_all(volume_path);

    return 0;
}

static int scan(const std::vector<std::string>& args)
{
    for (const auto& dir : std::filesystem::directory_iterator(vm_root)) {
        if (!dir.is_directory()) continue;
        const auto& path = dir.path();
        auto name =  path.filename().string();
        if (name[0] != '@') continue;
        name.replace(name.begin(), name.begin() + 1, "");
        if (name == "default") continue;

        if (get_source_device_from_mountpoint(path)) continue; // already mounted

        auto uuid_file = path / ".uuid";
        if (!std::filesystem::exists(uuid_file) || !std::filesystem::is_regular_file(uuid_file)) continue;

        std::string uuid;
        {
            std::ifstream f(uuid_file);
            if (!f) continue;
            f >> uuid;
        }

        if (mount(std::string("UUID=") + uuid, path) == 0) {
            std::cout << "Volume " + name + "(UUID=" + uuid + ") mounted on " + path.string() << std::endl;
        } else {
            std::cerr << "Volume " + name + "(UUID=" + uuid + ") couldn't be mounted." << std::endl;
        }
    }
    return 0;
}

std::map<std::string,Volume> get_volume_list()
{
    std::map<std::string,Volume> volumes;
    for (const auto& dir : std::filesystem::directory_iterator(vm_root)) {
        if (!dir.is_directory()) continue;
        const auto& path = dir.path();
        auto name =  path.filename().string();
        if (name[0] != '@') continue;
        name.replace(name.begin(), name.begin() + 1, "");

        Volume vol;

        auto device = get_source_device_from_mountpoint(path);
        auto uuid_file = path / ".uuid";
        if (!device && !std::filesystem::exists(uuid_file)) continue;

        if (device) {
            vol.online = true;
            vol.path = path;
            vol.device_or_uuid = device.value().first.c_str();
            vol.fstype = device.value().second.c_str();

            struct statvfs vfs;
            if (statvfs(path.c_str(), &vfs) == 0) {
                uint64_t blocksize = vfs.f_frsize? vfs.f_frsize : vfs.f_bsize; // https://github.com/coreutils/gnulib/blob/master/lib/fsusage.c#L124
                vol.size = blocksize * vfs.f_blocks;
                vol.free = blocksize * vfs.f_bfree;
            }
        } else {
            std::ifstream f(uuid_file);
            if (!f) continue;
            f >> vol.device_or_uuid;
        }
        volumes[name] = vol;
    }
    return volumes;
}

static int list(const std::vector<std::string>& args)
{
    auto volumes = get_volume_list();
    std::shared_ptr<libscols_table> table(scols_new_table(), scols_unref_table);
    if (!table) throw std::runtime_error("scols_new_table() failed");
    scols_table_new_column(table.get(), "ONLINE", 0.1, SCOLS_FL_RIGHT);
    scols_table_new_column(table.get(), "NAME", 0.1, 0);
    scols_table_new_column(table.get(), "PATH", 0.1, 0);
    scols_table_new_column(table.get(), "DEVICE | UUID", 0.1, 0);
    scols_table_new_column(table.get(), "FSTYPE", 0.1, 0);
    scols_table_new_column(table.get(), "SIZE", 0.1, SCOLS_FL_RIGHT);
    scols_table_new_column(table.get(), "FREE", 0.1, SCOLS_FL_RIGHT);
    auto sep = scols_table_new_line(table.get(), NULL);
    scols_line_set_data(sep, 0, "------");
    scols_line_set_data(sep, 1, "--------");
    scols_line_set_data(sep, 2, "----------------");
    scols_line_set_data(sep, 3, "------------------------------------");
    scols_line_set_data(sep, 4, "------");
    scols_line_set_data(sep, 5, "-------");
    scols_line_set_data(sep, 6, "-------");

    for (const auto& i : volumes) {
        auto line = scols_table_new_line(table.get(), NULL);
        if (i.second.online) scols_line_set_data(line, 0, "*");
        scols_line_set_data(line, 1, i.first.c_str());
        scols_line_set_data(line, 2, i.second.path.c_str());
        scols_line_set_data(line, 3, i.second.device_or_uuid.c_str());
        if (i.second.fstype) scols_line_set_data(line, 4, i.second.fstype.value().c_str());
        if (i.second.size) scols_line_set_data(line, 5, human_readable(i.second.size.value()).c_str());
        if (i.second.free) scols_line_set_data(line, 6, human_readable(i.second.free.value()).c_str());
    }

    scols_print_table(table.get());
    return 0;
}

int volume(const std::vector<std::string>& _args)
{
    if (_args.size() < 2) {
        std::cerr << "Action(add|remove|scan|list) required" << std::endl;
        return -1;
    }
    
    std::vector<std::string> args(_args.begin() + 1, _args.end());
    const std::string& action = args[0];

    if (action == "add") {
        return add(args);
    } else if (action == "remove") {
        return remove(args);
    } else if (action == "scan") {
        return scan(args);
    } else if (action == "list") {
        return list(args);
    }

    // else
    std::cerr << ("Unknown action " + action) << std::endl;
    return -1;
}

std::optional<std::filesystem::path> get_volume_dir(const std::string& volume_name)
{
    auto volume_dir = vm_root / ("@" + volume_name);
    return get_source_device_from_mountpoint(volume_dir)? std::make_optional(volume_dir) : std::nullopt;
}

std::filesystem::path get_volume_dir(const std::string& volume_name, std::function<std::filesystem::path(const std::string&)> noexists)
{
    auto volume_dir = get_volume_dir(volume_name);
    return volume_dir? volume_dir.value() : noexists(volume_name);
}

static int _main(int argc,char* argv[])
{
    std::vector<std::string> args;

    for (int i = 0; i < argc; i++) {
        args.push_back(argv[i]);
    }

    return volume(args);
}

#ifdef __MAIN_MODULE__
int main(int argc, char* argv[]) { return _main(argc, argv); }
#endif
