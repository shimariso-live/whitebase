#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>

#include <iostream>
#include <filesystem>
#include <functional>
#include <set>
#include <ext/stdio_filebuf.h> // for __gnu_cxx::stdio_filebuf

#include "common.h"
#include "disk.h"
#include "yajl_value.h"

static Blockdevice obj2blockdevice(yajl_val _d)
{
    Blockdevice device;

    auto d = get<std::map<std::string,yajl_val>>(_d);

    device.name = get<std::string>(d.at("name"));
    device.pkname = get<std::optional<std::string>>(d.at("pkname"));
    device.type = get<std::string>(d.at("type"));
    device.model = get<std::optional<std::string>>(d.at("model"));
    device.ro = get<bool>(d.at("ro"));
    device.size = get<uint64_t>(d.at("size"));
    device.tran = get<std::optional<std::string>>(d.at("tran"));
    device.log_sec = get<std::optional<uint16_t>>(d.at("log-sec"));
    device.mountpoint = get<std::optional<std::string>>(d.at("mountpoint"));

    std::string maj_min = get<std::string>(d.at("maj:min"));
    auto colon = maj_min.find(':');
    if (colon == std::string::npos) std::runtime_error("Invalid maj:min string");
    //else
    device.maj_min = {
        std::stoi(maj_min.substr(0,colon)), 
        std::stoi(maj_min.substr(colon + 1))
    };

    return device;
}

static bool for_each_blockdevice(std::function<bool(const Blockdevice&)> func)
{
    auto [pid, in] = forkinput([]() {
        return exec({"lsblk", "-b", "-n", "-l", "-J", "-o", "NAME,MODEL,TYPE,PKNAME,RO,MOUNTPOINT,SIZE,TRAN,LOG-SEC,MAJ:MIN"});
    });

    std::stringstream buf;
    {
        __gnu_cxx::stdio_filebuf<char> filebuf(in, std::ios::in);
        std::istream f(&filebuf);
        buf << f.rdbuf();
    }

    char errorbuf[1024];
    std::shared_ptr<yajl_val_s> tree(yajl_tree_parse(buf.str().c_str(), errorbuf, sizeof(errorbuf)), yajl_tree_free);
    if (!tree) throw std::runtime_error(std::string("yajl_tree_parse() failed: ") + errorbuf);

    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) throw std::runtime_error("lsblk exited abnoarmally");

    for (auto val : get<std::vector<yajl_val>>(get(tree.get(), "blockdevices"))) {
        if (!func(obj2blockdevice(val))) return false;
    }
    return true;
};

std::vector<Disk> get_unused_disks(uint64_t least_size/* = 1024L * 1024 * 1024 * 4*/)
{
    std::map<std::string,Disk> disk_map;
    std::set<std::string> to_be_removed;
    for_each_blockdevice([&disk_map,&to_be_removed,least_size](auto device) {
        if (device.mountpoint) {
            if (device.pkname) to_be_removed.insert(device.pkname.value());
        } else if (device.type == "disk" && device.size >= least_size && device.log_sec) {
            disk_map[device.name] = device;
        }
        return true;
    });

    std::vector<Disk> disks;
    for (const auto& item : disk_map) {
        if (!to_be_removed.contains(item.first)) disks.push_back(item.second);
    }
    return disks;
}

Disk get_unused_disk(const std::filesystem::path& device_path, uint64_t least_size/* = 1024L * 1024 * 1024 * 4*/)
{
    if (!std::filesystem::exists(device_path)) throw std::runtime_error(device_path.string() + " does not exist.");
    if (!std::filesystem::is_block_file(device_path)) throw std::runtime_error(device_path.string() + " is not a block device.");
    //else
    struct stat st;
    if (stat(device_path.c_str(), &st) < 0) throw std::runtime_error("stat");

    std::optional<Blockdevice> disk_found;
    std::set<std::string> disks_have_mounted_partition;
    std::pair<int,int> maj_min = {major(st.st_rdev), minor(st.st_rdev)};
    for_each_blockdevice([&maj_min,&disk_found,&disks_have_mounted_partition](auto device) {
        if (device.mountpoint) {
            if (device.pkname) disks_have_mounted_partition.insert(device.pkname.value());
        } else if (device.maj_min == maj_min && device.type == "disk") {
            disk_found = device;
        }
        return true;
    });

    if (!disk_found) throw std::runtime_error(device_path.string() + " is not a disk.");
    //else
    const auto disk = disk_found.value();
    if (disk.size < least_size) throw std::runtime_error(device_path.string() + " has no sufficient capacity.");
    //else
    if (!disk.log_sec) throw std::runtime_error(std::string("Cannot determine logical block size of ") + device_path.string() + ".");
    //else
    if (disks_have_mounted_partition.contains(disk.name)) {
        throw std::runtime_error(device_path.string() + " has mounted partition.");
    }

    return disk;
}

static int _main(int,char*[])
{
    auto disks = get_unused_disks(0);
    for (const auto& disk : disks) {
        std::cout << disk.name << " maj=" << disk.maj_min.first << ", min=" << disk.maj_min.second << std::endl;
    }

    auto disk = get_unused_disk("/dev/nvme0n1", 1024L * 1024 * 1024 * 4);
    std::cout << disk.name << " maj=" << disk.maj_min.first << ", min=" << disk.maj_min.second << std::endl;
    return 0;
}

#ifdef __MAIN_MODULE__
int main(int argc, char* argv[]) { return _main(argc, argv); }
#endif
