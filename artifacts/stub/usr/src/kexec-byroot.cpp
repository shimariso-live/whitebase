#include <unistd.h>

#include <fstream>
#include <filesystem>

#include <libmount/libmount.h>

#include <argparse/argparse.hpp>

static std::vector<std::string> parse_cmdline(const std::string& cmdline)
{
	std::vector<std::string> cmdline_args;
	bool quoted = false;
	std::string arg;
	for (const char* pt = cmdline.c_str(); *pt; pt++) {
		if (!quoted && *pt == ' ') {
			if (arg != "") {
				cmdline_args.push_back(arg);
				arg = "";
			}
			continue;
		}
		//else
		if (*pt == '"') quoted = !quoted;
		arg += *pt;
	}
	if (arg != "") cmdline_args.push_back(arg);
	return cmdline_args;
}

static bool has_root_enry_in_fstab(const std::filesystem::path& rootdir)
{
	std::ifstream fstab(rootdir / "etc" / "fstab");
	if (!fstab) return false;
	//else
	while (!fstab.eof()) {
		std::string line;
		std::getline(fstab, line);
		auto poundpos = line.find_first_of('#');
		if (poundpos != line.npos) line.replace(poundpos, line.length(), "");
		std::istringstream iss(line);
		std::string device, path;
		iss >> device >> path;
		if (device != "" && path == "/") return true;
	}

	return false;
}

static int kexec_boot(const std::filesystem::path& rootdir, bool quiet)
{
	if (!std::filesystem::exists(rootdir) || !std::filesystem::is_directory(rootdir)) {
		throw std::runtime_error(rootdir.string() + " is not a directory");
	}
	//else

	std::string device, fstype;

	{
		std::shared_ptr<libmnt_table> tb(mnt_new_table_from_file("/proc/self/mountinfo"),mnt_unref_table);
		if (!tb) throw std::runtime_error("Cannot open /proc/self/mountinfo");
		std::shared_ptr<libmnt_cache> cache(mnt_new_cache(), mnt_unref_cache);
		mnt_table_set_cache(tb.get(), cache.get());
		libmnt_fs* fs = mnt_table_find_target(tb.get(), rootdir.c_str(), MNT_ITER_BACKWARD);
		if (!fs) throw std::runtime_error("No filesystem mounted on " + rootdir.string());
		//else

		device = mnt_fs_get_srcpath(fs);
		fstype = mnt_fs_get_fstype(fs);
	}

	if (device == "") throw std::runtime_error("Source device of " + rootdir.string() + " couldn't be determined.");
	if (fstype == "") throw std::runtime_error("Filesystem type of " + device + " couldn't be determined.");
	//else

	auto bootdir = rootdir / "boot";
	std::optional<std::filesystem::path> kernel = std::nullopt;
	std::optional<std::filesystem::path> initramfs = std::nullopt;

	for (const auto candidate:{"kernel", "vmlinuz"}) {
		if (std::filesystem::exists(bootdir / candidate)) {
			kernel = bootdir / candidate;
			break;
		}
	}

	if (kernel) {
		for (const auto candidate:{"initramfs", "initrd.img"}) {
			if (std::filesystem::exists(bootdir / candidate)) {
				initramfs = bootdir / candidate;
				break;
			}
		}
	}

	if (!kernel) {
		auto latest = std::filesystem::file_time_type::min();
		if (std::filesystem::exists(bootdir) && std::filesystem::is_directory(bootdir)) {
			for (const auto& file:std::filesystem::directory_iterator(bootdir)) {
				if (!file.is_regular_file()) continue;
				const auto& filename = file.path().filename().string();
				if (!filename.starts_with("vmlinuz-")) continue;
				if (filename.ends_with(".old")) continue;
				auto file_time = file.last_write_time();
				if (file_time < latest) continue;
				//else
				kernel = file.path();
				latest = file_time;
			}
		}
		if (kernel) {
			auto kernel_filename = kernel->filename().string();
			auto initramfs_filename = "initramfs" + kernel_filename.substr(7) + ".img";
			if (std::filesystem::exists(kernel->parent_path() / initramfs_filename)) {
				initramfs = kernel->parent_path() / initramfs_filename;
			}
		}
	}

	if (!kernel) {
		if (!quiet) std::cout << ("No kernel found under " + rootdir.string()) << std::endl;
		return 1;
	}
	//else
	std::string cmdline;

	{
		std::ifstream proc_cmdline("/proc/cmdline");
		if (!proc_cmdline) throw std::runtime_error("Cannot open /proc/cmdline");
		std::getline(proc_cmdline, cmdline);
	}

	auto cmdline_args = parse_cmdline(cmdline);
	std::string new_cmdline;
	bool has_fstab = has_root_enry_in_fstab(rootdir);
	bool has_rw = false;
	for (const auto& arg:cmdline_args) {
		if (new_cmdline != "") new_cmdline += ' ';
		if (arg.starts_with("root=") || arg.starts_with("rootfstype=")) continue;
		if (!has_fstab && arg == "ro") continue;
		if (arg == "rw") has_rw = true;
		//else
		new_cmdline += arg;
	}
	new_cmdline += " root=" + device + " rootfstype=" + fstype;
	if (!has_fstab && !has_rw) new_cmdline += " rw"; // always mount root filesystem r/w when fstab is missing

	if (!quiet) {
		std::cout << "Kernel=" << kernel->string() << std::endl;
		std::cout << "Kernel args=" << new_cmdline << std::endl;
		if (initramfs) std::cout << "Initramfs=" << initramfs->string() << std::endl;
	}

	std::string arg_append = "--append=" + new_cmdline;
	std::string arg_initrd = "--initrd=" + (initramfs? initramfs->string() : std::string());
	std::vector<const char*> argv = {"kexec", "-l", arg_append.c_str()};
	if (initramfs) argv.push_back(arg_initrd.c_str());
	argv.push_back(kernel->c_str());
	argv.push_back(NULL);
	return execv("/usr/sbin/kexec",const_cast<char* const*>(argv.data()));
}

int main(int argc, char* argv[]) 
{
	argparse::ArgumentParser program(argv[0]);
	program.add_argument("-q", "--quiet").default_value(false).implicit_value(true);
	program.add_argument("rootdir").nargs(1);

	try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err) {
		std::cerr << err.what() << std::endl;
		std::cerr << program;
		return 1;
	}

	std::filesystem::path rootdir(program.get("rootdir"));

	try {
		return kexec_boot(rootdir, program.get<bool>("--quiet"));
	}
	catch (const std::runtime_error& err) {
		std::cerr << err.what() << std::endl;
	}
	return 1;
}
