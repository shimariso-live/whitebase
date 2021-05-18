#include <iostream>
#include "init.h"

void init::hooks::print_banner()
{
  std::cout
    << R"( __      __        .__ ___.         .__        )" "\n"
    << R"(/  \    /  \_____  |  |\_ |_________|__|__  ___)" "\n"
    << R"(\   \/\/   /\__  \ |  | | __ \_  __ \  \  \/  /)" "\n"
    << R"( \        /  / __ \|  |_| \_\ \  | \/  |>    < )" "\n"
    << R"(  \__/\  /  (____  /____/___  /__|  |__/__/\_ \)" "\n"
    << R"(       \/        \/         \/               \/)" << std::endl;
}

void init::hooks::setup_data_subvolumes(const std::filesystem::path& mnt_path) 
{
	const auto data_partition_dev_path = mnt_path / "vm";
	if (!init::lib::is_dir(data_partition_dev_path) && init::lib::exec(init::progs::BTRFS, {"subvolume", "create", data_partition_dev_path}) != 0) {
		std::cout << "Failed to create vm data subvolume under data partition." << std::endl;
	}
}

void init::hooks::post_init(const std::filesystem::path& newroot,
  std::optional<std::tuple<std::filesystem::path,std::optional<std::string/*uuid*/>,std::optional<std::string/*fstype*/>>> data_partition,
  inifile_t)
{
	if (!data_partition) return;
	const auto data_partition_dev_path = std::get<0>(data_partition.value());
	const auto vm_default = newroot / "var/vm/@default";
	if (!init::lib::is_dir(vm_default) || init::lib::mount(data_partition_dev_path, vm_default, "btrfs", MS_RELATIME, "subvol=vm") != 0) {
		std::cout << "Default VM subvolume couldn't be mounted." << std::endl;
	}
}

