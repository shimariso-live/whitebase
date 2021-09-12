struct VM {
    bool running = false;
    std::optional<std::string> volume = std::nullopt;
    std::optional<uint16_t> cpu = std::nullopt;
    std::optional<uint32_t> memory = std::nullopt;
    std::optional<std::string> ip_address = std::nullopt;
};

std::map<std::string,VM> list();
int list(const std::vector<std::string>& args);