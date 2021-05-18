#include <string>
#include <iostream>
#include <unistd.h>
#include <wayland-client.h>

static void global_registry_handler(void *data, struct wl_registry *, uint32_t,const char *interface, uint32_t)
{
    if (std::string(interface) == "wl_output") *((bool *)data) = true;
}

bool ping()
{
    struct wl_display* display = wl_display_connect(NULL);
    if (!display) {
        throw std::runtime_error("Can't connect to display");
    }

    //else
    bool output = false;
    struct wl_registry *registry = wl_display_get_registry(display);
    const struct wl_registry_listener registry_listener = {
        global_registry_handler, NULL
    };
    wl_registry_add_listener(registry, &registry_listener, &output);

    wl_display_dispatch(display);
    wl_display_roundtrip(display);

    wl_display_disconnect(display);

    return output;
}

int main(int argc, char **argv)
{
    try {
        while (!ping()) {
            sleep(1);
        }
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
    return 0;
}
