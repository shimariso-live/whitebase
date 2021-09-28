
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mount.h>

int main()
{
    mkdir("/.stubroot/.real_root", S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    if (mount("/", "/.stubroot/.real_root", "none", MS_BIND, "") < 0) {
        perror("mount");
        return 1;
    };
    if (chroot("/.stubroot") < 0) {
        perror("chroot");
        return 1;
    }
    return execl("/init", "/init", NULL);
}