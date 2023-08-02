import os,shutil,subprocess,logging

def configure(root):
    docker_orig = os.path.join(root, "var/lib/docker")
    if not os.path.isdir(docker_orig):
        logging.warning("No Docker data directory")
        return
    #else
    docker_work = os.path.join(root, "run/initramfs/rw/docker")
    if not os.path.exists(docker_work):
        shutil.copytree(docker_orig, docker_work)
        logging.info("Docker data directory copied.")

    if os.path.exists(docker_work) and not os.path.ismount(docker_orig):
        if subprocess.call(["mount", "--bind", docker_work, docker_orig]) == 0:
            logging.info("Docker data directory bind-mounted.")
        else:
            logging.error("Bind-mounting Docket data directory failed.")

