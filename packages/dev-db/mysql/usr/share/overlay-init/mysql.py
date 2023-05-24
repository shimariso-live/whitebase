import os,shutil,subprocess,logging,time,stat

def execute_mysqld(root):
    run = os.path.join(root, "run/mysqld")
    os.makedirs(run, exist_ok=True)
    shutil.chown(run, "mysql", "mysql")
    mysqld = subprocess.Popen(["/bin/chroot", root, "/usr/sbin/mysqld", 
        "--no-defaults", "--skip-networking", "--user=mysql", "--log_error_verbosity=1", "--basedir=/usr", 
        "--datadir=/var/lib/mysql", "--max_allowed_packet=8M", "--net_buffer_length=16K", "--skip-log-bin",
        "--console", "--tmpdir=/run/mysqld", "--socket=/run/mysqld/mysqld.sock"])
    for i in range(0,10):
        if mysqld.poll() is not None:
            logging.error("MySQL aborted")
            break # process exited
        socket = os.path.join(run, "mysqld.sock")
        if os.path.exists(socket) and stat.S_ISSOCK(os.stat(socket).st_mode):
            logging.info("MySQL started.")
            return (mysqld, socket)
        #else
        logging.debug("Waiting for MySQL to be up...")
        time.sleep(1)
    raise Exception("MySQL didn't come up")

def configure(root):
    mysql_orig = os.path.join(root, "var/lib/mysql")
    if not os.path.isdir(mysql_orig):
        logging.warning("No MySQL data directory")
        return
    #else
    mysql_work = os.path.join(root, "run/initramfs/rw/mysql")
    if not os.path.exists(mysql_work):
        if subprocess.call(["/bin/cp", "-a", mysql_orig, mysql_work]) == 0: # somehow shutil.copytree doesn't preserve file owner
            logging.info("MySQL data directory copied.")
        else:
            logging.error("Copying MySQL data directory failed.")

    if os.path.exists(mysql_work) and not os.path.ismount(mysql_orig):
        if subprocess.call(["mount", "--bind", mysql_work, mysql_orig]) == 0:
            logging.info("MySQL data directory bind-mounted.")
        else:
            logging.error("Bind-mounting MySQL Data directory failed.")
