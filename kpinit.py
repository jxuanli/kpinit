import os, shutil, subprocess
sys.path.append(os.path.join(path.dirname(path.abspath(__file__)), "src"))

from gen_launch import gen_launch

RAM_NAME = "initramfs.cpio.gz"
BZIMAGE_NAME = "bzImage"

"""
generate the workplace/challenge directory
"""
def gen_challenge(wp_path):
    chall_path = os.path.join(wp_path, "challenge")
    os.mkdir(chall_path)
    ram_fpath = os.path.join(os.getcwd(), RAM_NAME) # TODO:
    assert os.path.isfile(ram_fpath), "ramfs does not exist"
    bzImage_fpath = os.path.join(os.getcwd(), BZIMAGE_NAME) # TODO: 
    assert os.path.isfile(bzImage_fpath), "bzImage does not exist"
    shutil.copy2(ram_fpath, os.path.join(chall_path, RAM_NAME))
    shutil.copy2(bzImage_fpath, os.path.join(chall_path, BZIMAGE_NAME))

    # decompressing
    ram_dirpath = os.path.join(chall_path, "initramfs")
    os.mkdir(ram_dirpath)
    archive_path = os.path.join(ram_dirpath, RAM_NAME)
    shutil.copy(ram_fpath, archive_path)
    shutil.unpack_archive(archive_path, ram_dirpath)
    os.remove(archive_path)
    tmp = os.getcwd()
    os.chdir(ram_dirpath)
    cpio_fpath = os.path.join(ram_dirpath, "initramfs.cpio")
    assert os.path.isfile(cpio_fpath), "missing cpio"
    subprocess.run(["cpio", "-idm", "<", cpio_fpath])
    os.remove(cpio_fpath)
    os.chdir(tmp)

"""
generate the workplace/exploit directory
"""
def gen_exploit(wp_path):
    exploit_path = os.path.join(wp_path, "exploit")
    os.mkdir(exploit_path)
    run_fpath = os.path.join(os.getcwd(), "run.sh")
    assert os.path.isfile(run_fpath), "run.sh does not exit" # TODO: change that to maybe take command line input 
    gen_launch(run_fpath)

    # extra init file 
    init_fpath = os.path.join(wp_path, "challenge/initramfs/init")
    if os.path.isfile(init_fpath):
        shutil.copy(init_fpath, os.path.join(exploit_path, "init"))

"""
generate the workplace directory as specified in README.md
"""
def gen_workplace():
    wp_path = os.path.join(os.getcwd(), "workplace")
    os.mkdir(workplace)
    gen_challenge(wp_path)
    gen_exploit(wp_path)

if __name__ == "__main__":
    # TODO: consider taking cmdline input
    gen_workplace()
