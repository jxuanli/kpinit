import os, shutil, subprocess, sys
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from gen_launch import gen_launch
from utils import *

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
    prev = os.getcwd()
    os.chdir(ram_dirpath)
    subprocess.run(["gunzip", archive_path])
    cpio_fpath = os.path.join(ram_dirpath, "initramfs.cpio")
    assert os.path.isfile(cpio_fpath), "missing cpio"
    subprocess.run([f"cpio -idm < {cpio_fpath}"], shell = True)
    os.remove(cpio_fpath)
    os.chdir(prev)

    info("finished generating workplace/challenge")

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

    info("finished generating workplace/exploit")

"""
generate the workplace directory as specified in README.md
"""
def gen_workplace():
    wp_path = os.path.join(os.getcwd(), "workplace")
    os.mkdir(wp_path)
    gen_challenge(wp_path)
    gen_exploit(wp_path)

if __name__ == "__main__":
    # TODO: consider taking cmdline input
    gen_workplace()
