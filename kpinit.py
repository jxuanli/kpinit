import os, shutil, sys, json
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from gen_launch import gen_launch
from extract_files import *
from utils import *

"""
generate the workplace/challenge directory
"""
def gen_challenge(wp_path):
    chall_path = os.path.join(wp_path, "challenge")
    os.mkdir(chall_path)
    shutil.copy2(get_config_fpath(RAMFS), os.path.join(chall_path, RAMFS))
    shutil.copy2(get_config_fpath(BZIMAGE), os.path.join(chall_path, BZIMAGE))
    decompress_ramfs()
    extract_vmlinux()

    info("finished generating workplace/challenge")

"""
generate the workplace/exploit directory
"""
def gen_exploit(wp_path):
    exploit_path = os.path.join(wp_path, "exploit")
    os.mkdir(exploit_path)
    gen_launch()
    extract_init(wp_path, exploit_path)
    extract_ko()

    info("finished generating workplace/exploit")

"""
generate the workplace directory as specified in README.md
"""
def gen_workplace():
    wp_path = get_cwd_fpath("workplace")
    if os.path.exists(wp_path):
        assert os.path.isdir(wp_path)
        warn("removing existing workplace to generate a new one")
        os.rmdir(wp_path)
    os.mkdir(wp_path)
    extract_chall_settings(wp_path)
    gen_challenge(wp_path)
    gen_exploit(wp_path)

if __name__ == "__main__":
    gen_workplace()
