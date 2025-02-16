import os, shutil, sys, json
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from gen_launch import gen_launch
from gen_debug import gen_debug
from gen_exploit_src import gen_exploit_src
from extract_files import *
from utils import *
from checks import check_config

"""
generate the workplace/challenge directory
"""
def gen_challenge():
    os.mkdir(challenge_path())
    shutil.copy2(root_setting_fpath(RAMFS), wp_setting_fpath(RAMFS))
    shutil.copy2(root_setting_fpath(BZIMAGE), wp_setting_fpath(BZIMAGE))
    decompress_ramfs()
    extract_vmlinux()

"""
generate the workplace/exploit directory
"""
def gen_exploit():
    os.mkdir(exploit_path())
    gen_launch()
    extract_init()
    extract_ko()
    gen_debug()
    gen_exploit_src()
    check_config()

"""
generate the workplace directory as specified in README.md
"""
def gen_workplace():
    wp_path = workplace_path()
    if os.path.exists(wp_path):
        assert os.path.isdir(wp_path)
        warn("removing existing workplace/challenge and workplace/exploit to generate a new one")
        if os.path.isdir(challenge_path()):
            shutil.rmtree(challenge_path())
        if os.path.isdir(exploit_path()):
            shutil.rmtree(exploit_path())
    else:
        os.mkdir(wp_path)
    extract_chall_settings()
    gen_challenge()
    gen_exploit()
    important("Finished generating workplace")

if __name__ == "__main__":
    gen_workplace()
    important("happy hacking!")
