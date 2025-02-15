import os, shutil, subprocess, json
from utils import *

def decompress_ramfs():
    ram_path = os.path.join(chall_path, "initramfs")
    os.mkdir(ram_path)
    archive_path = os.path.join(ram_path, RAMFS)
    shutil.copy(get_config_fpath(RAMFS), archive_path)
    prev = os.getcwd()
    os.chdir(ram_path)
    subprocess.run(["gunzip", archive_path])
    cpio_fpath = os.path.join(os.path.join(chall_path, RAMFS), "initramfs.cpio")
    assert os.path.isfile(cpio_fpath), "missing cpio"
    subprocess.run([f"cpio -idm < {cpio_fpath}"], shell = True)
    os.remove(cpio_fpath)
    os.chdir(prev)

def extract_init(wp_path, exploit_path):
    init_fpath = os.path.join(wp_path, "challenge/initramfs/init")
    if os.path.isfile(init_fpath):
        shutil.copy(init_fpath, os.path.join(exploit_path, "init"))
    else:
        warn("did not find init file")

def extract_ko():
    if get_config_fpath(VULN) is not None:
        return 
    assert False, "not implemented" # TODO: 

def extract_vmlinux():
    if get_config_fpath(VMLINUX) is not None:
        return 
    assert False, "not implemented" # TODO:

"""
generate settings.json file
"""
def extract_chall_settings(wp_path):
    names = {}
    name = "bzImage"
    if is_in_cwd(name):
        names[BZIMAGE] = name 
    else:
        error("cannot file ../%s", name)
    name = "initramfs.cpio.gz"
    if is_in_cwd(name):
        names[RAMFS] = name 
    else:
        error("cannot file ../%s", name)
    name = "run.sh"
    if is_in_cwd(name):
        names[RUN_SH] = name 
    else:
        error("cannot file ../%s", name)
    name = "vmlinux"
    if is_in_cwd(name):
        names[VMLINUX] = name 
        info("found ../%s", name)
    else:
        names[name] = None
        warn("cannot file ../%s", name)

    for fname in os.listdir(os.getcwd()):
        if fname.endswith(".ko"):
            names[VULN] = fname
            info("found ../%s", fname)
            break
    if VULN not in names:
        warn("cannot find the vulnerable module")
        names[VULN] = None
    f = open(os.path.join(wp_path, CHALL_SETTING), "w")
    json.dump(names, f, indent=4)
