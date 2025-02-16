import os, shutil, subprocess, json
from utils import *
from checks import check_settings

def decompress_ramfs(chall_path):
    ram_path = os.path.join(chall_path, "initramfs")
    os.mkdir(ram_path)
    archive_path = os.path.join(ram_path, RAMFS)
    shutil.copy(get_settings_fpath(RAMFS), archive_path)
    prev = os.getcwd()
    os.chdir(ram_path)
    subprocess.run(["gunzip", archive_path])
    cpio_fpath = os.path.join(chall_path, f"{RAMFS.split('.')[0]}/initramfs.cpio")
    assert os.path.isfile(cpio_fpath), "missing cpio: " + cpio_fpath
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
    if get_settings_fpath(VULN_KO) is not None:
        return 
    assert False, "not implemented" # TODO: 

def extract_vmlinux():
    if get_settings_fpath(VMLINUX) is not None:
        return 
    assert False, "not implemented" # TODO:

"""
generate settings.json file if does not exist, otherwise use the existing settings
"""
def extract_chall_settings(wp_path):
    if not os.path.exists(settings_fpath):
        settings = {
            BZIMAGE: BZIMAGE,
            RAMFS: RAMFS,
            RUN_SH: RUN_SH,
            VMLINUX: None,
            VULN_KO: None
            LIBSLUB: None, 
            MODULE_NAME: None,
        }
        name = "vmlinux"
        if is_in_cwd(name):
            settings[VMLINUX] = name 
        path = "~/Tools/libslub/libslub.py" # default
        if os.path.exists(path):
            names[LIBSLUB] = path
        for fname in os.listdir(os.getcwd()):
            if fname.endswith(".ko"):
                settings[VULN_KO] = fname
                info(f"found ../{fname}")
                break
        f = open(os.path.join(wp_path, CHALL_SETTING), "w")
        json.dump(names, f, indent=4)
    check_settings(settings_fpath)
