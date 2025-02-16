import os, shutil, subprocess, json
from utils import *
from checks import check_settings

def decompress_ramfs():
    ram_path = challenge_path("initramfs")
    os.mkdir(ram_path)
    archive_path = os.path.join(ram_path, RAMFS)
    shutil.copy(root_setting_fpath(RAMFS), archive_path)
    cpio_fpath = challenge_path(f"{RAMFS.split('.')[0]}/initramfs.cpio")
    prev = os.getcwd()
    os.chdir(ram_path)
    subprocess.run(["gunzip", archive_path])
    assert os.path.isfile(cpio_fpath), "missing cpio: " + cpio_fpath
    subprocess.run([f"cpio -idm < {cpio_fpath}"], shell = True)
    os.remove(cpio_fpath)
    os.chdir(prev)

def extract_init():
    init_fpath = challenge_path("initramfs/init")
    if os.path.isfile(init_fpath):
        shutil.copy(init_fpath, exploit_path("init"))
    else:
        warn("did not find init file")

def extract_ko():
    if root_setting_fpath(VULN_KO) is not None:
        shutil.copy2(root_setting_fpath(VULN_KO), wp_setting_fpath(VULN_KO))
        return
    assert False, "not implemented" # TODO: 

def extract_vmlinux():
    if root_setting_fpath(VMLINUX) is not None:
        shutil.copy2(root_setting_fpath(VMLINUX), wp_setting_fpath(VMLINUX))
        return 
    assert False, "not implemented" # TODO:

"""
generate settings.json file if does not exist, otherwise use the existing settings
"""
def extract_chall_settings():
    settings_fpath = workplace_path(CHALL_SETTING)
    if not os.path.exists(settings_fpath):
        settings = {
            BZIMAGE: BZIMAGE,
            RAMFS: RAMFS,
            RUN_SH: RUN_SH,
            VMLINUX: None,
            VULN_KO: None,
            LIBSLUB: None, 
            MODULE_NAME: None,
            CONFIG: None,
        }
        if os.path.exists(root_path(VMLINUX)):
            settings[VMLINUX] = VMLINUX
        if os.path.exists(root_path(CONFIG)):
            settings[CONFIG] = CONFIG
        path = os.path.expanduser("~/Tools/libslub/libslub.py") # default
        if os.path.exists(path):
            settings[LIBSLUB] = path
        for fname in os.listdir(os.getcwd()):
            if fname.endswith(".ko"):
                settings[VULN_KO] = fname
                info(f"found ../{fname}")
                break
        f = open(settings_fpath, "w")
        json.dump(settings, f, indent=4)
        f.flush()
    check_settings()
