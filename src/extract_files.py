import os, shutil, subprocess, json
from utils import *
from checks import check_settings

def decompress_ramfs():
    ram_path = challenge_path("initramfs")
    os.mkdir(ram_path)
    archive_path = os.path.join(ram_path, RAMFS)
    shutil.copy(get_setting_path_from_root(RAMFS), archive_path)
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
    if get_setting_path_from_root(VULN_KO) is not None:
        shutil.copy2(get_setting_path_from_root(VULN_KO), get_setting_path(VULN_KO))
        return
    mods = []
    for _, _, files in os.walk(root_path()):
        for file in files:
            if file.endswith(".ko"):
                mods.append(file)
    mod = None
    if len(mods) > 0:
        mod = mods[0]
        if len(mods) > 1:
            warn("detected multiple loadable modules, select which one ❱")
            mod_substr = input()
            for m in mods:
                if mod_substr in m:
                    mod = m
                    break
    if mod is None or not os.path.exists(root_path(mod)):
        warn("no kernel loadable modules found")
        return
    assert set_setting(VULN_KO, mod)
    shutil.copy2(get_setting_path_from_root(VULN_KO), get_setting_path(VULN_KO))

def extract_vmlinux():
    if get_setting_path_from_root(VMLINUX) is not None:
        shutil.copy2(get_setting_path_from_root(VMLINUX), get_setting_path(VMLINUX))
        return 
    assert False, "not implemented" # TODO:

"""
generate settings.json file if does not exist, otherwise use the existing settings
"""
def extract_chall_settings():
    settings_path = workplace_path(CHALL_SETTING)
    if not os.path.exists(settings_path):
        settings = {
            BZIMAGE: BZIMAGE,
            RAMFS: RAMFS,
            RUN_SH: RUN_SH,
            VMLINUX: None,
            VULN_KO: None,
            LIBSLUB: None, 
            LIBKERNEL: None,
            CONFIG: None,
        }
        if os.path.exists(root_path(VMLINUX)):
            settings[VMLINUX] = VMLINUX
        if os.path.exists(root_path(CONFIG)):
            settings[CONFIG] = CONFIG
        path = os.path.expanduser("~/Tools/libslub/libslub.py") # default
        if os.path.exists(path):
            settings[LIBSLUB] = path
        path = os.path.expanduser("~/Tools/libkernel/libkernel.py") # default
        if os.path.exists(path):
            settings[LIBKERNEL] = path
        for fname in os.listdir(os.getcwd()):
            if fname.endswith(".ko"):
                settings[VULN_KO] = fname
                break
        f = open(settings_path, "w")
        json.dump(settings, f, indent=4)
        f.flush()
    f = open(settings_path, "r")
    important(f"Settings:\n{json.dumps(json.load(f), indent=4)}")
    check_settings()
