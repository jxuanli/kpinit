import os, json

RAMFS = "initramfs.cpio.gz"
BZIMAGE = "bzImage"
RUN_SH = "run.sh"
VMLINUX = "vmlinux"
VULN = "vuln"
CHALL_SETTING = "setting.json"

"""
get cwd file path, just a wrapper!
"""
def get_cwd_fpath(name):
    if name is None:
        return None
    return os.path.join(os.getcwd(), name)

"""
get the file path from the CHALL_SETTING
"""
def get_config_fpath(name):
    settings = json.load(open(os.path.join(os.getcwd(), f"workpalce/{CHALL_SETTING}"), "r"))
    return get_cwd_fpath(settings[name])

def is_in_cwd(name):
    return os.path.exists(get_cwd_fpath(name))

ANSI_YELLOW = "\u001b[33m"
ANSI_BLUE   = "\u001b[34m"
ANSI_RED    = "\u001b[31m"
ANSI_RESET  = "\u001b[0m"

def warn(*args, **kwargs):
    print(f"{ANSI_YELLOW}[+]{ANSI_RESET}", *args, **kwargs)

def info(*args, **kwargs):
    print(f"{ANSI_BLUE}[-]{ANSI_RESET}", *args, **kwargs)

def error(*args, **kwargs):
    print(f"{ANSI_RED}[x]{ANSI_RESET}", *args, **kwargs)
    exit(-1)
