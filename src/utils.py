import os, json

RAMFS = "initramfs.cpio.gz"
BZIMAGE = "bzImage"
RUN_SH = "run.sh"
VMLINUX = "vmlinux"
VULN_KO = "vuln"
LIBSLUB = "libslub" # TODO:
MODULE_NAME = "module_name"
CHALL_SETTING = "setting.json"

"""
get cwd file path, just a wrapper!
"""
def get_cwd_fpath(name):
    if name is None:
        return None
    return os.path.join(os.getcwd(), name)

def get_setting(setting):
    settings = json.load(open(os.path.join(os.getcwd(), f"workplace/{CHALL_SETTING}"), "r"))
    if setting not in settings: 
        return None
    return settings[setting]


"""
get the file path from the CHALL_SETTING
"""
def get_settings_fpath(setting):
    return get_cwd_fpath(get_setting(setting))

def is_in_cwd(name):
    fpath = get_cwd_fpath(name)
    if fpath is None:
        return False
    return os.path.exists(fpath)

"""
strict setting must be enforced 
"""
def strict_setting(setting):
    if get_setting(setting) is None:
        error(f"the setting for {setting} is invalid, change workplace/{CHALL_SETTING} in order to proceed")

"""
invalid soft settings are allowed
"""
def soft_setting(setting):
    if get_setting(setting) is None:
        warn(f"the setting for {setting} is invalid, consider changing workplace/{CHALL_SETTING}")

ANSI_YELLOW = "\u001b[33m"
ANSI_BLUE   = "\u001b[34m"
ANSI_RED    = "\u001b[31m"
ANSI_RESET  = "\u001b[0m"

def warn(*args, **kwargs):
    print(f"{ANSI_YELLOW}[*]{ANSI_RESET}", *args, **kwargs)

def info(*args, **kwargs):
    print(f"{ANSI_BLUE}[!]{ANSI_RESET}", *args, **kwargs)

def error(*args, **kwargs):
    print(f"{ANSI_RED}[-]{ANSI_RESET}", *args, **kwargs)
    exit(-1)
