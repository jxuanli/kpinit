import os, json

RAMFS = "initramfs.cpio.gz"
BZIMAGE = "bzImage"
RUN_SH = "run.sh"
VMLINUX = "vmlinux"
VULN_KO = "vuln"
LIBSLUB = "libslub"
MODULE_NAME = "module_name"
CONFIG = "kernel_config"
CHALL_SETTING = "setting.json"

"""
get cwd file path, just a wrapper!
"""
def root_path(name):
    if name is None:
        return None
    return os.path.join(os.getcwd(), name)

def workplace_path(fname=None):
    if fname is None:
        return root_path("workplace/")
    else: 
        return root_path(f"workplace/{fname}")

def challenge_path(fname=None):
    if fname is None:
        return workplace_fpath("challenge/")
    else: 
        return workplace_fpath(f"challenge/{fname}")

def exploit_path(fname=None):
    if fname is None:
        return workplace_fpath("exploit/")
    else: 
        return workplace_fpath(f"exploit/{fname}")

def get_setting(setting):
    settings = json.load(open(workplace_path(CHALL_SETTING), "r"))
    if setting not in settings: 
        return None
    return settings[setting]

def wp_setting_fpath(setting):
    val = get_setting(setting)
    if val is None:
        return None
    if setting in [RAMFS, BZIMAGE, VMLINUX]:
        return challenge_path(val)
    elif setting in [VULN_KO]:
        return challenge_path(val)
    elif setting in [CHALL_SETTING]:
        return workplace_path(CHALL_SETTING)
    else: 
        assert False, "should not have reached here"

"""
get the file path from the CHALL_SETTING
"""
def root_setting_fpath(setting):
    return root_path(get_setting(setting))

def warn_none_setting(setting):
    warn(f"the setting for {setting} is none, consider changing workplace/{CHALL_SETTING}")

def error_invalid_setting(setting):
    error(f"the setting for {setting} is invalid, change workplace/{CHALL_SETTING} in order to proceed")

"""
strict setting must be enforced 
"""
def strict_setting(setting):
    if get_setting(setting) is None or os.path.exists(root_setting_fpath(setting)):
        error_invalid_setting(setting)

"""
None soft settings are allowed
However, if specified, must be valid
"""
def soft_setting(setting):
    if get_setting(setting) is None:
        warn_none_setting(setting)
    elif os.path.exists(root_setting_fpath(setting)):
        error_invalid_setting(setting)

ANSI_BRIGHT_GREEN = "\u001b[32;1m"
ANSI_YELLOW = "\u001b[33m"
ANSI_BLUE   = "\u001b[34m"
ANSI_RED    = "\u001b[31m"
ANSI_RESET  = "\u001b[0m"

def important(*args, **kwargs):
    print(f"{ANSI_BRIGHT_GREEN}[!]{ANSI_RESET}", *args, **kwargs)

def warn(*args, **kwargs):
    print(f"{ANSI_YELLOW}[*]{ANSI_RESET}", *args, **kwargs)

def info(*args, **kwargs):
    print(f"{ANSI_BLUE}[+]{ANSI_RESET}", *args, **kwargs)

def error(*args, **kwargs):
    print(f"{ANSI_RED}[-]{ANSI_RESET}", *args, **kwargs)
    exit(-1)
