import os, json

RAMFS = "initramfs.cpio.gz"
BZIMAGE = "bzImage"
RUN_SH = "run.sh"
VMLINUX = "vmlinux"
VULN_KO = "vuln"
LIBSLUB = "libslub"
CONFIG = "kernel_config"
CHALL_SETTING = "settings.json"

"""
get cwd file path, just a wrapper!
"""
def root_path(name=None):
    if name is None:
        name = ""
    return os.path.join(os.getcwd(), name)

def workplace_path(fname=None):
    if fname is None:
        fname = ""
    return root_path(f"workplace/{fname}")

def challenge_path(fname=None):
    if fname is None:
        fname = ""
    return workplace_path(f"challenge/{fname}")

def exploit_path(fname=None):
    if fname is None:
        fname = ""
    return workplace_path(f"exploit/{fname}")

def get_setting(setting):
    settings = json.load(open(workplace_path(CHALL_SETTING), "r"))
    if setting not in settings: 
        return None
    return settings[setting]

def set_setting(setting, val):
    settings = json.load(open(workplace_path(CHALL_SETTING), "r"))
    if setting not in settings: 
        return False
    settings[setting] = val
    settings_path = get_setting_path_from_root(CHALL_SETTING)
    f = open(settings_path, "w")
    json.dump(settings, f, indent=4)
    f.flush()
    return True

def get_setting_path(setting):
    val = get_setting(setting)
    if val is None:
        return None
    if setting in [RAMFS, BZIMAGE, VMLINUX]:
        return challenge_path(val)
    elif setting in [VULN_KO]:
        return exploit_path(val)
    elif setting in [CHALL_SETTING]:
        return workplace_path(val)
    else:
        assert False, "should not have reached here"

"""
get the file path from the CHALL_SETTING
"""
def get_setting_path_from_root(setting):
    val = get_setting(setting)
    if val is None:
        return None
    return root_path(val)

def warn_none_setting(setting):
    warn(f"the setting for {setting} is none, consider changing workplace/{CHALL_SETTING}")

def error_invalid_setting(setting):
    error(f"the setting for {setting} is invalid, change workplace/{CHALL_SETTING} in order to proceed")

"""
strict setting must be enforced 
"""
def strict_setting(setting):
    if get_setting(setting) is None or not os.path.exists(get_setting_path_from_root(setting)):
        error_invalid_setting(setting)

"""
None soft settings are allowed
However, if specified, must be valid
"""
def soft_setting(setting):
    if get_setting(setting) is None:
        warn_none_setting(setting)
    elif not os.path.exists(get_setting_path_from_root(setting)):
        error_invalid_setting(setting)

ANSI_BRIGHT_GREEN = "\u001b[32;1m"
ANSI_YELLOW = "\u001b[33m"
ANSI_BLUE   = "\u001b[34m"
ANSI_RED    = "\u001b[31m"
ANSI_RESET  = "\u001b[0m"

def important(msg):
    print(f"{ANSI_BRIGHT_GREEN}[!] {msg}{ANSI_RESET}")

def warn(*args, **kwargs):
    print(f"{ANSI_YELLOW}[*]{ANSI_RESET}", *args, **kwargs)

def info(*args, **kwargs):
    print(f"{ANSI_BLUE}[+]{ANSI_RESET}", *args, **kwargs)

def error(*args, **kwargs):
    print(f"{ANSI_RED}[-]{ANSI_RESET}", *args, **kwargs)
    exit(-1)
