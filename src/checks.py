from utils import *
import subprocess

def check_settings():
    strict_setting(BZIMAGE)
    strict_setting(RAMFS)
    strict_setting(RUN_SH)
    soft_setting(VMLINUX)
    soft_setting(VULN_KO)
    soft_setting(CONFIG)
    if get_setting(LIBSLUB) is None:
        warn_none_setting(LIBSLUB)
    elif not os.path.exists(os.path.expanduser(get_setting(LIBSLUB))):
        error_invalid_setting(LIBSLUB)

"""
@opt: the cpu option for the qemu command
@effect: prints out checks on cpu option
"""
def check_cpu_option(opt):
    if "+smep" in opt:
        warn("SMEP enabled")
    else:
        info("SMEP disabled")
    if "+smap" in opt:
        warn("SMAP enabled")
    else:
        info("SMAP disabled")

"""
@opt: the append option for the qemu command
@effect: prints out checks on append option
"""
def check_append_option(opt):
    if "nokaslr" in opt:
        info("KASLR disabled")
    else:
        warn("KASLR enabled")
    if "oops=panic" in opt or "panic_on_oops=1" in opt: 
        warn("Kernel panic on oops")
    else:
        info("panic_on_oops disabled")
    if "kpti=1" in opt or "pti=on" in opt: 
        warn("KPTI enabled")
    else:
        info("KPTI diabled")

def check_qemu_options(tokens):
    important("Checking qemu command line options")
    if "cpu" in tokens:
        check_cpu_option(tokens["cpu"])
    else:
        check_cpu_option("")
    if "append" in tokens:
        check_append_option(tokens["append"])
    else:
        check_append_option("")

def check_kernel_config():
    assert False, "not implemented" # TODO:

def check_vmlinux():
    out = subprocess.check_output(["nm", "-a", get_setting_path(VMLINUX)], stderr=subprocess.DEVNULL).decode().strip()
    if len(out) < 100:
        warn("No symbols in vmlinux")
        return
    symbols = {}
    for line in out.splitlines():
        tmp = line.split()
        if len(tmp[0]) == 0x10:
            symbols[tmp[2]] = int(tmp[0], 16)
    configs = { # TODO:
        "RANDOM_KMALLOC_CACHES": None,
        "FUSE_FS": None,
        "HARDENED_USERCOPY": None,
        "SLAB_FREELIST_RANDOM": None,
    }
    for c, funcs in configs.items():
        if funcs is None:
            warn(f"{c} is not checked")
            continue
        for func in funcs:
            if func in symbols:
                warn(f"{c} is enabled")
                continue
        info(f"{c} is disabled")
    # TODO: checks with disassembly:
    # check SLAB_FREELIST_HARDENED
    # check STATIC_USERMODEHELPER

"""
check mitigations from .config if exists, otherwise checks vmlinux
"""
def check_config():
    important("Checking kernel configs")
    if get_setting(CONFIG):
        check_kernel_config()
    else:
        check_vmlinux()
