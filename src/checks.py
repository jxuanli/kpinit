from utils import *

def check_settings():
    strict_setting(BZIMAGE)
    strict_setting(RAMFS)
    strict_setting(RUN_SH)
    soft_setting(VMLINUX)
    soft_setting(VULN_KO)
    soft_setting(LIBSLUB)
    soft_setting(MODULE_NAME)


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

