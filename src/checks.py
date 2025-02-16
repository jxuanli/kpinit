from utils import *

def check_settings():
    strict_setting(BZIMAGE)
    strict_setting(RAMFS)
    strict_setting(RUN_SH)
    soft_setting(VMLINUX)
    soft_setting(VULN_KO)
    soft_setting(LIBSLUB)
    soft_setting(MODULE_NAME)

