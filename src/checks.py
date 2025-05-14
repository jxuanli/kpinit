from utils import logger, ctx
import subprocess
from typing import List
import re


def check_cpu_option(opt):
    """
    @opt: the cpu option for the qemu command
    @effect: prints out checks on cpu option
    """
    if "+smep" in opt:
        logger.warn("SMEP enabled")
    else:
        logger.info("SMEP disabled")
    if "+smap" in opt:
        logger.warn("SMAP enabled")
    else:
        logger.info("SMAP disabled")


def check_append_option(opt):
    """
    @opt: the append option for the qemu command
    @effect: prints out checks on append option
    """
    if "nokaslr" in opt:
        logger.info("KASLR disabled")
    else:
        logger.warn("KASLR enabled")
    if "oops=panic" in opt or "panic_on_oops=1" in opt:
        logger.warn("Kernel panic on oops")
    else:
        logger.info("panic_on_oops disabled")
    if "kpti=1" in opt or "pti=on" in opt:
        logger.warn("KPTI enabled")
    else:
        logger.info("KPTI diabled")


def check_qemu_options(tokens):
    logger.important("Checking qemu command line options")
    if "cpu" in tokens:
        check_cpu_option(tokens["cpu"])
    else:
        check_cpu_option("")
    if "append" in tokens:
        check_append_option(tokens["append"])
    else:
        check_append_option("")

class KernelConfig():

    name: str
    msg_set: str
    msg_unset: str
    funcs: List[str]

    def __init__(self, name: str, msg_set: str | None = None, msg_unset: str | None = None, funcs: List[str] = []):
        self.name = name
        self.msg_set = msg_set
        self.msg_unset = msg_unset
        self.funcs = funcs

    def __warn__(self):
        logger.warn(f"{self.name} set: {self.msg_set}")

    def __info__(self):
        logger.info(f"{self.name} not set: {self.msg_unset}")

    def check_kconfig(self, kconfig):
        if self.name + "=y" in kconfig:
            self.__warn__()
        else:
            self.__info__()

    def dyn_check_vmlinux(self, symbols):
        logger.error(f"{self.name}: Not implemented")

    def check_vmlinux(self, symbols):
        for func in self.funcs:
            if func in symbols:
                self.__warn__()
                return
        if len(self.funcs) == 0:
            self.dyn_check_vmlinux(symbols)
            return
        self.__info__()

    def gdb_exec(self, cmd):
        try:
            out = subprocess.check_output(['gdb', '-batch','-ex', f'file {ctx.get(ctx.VMLINUX)}', '-ex', cmd], stderr=subprocess.DEVNULL).decode()
        except Exception as e:
            error(str(e))
            out = ""
        return out

class UsermodeHelperConfig(KernelConfig):
    def __init__(self):
        super().__init__("CONFIG_STATIC_USERMODEHELPER", "cannot change critical strings", "can change critical strings")

    def dyn_check_vmlinux(self, symbols):
        out = self.gdb_exec("disassemble call_usermodehelper_setup")
        if re.search(r'\[r..?\+0x28\],\s*(0x[0-9a-f]+)', out): # TODO: double check if correct
            self.__warn__()
        else:
            self.__info__()

class SlabMergeDefaultConfig(KernelConfig):
    def __init__(self):
        super().__init__("CONFIG_SLAB_MERGE_DEFAULT", "no cg cache", "cg cache exists")

    def dyn_check_vmlinux(self, symbols):
        out = None
        try:
            out = self.gdb_exec("p/x (long)slab_nomerge")
        except:
            logger.warn(f"{self.name} is not checked")
            return
        if "$1 = 0x0" in out:
            self.__warn__()
        else:
            self.__info__()

class SlabFreelistHardened(KernelConfig):
    def __init__(self):
        super().__init__("CONFIG_SLAB_FREELIST_HARDENED", "checks on double free and mangles heap pointers", "no check on DF and heap pointers are not mangled")

    def dyn_check_vmlinux(self, symbols):
        for sym in ['__kmem_cache_create', 'kmem_cache_open', 'do_kmem_cache_create']:
            if sym not in symbols:
                continue
            out = self.gdb_exec(f'disassemble {sym}')
            if 'get_random' in out:
                self.__warn__()
                return
            break
        self.__info__()

def check_kconfig(configs):
    kconfig = open(ctx.get(ctx.CONFIG), "r").read()
    for config in configs:
        config.check_kconfig(kconfig)


def check_vmlinux(configs):
    out = (
        subprocess.check_output(
            ["nm", "-a", ctx.get_path(ctx.VMLINUX)], stderr=subprocess.DEVNULL
        )
        .decode()
        .strip()
    )
    if len(out) < 100:
        logger.warn("No symbols in vmlinux")
        return
    symbols = {}
    for line in out.splitlines():
        tmp = line.split()
        if len(tmp[0]) == 0x10:
            symbols[tmp[2]] = int(tmp[0], 16)
    for config in configs:
        config.check_vmlinux(symbols)


def check_config():
    """
    check mitigations from .config if exists, otherwise checks vmlinux
    """
    configs = [
        KernelConfig("CONFIG_SLAB_FREELIST_RANDOM", "initial slub freelist randomized", "initial slub freelist not randomized", ["init_cache_random_seq"]),
        KernelConfig("CONFIG_HARDENED_USERCOPY", "defined usercopy region", "undefined usercopy region", ["usercopy_abort"]),
        UsermodeHelperConfig(),
        # KernelConfig("CONFIG_RANDOM_KMALLOC_CACHES", "", "", ["random_kmalloc_seed"]),
        SlabFreelistHardened(),
        SlabMergeDefaultConfig(),
    ]
    logger.important("Checking kernel configs")
    if ctx.get(ctx.CONFIG) and False:
        check_kconfig(configs)
    else:
        check_vmlinux(configs)
