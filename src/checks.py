from utils import logger, ctx
import subprocess
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


class KernelConfig:
    name: str
    is_config_set_desired: (
        bool  # indicates if the config set is desirable for the attacker
    )
    _set_msg: str
    _not_set_msg: str
    NOSYMBOL = "No symbol"

    @property
    def set_msg(self):
        return f"{self.name} is set: {self._set_msg}"

    @property
    def not_set_msg(self):
        return f"{self.name} is not set: {self._not_set_msg}"

    def check_vmlinux(self):
        is_set = self._check_vmlinux()
        if is_set is None:
            logger.warn(f"{self.name} is not checked")
            return
        if is_set:
            if self.is_config_set_desired:
                logger.info(self.set_msg)
            else:
                logger.warn(self.set_msg)
        else:
            if self.is_config_set_desired:
                logger.warn(self.unset_msg)
            else:
                logger.info(self.unset_msg)

    def _check_vmlinux(self):
        return None

    def gdb_exec(self, cmd):
        try:
            return subprocess.check_output(
                ["gdb", "-batch", "-ex", f"file {ctx.get(ctx.VMLINUX)}", "-ex", cmd],
                stderr=subprocess.DEVNULL,
            ).decode()
        except Exception as e:
            logger.warn(str(e))
            return self.NOSYMBOL


class UsermodeHelperConfig(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_STATIC_USERMODEHELPER"
        self.is_config_set_desired = False
        self._set_msg = "cannot change critical strings"
        self._not_set_msg = "can change critical strings"

    def _check_vmlinux(self):
        out = self.gdb_exec("disassemble call_usermodehelper_setup")
        if self.NOSYMBOL in out:
            return None
        return re.search(
            r"\[r..?\+0x28\],\s*(0x[0-9a-f]+)", out
        )  # TODO: double check if correct


class SlabMergeDefaultConfig(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_SLAB_MERGE_DEFAULT"
        self.is_config_set_desired = True
        self._set_msg = "slabs can be aliased"
        self._not_set_msg = "slabs cannot be aliased"

    def _check_vmlinux(self):
        out = self.gdb_exec("p/x (long)slab_nomerge")
        if self.NOSYMBOL in out:
            return None
        return "$1 = 0x0" not in out


class SlabFreelistHardened(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_SLAB_FREELIST_HARDENED"
        self.is_config_set_desired = False
        self._set_msg = "checks on double free and mangles heap pointers"
        self._not_set_msg = "no check on DF and heap pointers are not mangled"

    def _check_vmlinux(self):
        for sym in ["__kmem_cache_create", "kmem_cache_open", "do_kmem_cache_create"]:
            out = self.gdb_exec(f"disassemble {sym}")
            if self.NOSYMBOL in out:
                continue
            if "get_random" in out:
                return True
            else:
                return False
        return None


class SlabFreelistRandom(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_SLAB_FREELIST_RANDOM"
        self.is_config_set_desired = False
        self._set_msg = "initial slub freelist randomized"
        self._not_set_msg = "initial slub freelist not randomized"

    def _check_vmlinux(self):
        return self.NOSYMBOL not in self.gdb_exec("disassemble init_cache_random_seq")


class HardenedUsercopy(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_HARDENED_USERCOPY"
        self.is_config_set_desired = False
        self._set_msg = "bounds checking on reads/writes to kernel heap objects"
        self._not_set_msg = "NO bounds checking on reads/writes to kernel heap objects"

    def _check_vmlinux(self):
        return self.NOSYMBOL not in self.gdb_exec("disassemble __check_heap_object")


def check_kconfig(configs):
    kconfig = open(ctx.get(ctx.CONFIG), "r").read()
    for config in configs:
        config.check_kconfig(kconfig)


def check_vmlinux(configs):
    for config in configs:
        config.check_vmlinux()


def check_config():
    """
    check mitigations from .config if exists, otherwise checks vmlinux
    """
    configs = [
        SlabFreelistRandom(),
        HardenedUsercopy(),
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
