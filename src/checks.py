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
        logger.info("KPTI disabled")


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
    _msg_if_set: str
    _msg_if_not_set: str
    NOSYMBOL = "No symbol"

    @property
    def msg_if_set(self):
        return f"{self.name} is set: {self._msg_if_set}"

    @property
    def msg_if_not_set(self):
        return f"{self.name} is not set: {self._msg_if_not_set}"

    def check_vmlinux(self):
        is_set = self._check_vmlinux()
        if is_set is None:
            logger.warn(f"{self.name} is not checked")
            return
        if is_set:
            if self.is_config_set_desired:
                logger.info(self.msg_if_set)
            else:
                logger.warn(self.msg_if_set)
        else:
            if self.is_config_set_desired:
                logger.warn(self.msg_if_not_set)
            else:
                logger.info(self.msg_if_not_set)

    def _check_vmlinux(self):
        return None

    def gdb_exec(self, cmd):
        try:
            gdb = "gdb" if "x86" in ctx.arch else "gdb-multiarch"
            MAGICSTR = '"hi"'
            res = subprocess.check_output(
                [
                    gdb,
                    "-batch",
                    "-ex",
                    f"file {ctx.get(ctx.VMLINUX)}",
                    "-ex",
                    f"print {MAGICSTR}",
                    "-ex",
                    cmd,
                ],
                stderr=subprocess.DEVNULL,
            ).decode()
            if MAGICSTR not in res:
                logger.warn("something went terribly wrong while running gdb")
                return self.NOSYMBOL
            print(res)
            return res.split(MAGICSTR)[1]
        except Exception:
            return self.NOSYMBOL


class UsermodeHelperConfig(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_STATIC_USERMODEHELPER"
        self.is_config_set_desired = False
        self._msg_if_set = "cannot change critical strings"
        self._msg_if_not_set = "can change critical strings"

    def _check_vmlinux(self):
        out = self.gdb_exec("disassemble call_usermodehelper_setup")
        if self.NOSYMBOL in out:
            return None
        if ctx.arch == "x86-64":
            return re.search(r"\[r..?\+0x28\],\s*(0x[0-9a-f]+)", out) is not None
        if ctx.arch == "aarch64":
            return len(out.splitlines()) > 50


class SlabMergeDefaultConfig(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_SLAB_MERGE_DEFAULT"
        self.is_config_set_desired = True
        self._msg_if_set = "slabs can be aliased"
        self._msg_if_not_set = "slabs cannot be aliased"

    def _check_vmlinux(self):
        out = self.gdb_exec("p/x slab_nomerge")
        if self.NOSYMBOL in out:
            # the symbol is part of DAWRF
            out = self.gdb_exec("disassemble find_mergeable")
            if self.NOSYMBOL in out:
                return None
            return len(out.splitlines()) > 5
        return "$2 = 0x0" in out


class SlabFreelistHardened(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_SLAB_FREELIST_HARDENED"
        self.is_config_set_desired = False
        self._msg_if_set = "checks on double free and mangles heap pointers"
        self._msg_if_not_set = "no check on DF and heap pointers are not mangled"

    def _check_vmlinux(self):
        for sym in ["do_kmem_cache_create", "kmem_cache_open", "__kmem_cache_create"]:
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
        self._msg_if_set = "initial slub freelist randomized"
        self._msg_if_not_set = "initial slub freelist not randomized"

    def _check_vmlinux(self):
        return self.NOSYMBOL not in self.gdb_exec("disassemble init_cache_random_seq")


class HardenedUsercopy(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_HARDENED_USERCOPY"
        self.is_config_set_desired = False
        self._msg_if_set = "bounds checking on reads/writes to kernel heap objects"
        self._msg_if_not_set = (
            "NO bounds checking on reads/writes to kernel heap objects"
        )

    def _check_vmlinux(self):
        return self.NOSYMBOL not in self.gdb_exec("disassemble __check_heap_object")


class BpfUnprivDefaultOff(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_BPF_UNPRIV_DEFAULT_OFF"
        self.is_config_set_desired = False
        self._msg_if_set = "unpriveleged user CANNOT load BPF programs"
        self._msg_if_not_set = "unpriveleged user CAN load BPF programs"

    def _check_vmlinux(self):
        return "$2 = 0x2" in self.gdb_exec("p/x (int)sysctl_unprivileged_bpf_disabled")


class RandStruct(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_RANDSTRUCT"
        self.is_config_set_desired = False
        self._msg_if_set = "marked structures are randomized"
        self._msg_if_not_set = "marked structures are NOT randomized"

    def _check_vmlinux(self):
        out = self.gdb_exec("p/x (long)tainted_mask")
        return self.NOSYMBOL not in out and "$2 = 0x0" not in out


class RandomKmallocCaches(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_RANDOM_KMALLOC_CACHES"
        self.is_config_set_desired = False
        self._msg_if_set = "Multiple copies of slab caches are used for normal kmalloc"
        self._msg_if_not_set = "One copy of slab caches is used for normal kmalloc"

    def _check_vmlinux(self):
        return self.NOSYMBOL not in self.gdb_exec("p/x &random_kmalloc_seed")


class Memcg(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_MEMCG"
        self.is_config_set_desired = False
        self._msg_if_set = "cg-caches exist"
        self._msg_if_not_set = "cg-caches do not exist"

    def _check_vmlinux(self):
        return self.NOSYMBOL not in self.gdb_exec("p/x &kpagecgroup_proc_ops")


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
        RandomKmallocCaches(),
        SlabFreelistHardened(),
        SlabMergeDefaultConfig(),
        BpfUnprivDefaultOff(),
        RandStruct(),
        Memcg(),
    ]
    logger.important("Checking kernel configs")
    if ctx.get(ctx.CONFIG):
        check_kconfig(configs)
    else:
        check_vmlinux(configs)
