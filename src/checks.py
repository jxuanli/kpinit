from utils import info, warn, error, important, ctx, runcmd
import re
from typing import List


def check_cpu(cpu):
    """
    @opt: the cpu option for the qemu command
    @effect: prints out checks on cpu option
    """
    if ctx.arch == "x86-64":
        if "+smep" in cpu:
            warn("SMEP enabled")
        else:
            info("SMEP disabled")
        if "+smap" in cpu:
            warn("SMAP enabled")
        else:
            info("SMAP disabled")


def check_append(append):
    """
    @opt: the append option for the qemu command
    @effect: prints out checks on append option
    """
    if "nokaslr" in append:
        info("KASLR disabled")
    else:
        warn("KASLR enabled")
    if "oops=panic" in append or "panic_on_oops=1" in append:
        warn("Kernel panic on oops")
    else:
        info("panic_on_oops disabled")
    if "panic_on_warn" in append:
        warn("panic_on_warn enabled")
    else:
        info("panic_on_warn disabled")
    if "kpti=1" in append or "pti=on" in append:
        warn("KPTI enabled")
    else:
        info("KPTI disabled")
    # TODO: multiple cores


def check_qemu(parsed) -> str | None:
    important("Checking qemu command line options")
    if (cpu := parsed.cpu) is not None:
        check_cpu(cpu)
    else:
        warn("cpu options are not checked")
    if (append := parsed.append) is not None:
        check_append(append)
        fsimgs = ctx.fsimgs.get()
        if (
            ctx.ramfs.get() is not None
            or fsimgs is None
            or not isinstance(fsimgs, List)
        ):
            return None
        target = None
        for e in append.split(" "):
            prefix = "root="
            if e.startswith(prefix):
                target = e[len(prefix) :]
                break
        if target is None:
            return None
        imgfile = None
        is_virtio = False
        if target.startswith("/dev/sd"):
            pass
        elif target.startswith("/dev/vd"):
            is_virtio = True
        else:
            return None
        dev = target[7:][0]
        imgfile = getattr(parsed, f"hd{dev}")
        if imgfile is not None or parsed.drive is None:
            return imgfile
        target_idx = ord(dev) - ord("a")
        for idx, drive in enumerate(parsed.drive):
            if is_virtio and ",if=virtio" not in drive:
                continue
            if ("index=" not in drive and idx == target_idx) or (
                f"index={target_idx}" in drive
            ):
                imgfile = drive.split("=")[1].split(",")[0]
                break
        return imgfile
    else:
        warn("append options are not checked")
    return None


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

    def print_msg(self, is_set):
        if is_set is None:
            warn(f"{self.name} is not checked")
            return
        if is_set:
            if self.is_config_set_desired:
                info(self.msg_if_set)
            else:
                warn(self.msg_if_set)
        else:
            if self.is_config_set_desired:
                warn(self.msg_if_not_set)
            else:
                info(self.msg_if_not_set)

    def check_kconfig(self, configs):
        self.print_msg(f"{self.name}=y" in configs)

    def check_vmlinux(self):
        self.print_msg(self._check_vmlinux())

    def _check_vmlinux(self):
        return None

    def gdb_exec(self, cmd):
        try:
            gdb = "gdb" if "x86" in ctx.arch else "gdb-multiarch"
            MAGICSTR = '"hi"'
            res = runcmd(
                gdb,
                "-batch",
                "-ex",
                f'file "{ctx.vmlinux.get()}"',
                "-ex",
                f"print {MAGICSTR}",
                "-ex",
                cmd,
                verbose=False,
            )
            if MAGICSTR not in res:
                warn("Something went terribly wrong while running gdb")
                return self.NOSYMBOL
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
        return "$2 = 0x2" in self.gdb_exec(
            "p/x *(int *)&sysctl_unprivileged_bpf_disabled"
        )


class RandStruct(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_RANDSTRUCT"
        self.is_config_set_desired = False
        self._msg_if_set = "marked structures are randomized"
        self._msg_if_not_set = "marked structures are NOT randomized"

    def _check_vmlinux(self):
        out = self.gdb_exec("p/x *(long *)&tainted_mask")
        return self.NOSYMBOL not in out and "$2 = 0x0" not in out


class RandomKmallocCaches(KernelConfig):
    def __init__(self):
        self.name = "CONFIG_RANDOM_KMALLOC_CACHES"
        self.is_config_set_desired = False
        self._msg_if_set = "multiple copies of slab caches are used for normal kmalloc"
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
        return self.NOSYMBOL not in self.gdb_exec("p/x &memcg_to_vmpressure")


def check_kconfig(configs):
    kconfig = open(ctx.config.get(), "r").read()
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
    important("Checking kernel configs")
    if ctx.config.get():
        check_kconfig(configs)
    else:
        vmlinux_info = runcmd("file", ctx.vmlinux.get())
        if "not stripped" not in vmlinux_info:
            error("vmlinux does not contain kernel symbols")
        check_vmlinux(configs)
