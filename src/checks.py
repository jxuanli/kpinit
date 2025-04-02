from utils import logger, ctx
import subprocess


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


def check_kernel_config():
    assert False, "not implemented"  # TODO:


def check_vmlinux():
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
    configs = {  # TODO:
        "RANDOM_KMALLOC_CACHES": None,
        "FUSE_FS": None,
        "HARDENED_USERCOPY": None,
        "SLAB_FREELIST_RANDOM": None,
    }
    for c, funcs in configs.items():
        if funcs is None:
            logger.warn(f"{c} is not checked")
            continue
        for func in funcs:
            if func in symbols:
                logger.warn(f"{c} is enabled")
                continue
        logger.info(f"{c} is disabled")
    # TODO: checks with disassembly:
    # check SLAB_FREELIST_HARDENED
    # check STATIC_USERMODEHELPER


def check_config():
    """
    check mitigations from .config if exists, otherwise checks vmlinux
    """
    logger.important("Checking kernel configs")
    if ctx.get(ctx.CONFIG):
        check_kernel_config()
    else:
        check_vmlinux()
