import os, shutil, subprocess
from utils import logger, ctx


def decompress_ramfs():
    ram_path = ctx.challenge_path("initramfs")
    os.mkdir(ram_path)
    archive_path = os.path.join(ram_path, ctx.RAMFS)
    shutil.copy(ctx.get_path_root(ctx.RAMFS), archive_path)
    cpio_fpath = ctx.challenge_path(f"{ctx.RAMFS.split('.')[0]}/initramfs.cpio")
    prev = os.getcwd()
    os.chdir(ram_path)
    subprocess.run(["gunzip", archive_path])
    assert os.path.isfile(cpio_fpath), "missing cpio: " + cpio_fpath
    subprocess.run([f"cpio -idm < {cpio_fpath}"], shell=True)
    os.remove(cpio_fpath)
    os.chdir(prev)


def extract_init():
    init_fpath = ctx.challenge_path("initramfs/init")
    if os.path.isfile(init_fpath):
        shutil.copy(init_fpath, ctx.exploit_path("init"))
    else:
        logger.warn("did not find init file")


def extract_ko():
    if ctx.get_path_root(ctx.VULN_KO) is not None:
        shutil.copy2(ctx.get_path_root(ctx.VULN_KO), ctx.get_path(ctx.VULN_KO))
        return
    mods = []
    for _, _, files in os.walk(ctx.root_path()):
        for file in files:
            if file.endswith(".ko"):
                mods.append(file)
    mod = None
    if len(mods) > 0:
        mod = mods[0]
        if len(mods) > 1:
            logger.warn("detected multiple loadable modules, select which one ❱")
            mod_substr = input()
            for m in mods:
                if mod_substr in m:
                    mod = m
                    break
    if mod is None or not os.path.exists(ctx.ctx.root_path(mod)):
        logger.warn("no kernel loadable modules found")
        return
    ctx.set(ctx.VULN_KO, mod)
    shutil.copy2(ctx.get_path_root(ctx.VULN_KO), ctx.get_path(ctx.VULN_KO))


def extract_vmlinux():
    if ctx.get_path_root(ctx.VMLINUX) is not None:
        shutil.copy2(ctx.get_path_root(ctx.VMLINUX), ctx.get_path(ctx.VMLINUX))
        return
    assert False, "not implemented"  # TODO:


def extract_context():
    """
    generate settings.json file if does not exist, otherwise use the existing settings
    """
    if not ctx.load():
        ctx.set_path(ctx.BZIMAGE, ctx.root_path(ctx.BZIMAGE), True)
        ctx.set_path(ctx.RUN_SH, ctx.root_path(ctx.RUN_SH), True)
        ctx.set_path(ctx.VMLINUX, ctx.root_path(ctx.VMLINUX))
        ctx.set_path(ctx.CONFIG, ctx.root_path(ctx.CONFIG))
        ctx.set_path(ctx.RAMFS, ctx.root_path(ctx.RAMFS))
        ctx.set_path(ctx.LIBSLUB, os.path.expanduser("~/Tools/libslub/libslub.py"))
        ctx.set_path(
            ctx.LIBKERNEL, os.path.expanduser("~/Tools/libkernel/libkernel.py")
        )
        for fname in os.listdir(os.getcwd()):
            if fname.endswith(".ko"):
                ctx.set_path(ctx.VULN_KO, ctx.root_path(fname))
                break
    logger.important(ctx)
    ctx.check()
