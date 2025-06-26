import os, shutil, subprocess
from utils import logger, ctx


def decompress_ramfs():
    if ctx.get(ctx.RAMFS) is None:
        return
    shutil.copy2(ctx.get_path_root(ctx.RAMFS), ctx.get_path(ctx.RAMFS))
    fsname = ctx.fsname()
    ram_path = ctx.challenge_path(fsname)
    os.mkdir(ram_path)
    archive_path = os.path.join(ram_path, fsname + ".cpio.gz")
    shutil.copy(ctx.get_path_root(ctx.RAMFS), archive_path)
    cpio_fpath = os.path.join(ram_path, fsname + ".cpio")
    prev = os.getcwd()
    os.chdir(ram_path)
    subprocess.run(["gunzip", archive_path])
    assert os.path.isfile(cpio_fpath), "missing cpio: " + cpio_fpath
    subprocess.run([f"cpio -idm < {cpio_fpath}"], shell=True)
    os.remove(cpio_fpath)
    os.chdir(prev)


def extract_init():
    if ctx.get_path(ctx.RAMFS) is not None:
        init_fpath = ctx.challenge_path(f"{ctx.fsname()}/init")
        if os.path.isfile(init_fpath):
            shutil.copy(init_fpath, ctx.exploit_path("init"))
        else:
            logger.warn("did not find init file")


def extract_ko():
    if ctx.get_path_root(ctx.VULN_KO) is not None:
        shutil.copy2(ctx.get_path_root(ctx.VULN_KO), ctx.get_path(ctx.VULN_KO))
        return
    if ctx.get(ctx.RAMFS) is None:
        return
    mods = []
    for dir, _, files in os.walk(ctx.root_path()):
        for file in files:
            if file.endswith(".ko") and file not in mods:
                mods.append(os.path.join(dir, file))
    mod = None
    if len(mods) > 0:
        mod = mods[0]
        if len(mods) > 1:
            logger.info(f"modules: {mods}")
            logger.warn("detected multiple loadable modules, select which one ❱")
            mod_substr = input()
            for m in mods:
                if mod_substr in m:
                    mod = m
                    break
    if mod is None or not os.path.exists(mod):
        logger.warn("no kernel loadable modules found")
        return
    ctx.set(ctx.VULN_KO, mod)
    shutil.copy2(ctx.get_path_root(ctx.VULN_KO), ctx.get_path(ctx.VULN_KO))


def extract_vmlinux():
    out = b""
    if ctx.get_path_root(ctx.VMLINUX) is None:
        vmlinux_path = ctx.root_path("vmlinux")
        if shutil.which('vmlinux-to-elf') is not None:
            logger.info("Extracting vmlinux...")
            out = subprocess.run(['vmlinux-to-elf', ctx.get_path(ctx.BZIMAGE), vmlinux_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout            
            if b"Successfully wrote the new ELF kernel" in out:
                logger.info("extracted vmlinux with vmlinux-to-elf")
                ctx.set_path(ctx.VMLINUX, vmlinux_path)
    if ctx.get_path_root(ctx.VMLINUX) is None:
        # fallback
        logger.warn(f"extracting vmlinux with vmlinux-to-elf failed: {out}")
        out = subprocess.check_output([os.path.join(os.path.dirname(os.path.abspath(__file__)), "extract-vmlinux"), ctx.get_path(ctx.BZIMAGE)])
        vmlinux_path = ctx.root_path("vmlinux")
        f = open(vmlinux_path, "wb")
        f.write(out)
        ctx.set_path(ctx.VMLINUX, vmlinux_path)
        logger.info("extracted vmlinux with extract-vmlinux")

    shutil.copy2(ctx.get_path_root(ctx.VMLINUX), ctx.get_path(ctx.VMLINUX))       
    try:
        path = subprocess.run(
            f"readelf --debug-dump=info {ctx.get_path(ctx.VMLINUX)} | grep -m 1 'DW_AT_comp_dir'",
            shell=True,
            capture_output=True,
            text=True
        ).stdout.strip().split(" ")[-1]
        if path and len(path) > 0:
            ctx.set(ctx.ORIG_LINUX_PATH, path)
            logger.info(f"found original linux source path at {path}")
            return
    except subprocess.CalledProcessError as e:
        logger.error(f"Error: {e}")
    logger.warn("did not find the path in which the kernel is compiled")

def extract_context():
    """
    generate settings.json file if does not exist, otherwise use the existing settings
    """
    if not ctx.load():
        ctx.set_path(ctx.LIBSLUB, os.path.expanduser("~/Tools/libslub/libslub.py"))
        ctx.set_path(
            ctx.GDB_PLUGIN, os.path.expanduser("~/Documents/pwndbg/gdbinit.py")
        )
        for fname in os.listdir(os.getcwd()):
            if fname.endswith(".ko"):
                ctx.set_path(ctx.VULN_KO, ctx.root_path(fname))
            elif "bzImage" in fname or "vmlinuz" in fname:
                ctx.set_path(ctx.BZIMAGE, ctx.root_path(fname), True)
            elif "vmlinux" in fname:
                ctx.set_path(ctx.VMLINUX, ctx.root_path(fname))
            elif fname.endswith(".qcow2") or fname.endswith(".img"):
                ctx.set_path(ctx.QCOW, ctx.root_path(fname))
            elif fname.endswith(".sh"):
                ctx.set_path(ctx.RUN_SH, ctx.root_path(fname), True)
            elif "linux" in fname and os.path.isdir(ctx.root_path(fname)):
                ctx.set_path(ctx.LINUX_SRC, ctx.root_path(fname))
            elif "cpio" in fname or "gz" in fname:
                ctx.set_path(ctx.RAMFS, ctx.root_path(fname))
            elif "config" in fname:
                ctx.set_path(ctx.CONFIG, ctx.root_path(fname))
    logger.important(ctx)
    ctx.check()


def extract_qcow():
    imgpath = ctx.get(ctx.QCOW)
    if imgpath is None:
        return
    shutil.copy2(imgpath, ctx.challenge_path())
