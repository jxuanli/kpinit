import os
import shutil
import subprocess
from utils import logger, ctx


def decompress_ramfs():
    if ctx.ramfs.get() is None:
        return
    shutil.copy2(ctx.ramfs.origpath, ctx.ramfs.wspath)
    fsname = ctx.fsname()
    ram_path = ctx.challenge_path(fsname)
    os.mkdir(ram_path)
    archive_path = os.path.join(ram_path, fsname + ".cpio.gz")
    shutil.copy(ctx.ramfs.origpath, archive_path)
    cpio_fpath = os.path.join(ram_path, fsname + ".cpio")
    prev = os.getcwd()
    os.chdir(ram_path)
    subprocess.run(["gunzip", archive_path])
    assert os.path.isfile(cpio_fpath), "missing cpio: " + cpio_fpath
    subprocess.run([f"cpio -idm < {cpio_fpath}"], shell=True)
    os.remove(cpio_fpath)
    os.chdir(prev)


def extract_init():
    if ctx.ramfs.wspath is not None:
        init_fpath = ctx.challenge_path(f"{ctx.fsname()}/init")
        if os.path.isfile(init_fpath):
            shutil.copy(init_fpath, ctx.exploit_path("init"))
        else:
            logger.warn("did not find init file")


def extract_ko():
    if ctx.vuln_ko.origpath is not None:
        shutil.copy2(ctx.vuln_ko.origpath, ctx.vuln_ko.wspath)
        return
    if ctx.ramfs.get() is None:
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
    ctx.vuln_ko.set(mod, is_path=False)
    shutil.copy2(ctx.vuln_ko.origpath, ctx.vuln_ko.wspath)


def extract_vmlinux():
    out = b""
    if ctx.vmlinux.origpath is None:
        vmlinux_path = ctx.root_path("vmlinux")
        if shutil.which("vmlinux-to-elf") is not None:
            logger.info("Extracting vmlinux...")
            out = subprocess.run(
                ["vmlinux-to-elf", ctx.bzimage.wspath, vmlinux_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            ).stdout
            if b"Successfully wrote the new ELF kernel" in out:
                logger.info("extracted vmlinux with vmlinux-to-elf")
                ctx.vmlinux.set_path(vmlinux_path)
    if ctx.vmlinux.origpath is None:
        # fallback
        logger.warn(f"extracting vmlinux with vmlinux-to-elf failed: {out}")
        out = subprocess.check_output(
            [
                os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), "extract-vmlinux"
                ),
                ctx.bzimage.wspath,
            ]
        )
        vmlinux_path = ctx.root_path("vmlinux")
        f = open(vmlinux_path, "wb")
        f.write(out)
        # TODO: seems a bit awkward
        ctx.vmlinux.set(vmlinux_path)
        logger.info("extracted vmlinux with extract-vmlinux")

    shutil.copy2(ctx.vmlinux.origpath, ctx.vmlinux.wspath)
    try:
        path = (
            subprocess.run(
                f"readelf --debug-dump=info {ctx.vmlinux.wspath} | grep -m 1 'DW_AT_comp_dir'",
                shell=True,
                capture_output=True,
                text=True,
            )
            .stdout.strip()
            .split(" ")[-1]
        )
        if path and len(path) > 0:
            ctx.build_path.set(path, is_path=False)
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
        for fname in os.listdir(os.getcwd()):
            if fname.endswith(".ko"):
                ctx.vuln_ko.set(ctx.root_path(fname))
            elif "Image" in fname or "vmlinuz" in fname:
                ctx.image.set(ctx.root_path(fname), is_strict=True)
            elif "vmlinux" in fname:
                ctx.vmlinux.set(ctx.root_path(fname))
                vmlinux_info = subprocess.run(
                    ["file", ctx.vmlinux.get()],
                    stdout=subprocess.PIPE,
                    text=True,
                ).stdout
                ctx.arch = "x86-64"
                if "aarch64" in vmlinux_info:
                    ctx.arch = "aarch64"
                elif "riscv64" in vmlinux_info:
                    ctx.arch = "riscv64"
            elif fname.endswith(".qcow2") or fname.endswith(".img"):
                ctx.qcow.set(ctx.root_path(fname))
            elif fname.endswith(".sh"):
                ctx.run_sh.set(ctx.root_path(fname), is_strict=True)
            elif "linux" in fname and os.path.isdir(ctx.root_path(fname)):
                ctx.linux_src.set(ctx.root_path(fname))
            elif "cpio" in fname or "gz" in fname:
                ctx.ramfs.set(ctx.root_path(fname))
            elif "config" in fname:
                ctx.config.set(ctx.root_path(fname))
    logger.important(ctx)
    ctx.check()


def extract_qcow():
    imgpath = ctx.qcow.get()
    if imgpath is None:
        return
    shutil.copy2(imgpath, ctx.challenge_path())
