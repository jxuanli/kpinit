import os
import shutil
import subprocess
from utils import logger, ctx


def decompress_ramfs():
    if ctx.ramfs.get() is None:
        return
    shutil.copy2(ctx.ramfs.get(), ctx.ramfs.wspath)
    fsname = ctx.fsname()
    ram_path = ctx.challdir(fsname)
    os.mkdir(ram_path)
    archive_path = os.path.join(ram_path, fsname + ".cpio.gz")
    shutil.copy(ctx.ramfs.get(), archive_path)
    cpio_fpath = os.path.join(ram_path, fsname + ".cpio")
    prev = os.getcwd()
    os.chdir(ram_path)
    subprocess.run(["gunzip", archive_path])
    if not os.path.isfile(cpio_fpath):
        logger.error("Missing cpio: " + cpio_fpath)
    subprocess.run([f"cpio -idm < {cpio_fpath}"], shell=True)
    os.remove(cpio_fpath)
    os.chdir(prev)


def extract_init():
    if ctx.ramfs.wspath is not None:
        init_fpath = ctx.challdir(f"{ctx.fsname()}/init")
        if os.path.isfile(init_fpath):
            shutil.copy(init_fpath, ctx.expdir("init"))
        else:
            logger.warn("did not find init file")


def extract_ko():
    if ctx.vuln_ko.get() is not None:
        shutil.copy2(ctx.vuln_ko.get(), ctx.vuln_ko.wspath)
        return
    if ctx.ramfs.get() is None:
        return
    mods = []
    for dir, _, files in os.walk(ctx.rootdir()):
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
    ctx.vuln_ko.set(mod)
    shutil.copy2(ctx.vuln_ko.get(), ctx.vuln_ko.wspath)


def extract_vmlinux():
    out = b""
    vmlinux_path = ctx.rootdir("vmlinux")
    if ctx.vmlinux.get() is None:
        if shutil.which("vmlinux-to-elf") is not None:
            logger.info("Extracting vmlinux...")
            out = subprocess.run(
                ["vmlinux-to-elf", ctx.image.wspath, vmlinux_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            ).stdout
            if b"Successfully wrote the new ELF kernel" in out:
                logger.info("extracted vmlinux with vmlinux-to-elf")
                ctx.vmlinux.set(vmlinux_path)
    if ctx.vmlinux.get() is None:
        # fallback
        logger.warn(f"extracting vmlinux with vmlinux-to-elf failed: {out}")
        out = subprocess.check_output(
            [
                os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), "extract-vmlinux"
                ),
                ctx.image.wspath,
            ]
        )
        if len(out) < 0x100:
            logger.error("Failed to extract vmlinux")
        f = open(vmlinux_path, "wb")
        f.write(out)
        ctx.vmlinux.set(vmlinux_path)
        logger.info("Extracted vmlinux with extract-vmlinux")

    shutil.copy2(ctx.vmlinux.get(), ctx.vmlinux.wspath)
    try:
        logger.info("Finding original linux source path...")
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
            ctx.build_path.setval(path)
            logger.info(f"Found original linux source path at {path}")
            return
    except subprocess.CalledProcessError as e:
        logger.error(f"Error: {e}")
    logger.warn("Could not find riginal linux source path")


def copy_efiles():
    efiles = ctx.extra_files.get()
    if efiles is None:
        return
    for fpath in efiles:
        if os.path.exists(fpath):
            new_fpath = ctx.expdir(fpath.split("/")[-1])
            shutil.copy2(fpath, new_fpath)


def extract_context():
    """
    generate context.json file if does not exist, otherwise use the existing settings
    """
    if not ctx.load():
        for fname in os.listdir(ctx.rootdir()):
            if fname.endswith(".ko"):
                ctx.vuln_ko.set(ctx.rootdir(fname))
            elif "Image" in fname or "vmlinuz" in fname:
                ctx.image.set(ctx.rootdir(fname), notnone=True)
            elif "vmlinux" in fname:
                ctx.vmlinux.set(ctx.rootdir(fname))
                vmlinux_info = subprocess.run(
                    ["file", ctx.vmlinux.get()],
                    stdout=subprocess.PIPE,
                    text=True,
                ).stdout
                ctx.arch = "x86-64"
                if "aarch64" in vmlinux_info:
                    ctx.arch = "aarch64"
            elif fname.endswith(".qcow2") or fname.endswith(".img"):
                ctx.add_efile(fname)
            elif fname.endswith(".sh"):
                ctx.run_sh.set(ctx.rootdir(fname), notnone=True)
            elif "linux" in fname and os.path.isdir(ctx.rootdir(fname)):
                ctx.linux_src.set(ctx.rootdir(fname))
            elif "cpio" in fname or "gz" in fname:
                ctx.ramfs.set(ctx.rootdir(fname))
            elif "config" in fname:
                ctx.config.set(ctx.rootdir(fname))
    logger.important(ctx)
    ctx.check()
