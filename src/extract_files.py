import os
import shutil
import subprocess
from utils import info, warn, error, important, ctx, runcmd


def decompress_ramfs():
    if ctx.ramfs.get() is None:
        return
    shutil.copy2(ctx.ramfs.get(), ctx.ramfs.wspath)
    fsname = ctx.fsname()
    ram_path = ctx.challdir(fsname)
    os.mkdir(ram_path)
    archive_path = os.path.join(ram_path, fsname + ".cpio.gz")
    cpio_fpath = os.path.join(ram_path, fsname + ".cpio")
    prev = os.getcwd()
    os.chdir(ram_path)
    if ctx.ramfs.get().endswith(".gz"):
        shutil.copy(ctx.ramfs.get(), archive_path)
        runcmd("gunzip", archive_path, fail_on_error=True)
    else:
        shutil.copy(ctx.ramfs.get(), cpio_fpath)
    if not os.path.isfile(cpio_fpath):
        error("Missing cpio: " + cpio_fpath)
    f = open(cpio_fpath, "rb")
    subprocess.run(["cpio", "-idm"], stdin=f, check=True)
    os.remove(cpio_fpath)
    os.chdir(prev)


def extract_init():
    if ctx.ramfs.wspath is not None:
        init_fpath = ctx.challdir(f"{ctx.fsname()}/init")
        if os.path.isfile(init_fpath):
            shutil.copy(init_fpath, ctx.expdir("init"))
        else:
            warn("Did not find init file")


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
            info(f"Modules: {mods}")
            warn(
                f"Detected multiple loadable modules, select which one (default: {mod.split('/')[-1]}) ❱"
            )
            mod_end = input()
            for m in mods:
                if m.endswith(mod_end):
                    mod = m
                    break
    if mod is None or not os.path.exists(mod):
        warn("No kernel loadable modules found")
        return
    ctx.vuln_ko.set(mod)
    shutil.copy2(ctx.vuln_ko.get(), ctx.vuln_ko.wspath)


def extract_vmlinux():
    out = b""
    vmlinux_path = ctx.wsdir("vmlinux")  # path used if vmlinux is not provided
    if vmlinux_path is not None and os.path.exists(vmlinux_path):
        # optimization -- avoid repeated vmlinux generation
        ctx.vmlinux.set(vmlinux_path)
        ctx.update_arch()
    if ctx.vmlinux.get() is None:
        if shutil.which("vmlinux-to-elf") is not None:
            info("Extracting vmlinux... (might take a minute)")
            out = runcmd("vmlinux-to-elf", ctx.image.get(), vmlinux_path)
            if out is not None and "Successfully wrote the new ELF kernel" in out:
                info("Extracted vmlinux with vmlinux-to-elf")
                ctx.vmlinux.set(vmlinux_path)
                ctx.update_arch()
    if ctx.vmlinux.get() is None:
        # fallback
        warn(f"Extracting vmlinux with vmlinux-to-elf failed: {out}")
        out = runcmd(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "extract-vmlinux"),
            ctx.image.get(),
        )
        if len(out) < 0x100:
            error("Failed to extract vmlinux")
        f = open(vmlinux_path, "wb")
        f.write(out)
        ctx.vmlinux.set(vmlinux_path)
        ctx.update_arch()
        info("Extracted vmlinux with extract-vmlinux")
    info("Finding original linux source path...")
    out = runcmd("readelf", "--debug-dump=info", ctx.vmlinux.get())
    if out is not None:
        path = None
        for line in out.splitlines():
            if "DW_AT_comp_dir" in line:
                path = line.strip().split(" ")[-1]
        if path and len(path) > 0:
            ctx.build_path.setval(path)
            info(f"Found original linux source path at {path}")
            return
    warn("Could not find original linux source path")


def extract_context():
    """
    generate context.json file if does not exist, otherwise use the existing settings
    """
    if not ctx.load():
        info("Creating ./workspace/context.json")
        for fname in os.listdir(ctx.rootdir()):
            if fname.endswith(".ko"):
                ctx.vuln_ko.set(ctx.rootdir(fname))
            elif "Image" in fname or "vmlinuz" in fname:
                ctx.image.set(ctx.rootdir(fname), notnone=True)
                ctx.update_arch()
            elif "vmlinux" in fname and b"\x7fELF" == open(fname, "rb").read(4):
                ctx.vmlinux.set(ctx.rootdir(fname))
                ctx.update_arch()
            elif (
                os.path.isfile(fname)
                and (
                    fname.endswith(".sh")
                    or any(name in fname for name in ["start", "run", "launch"])
                )
                and open(fname, "rb").read(0x1000)
            ):
                ctx.run_sh.set(ctx.rootdir(fname), notnone=True)
            elif "linux" in fname and os.path.isdir(ctx.rootdir(fname)):
                ctx.linux_src.set(ctx.rootdir(fname))
            elif "cpio" in fname or "gz" in fname:
                ctx.ramfs.set(ctx.rootdir(fname))
            elif "config" in fname:
                ctx.config.set(ctx.rootdir(fname))
    else:
        info("Reusing existing ./workspace/context.json")
    important(ctx)
    ctx.check()
