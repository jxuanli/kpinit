import os
import tempfile
import shutil
import subprocess
import json

BOOTFILE_TEMPLATE = """#!/bin/bash
{} \\
  -kernel {} \\
  -nographic \\
  -append {} \\
  -drive "file={},if=virtio,format=qcow2" \\
  -gdb tcp::1234
"""

ANSI_BRIGHT_GREEN = "\u001b[32;1m"
ANSI_YELLOW = "\u001b[33m"
ANSI_BLUE = "\u001b[34m"
ANSI_RED = "\u001b[31m"
ANSI_RESET = "\u001b[0m"

tested_configs = (
    "CONFIG_STATIC_USERMODEHELPER",
    "CONFIG_SLAB_MERGE_DEFAULT",
    "CONFIG_SLAB_FREELIST_HARDENED",
    "CONFIG_SLAB_FREELIST_RANDOM",
    "CONFIG_HARDENED_USERCOPY",
    "CONFIG_BPF_UNPRIV_DEFAULT_OFF",
    "CONFIG_RANDSTRUCT",
    "CONFIG_RANDOM_KMALLOC_CACHES",
    "CONFIG_MEMCG",
)

def important(s):
    return f"{ANSI_BRIGHT_GREEN}{s}{ANSI_RESET}"

def error(s):
    return f"{ANSI_RED}{s}{ANSI_RESET}"

def abspath(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)

def prep_tmp_workspace(tmpdir, vmlinux, add_vmlinux=True):
    arch = vmlinux.split("-")[-1]
    qemu, cmdline, drive, image_type = None, None, None, None
    if arch == "x86_64":
        qemu = "qemu-system-x86_64"
        cmdline = "8250.nr_uarts=1 console=ttyS0 root=/dev/vda"
        image_type = "bzImage"
    elif arch == "arm64":
        qemu = "qemu-system-aarch64"
        cmdline = "console=ttyAMA0 root=/dev/vda"
        image_type = "Image"
    for fname in os.listdir(abspath("kernel_images")):
        if fname.endswith(f"-{arch}.img"):
            drive = fname
    assert qemu and drive, "unexpected arch"
    kernel_image = f"{image_type}-{vmlinux[len('vmlinux-'):]}"
    f = open(os.path.join(tmpdir, "run.sh"), "w")
    f.write(BOOTFILE_TEMPLATE.format(qemu, kernel_image, cmdline, drive))
    kernel_image = abspath("kernel_images/" + kernel_image)
    shutil.copy2(kernel_image, tmpdir)
    if add_vmlinux:
        vmlinux = abspath("kernel_images/" + vmlinux)
        shutil.copy2(vmlinux, tmpdir)
    drive = abspath("kernel_images/" + drive)
    shutil.copy2(drive, tmpdir)

def check_output(configs, output):
    for config in configs["enable"].split():
        if config not in tested_configs:
            continue
        if f"{config} is set" not in output:
            print(error(f"{config} is not set when should be set. FAIL"))
            return False
    for config in configs["disable"].split():
        if config not in tested_configs:
            continue
        if f"{config} is not set" not in output:
            print(error(f"{config} is set when should not be set. FAIL"))
            return False
    return True

tmpdir = tempfile.mkdtemp()
kernel_configs = {}
for configs in json.load(open(abspath("kernel_images/configs.json"), "r")):
    vmlinux = f"vmlinux-linux-{configs['version']}-{configs['arch']}"
    kernel_configs[vmlinux] = configs

for fname in os.listdir(abspath("kernel_images")):
    if fname.startswith("vmlinux"):
        assert fname in kernel_configs, error(f"cannot find configs for {fname}, FAIL")
        dir = os.path.join(tmpdir, fname[len("vmlinux-"):])
        os.mkdir(dir)
        prep_tmp_workspace(dir, fname)
        os.chdir(dir)
        print(important(f"Checking {fname} ..."))
        result = subprocess.run(["python3", abspath("../kpinit.py")], capture_output=True, text=True).stdout
        if not check_output(kernel_configs[fname], result):
            print(result)
            exit(1)
        print(f"{important('PASS')}")
        # # there are some issues with vmlinux-to-elf
        # dir = dir + "-novmlinux"
        # os.mkdir(dir)
        # prep_tmp_workspace(dir, fname, False)
        # os.chdir(dir)
        # print(important(f"Checking {fname} (no vmlinux) ..."))
        # result = subprocess.run(["python3", abspath("../kpinit.py")], capture_output=True, text=True).stdout
        # if not check_output(kernel_configs[fname], result):
        #     print(result)
        #     exit(1)
        # print(f"{important('PASS')}")
