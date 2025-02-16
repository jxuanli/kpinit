import os
from utils import *
from checks import check_cpu_option, check_append_option

qemu_magic = "qemu-system-"
launch_header = """#!/bin/sh

gcc ./exploit.c -o ./exploit -static
mv ./exploit ../challenge/initramfs/exploit
cp ./init ../challenge/initramfs/init
cd ../challenge/initramfs
find . -print0 |
  cpio --null -ov --format=newc |
  gzip -9 -q >initramfs.cpio.gz
mv ./initramfs.cpio.gz ../

"""

"""
@command: a valid qemu command 
@return: list of options, a map with their corresponding values of the qemu command 
"""
def get_qemu_options(command):
    parts = command.split()
    tokens = {}
    opts = []
    i = 1 # skip the qemu bin name 
    while i < len(parts):
        assert parts[i].startswith('-'), "more qemu args to parse but no option is specified"
        option = parts[i][1:]
        i += 1
        assert option not in tokens, "duplicate option seen in qemu command"
        tokens[option] = ""
        opts.append(option)
        while i < len(parts) and not parts[i].startswith('-'):
            tokens[option] += parts[i] + " "
            i += 1
    return opts, tokens

"""
@command: a valid qemu command 
@return: the architecture used for the vm  
"""
def get_qemu_arch(command):
    bin = command.split()[0]
    assert bin.startswith(qemu_magic)
    return bin[len(qemu_magic):]


"""
@file_bs: the content of a file (run.sh)
@return: the qemu command
"""
def get_qemu_cmd(file_bs):
    idx = file_bs.find(qemu_magic)
    assert idx > -1, "can't find qemu_magic in provided file content"
    return file_bs[idx:]
        
"""
@assume: the directory structure in README.md has been created
@effect: generate the launch.sh file
            since this parses the run.sh, it will check the interesting qemu options
            **checks SMAP, SMEP, KPTI, KASLR, and panic_on_oops**
"""
def gen_launch():
    runsh_fpath = get_settings_fpath(RUN_SH)
    f = open(runsh_fpath, "r")
    content = f.read() 
    qemu_cmd = get_qemu_cmd(content).replace("\\" ," ")
    opts, tokens = get_qemu_options(qemu_cmd)

    if "cpu" in tokens:
        check_cpu_option(tokens["cpu"])
    else:
        check_cpu_option("")
    if "append" in tokens:
        check_append_option(tokens["append"])
    else:
        check_append_option("")

    if "s" not in tokens: # enable debug 
        tokens["s"] = ""
        opts.append("s")

    dir = os.path.dirname(runsh_fpath)
    # adjust kernel and initrd 
    tokens["kernel"] = os.path.join(dir, "workplace/challenge/bzImage") + " "
    tokens["initrd"] = os.path.join(dir, "workplace/challenge/initramfs.cpio.gz") + " "
    new_content = launch_header
    new_content += qemu_cmd.split()[0] + " "
    for option in opts:
        assert option in tokens
        new_content += "\\\n\t" + "-" + option + " " + tokens[option]

    new_content += "\n\n\nsetterm -linewrap on" # TODO:
    launch_fpath = os.path.join(dir, "workplace/exploit/launch.sh")
    f = open(launch_fpath, "w")
    f.write(new_content)
    os.chmod(launch_fpath, 0o700)









