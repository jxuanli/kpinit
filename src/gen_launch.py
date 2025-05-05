import os
from utils import logger, ctx
from checks import check_qemu_options

QEMU_MAGIC = "qemu-system-"
HEADER = """#!/bin/sh
"""
OPTIONS = """
NOKASLR=""
GDB = ""
while [ $# -gt 0 ]; do
  case "$1" in
  --gdb)
    GDB="yes"
    ;;
  --debug)
    NOKASLR="nokaslr"
    ;;
  *)
    FILENAME="$1"
    ;;
  esac
  shift
done

gcc ./exploit.c ./util/io_helpers.c ./util/general.c ./util/kheap.c -g -o ./exploit -static
"""
CPIO_SCRIPT = """
if [ $? -ne 0 ]; then
  echo "failed on compiling exploit script"
  exit 1
fi
fsname="{}"
cp ./exploit ../challenge/$fsname/exploit
cp ./init ../challenge/$fsname/init
cd ../challenge/$fsname
find . -print0 |
  cpio --null -ov --format=newc |
  gzip -9 -q >$fsname.cpio.gz
mv ./$fsname.cpio.gz ../
cd -
"""
GDB_CMD = """
if [ "$GDB" = "yes" ]; then
  if type zellij >/dev/null 2>&1; then
    zellij action new-pane -d right -c -- bash -c "sleep 3; gdb {}"
  elif type tmux >/dev/null 2>&1; then
    tmux split-window -h -c "#{{pane_current_path}}" "bash -c 'sleep 3; gdb {}'"
  fi
fi
"""


def get_qemu_options(command):
    """
    @command: a valid qemu command
    @return: list of options, a map with their corresponding values of the qemu command
    """
    parts = command.split()
    tokens = {}
    opts = []
    i = 1  # skip the qemu bin name
    while i < len(parts):
        assert parts[i].startswith("-"), (
            "more qemu args to parse but no option is specified"
        )
        option = parts[i][1:]
        i += 1
        assert option not in tokens, "duplicate option seen in qemu command"
        tokens[option] = ""
        opts.append(option)
        while i < len(parts) and not parts[i].startswith("-"):
            tokens[option] += parts[i] + " "
            i += 1
        tokens[option] = tokens[option].strip()
    return opts, tokens


def get_qemu_arch(command):
    """
    @command: a valid qemu command
    @return: the architecture used for the vm
    """
    bin = command.split()[0]
    assert bin.startswith(QEMU_MAGIC)
    return bin[len(QEMU_MAGIC) :]


def get_qemu_cmd(file_bs):
    """
    @file_bs: the content of a file (run.sh)
    @return: the qemu command
    """
    idx = file_bs.find(QEMU_MAGIC)
    assert idx > -1, "can't find qemu_magic in provided file content"
    return file_bs[idx:]


def gen_launch():
    """
    @assume: the directory structure in README.md has been created
    @effect: generate the launch.sh file
                since this parses the run.sh, it will check the interesting qemu options
                **checks SMAP, SMEP, KPTI, KASLR, and panic_on_oops**
    """
    runsh_fpath = ctx.get_path_root(ctx.RUN_SH)
    f = open(runsh_fpath, "r")
    content = f.read()
    qemu_cmd = get_qemu_cmd(content).replace("\\", " ")
    opts, tokens = get_qemu_options(qemu_cmd)

    if "s" not in tokens:  # enable debug
        tokens["s"] = ""
        opts.append("s")

    # adjust kernel and initrd

    if "kernel" not in tokens:
        logger.error("kernel should be one of the tokens but is not")
    tokens["kernel"] = ctx.get_path(ctx.BZIMAGE)
    script = HEADER
    script += OPTIONS
    if ctx.get_path(ctx.RAMFS) is not None:
        tokens["initrd"] = ctx.get_path(ctx.RAMFS)
        script += CPIO_SCRIPT.format(ctx.fsname())
    if ctx.get_path(ctx.QCOW) is not None:
        tokens["hda"] = ctx.get_path(ctx.QCOW)
    ignore_gdbinit = ""
    if ctx.get(ctx.GDB_PLUGIN) is not None:
        ignore_gdbinit = f"-nx "
    ignore_gdbinit += f"-x {ctx.challenge_path('debug.gdb')}"
    script += GDB_CMD.format(ignore_gdbinit, ignore_gdbinit)
    tokens["append"] = tokens["append"][:-1] + ' $NOKASLR"'
    script += qemu_cmd.split()[0] + " "
    for option in opts:
        assert option in tokens
        script += "\\\n\t" + "-" + option + " " + tokens[option] + " "

    script += "\n\n\nsetterm -linewrap on"  # TODO:
    launch_fpath = ctx.exploit_path("launch.sh")
    f = open(launch_fpath, "w")
    f.write(script)
    os.chmod(launch_fpath, 0o700)

    check_qemu_options(tokens)
