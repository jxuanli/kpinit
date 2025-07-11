import os
import subprocess
from utils import logger, ctx
from checks import check_qemu_options
import shutil

QEMU_MAGIC = "qemu-system-"
HEADER = """#!/bin/sh
"""
OPTIONS = """
NOKASLR=""
GDB=""
PORT=1234
while [ $# -gt 0 ]; do
  case "$1" in
  --gdb)
    GDB="yes"
    ;;
  --port)
    shift
    PORT="$1"
    # https://stackoverflow.com/questions/12968093/regex-to-validate-port-number
    re="^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
    if [[ ! $PORT =~ $re ]]; then
      echo "port needs to be a numeric number between 0 and 65535."
      exit 1
    fi
    ;;
  --nokaslr)
    NOKASLR="nokaslr"
    ;;
  *)
    FILENAME="$1"
    ;;
  esac
  shift
done
"""
COMPILE_EXPLOIT = (
    "{} ./exploit.c ./util/io_helpers.c ./util/general.c -g -o ./exploit -static"
)
CPIO_SCRIPT = """
if [ $? -ne 0 ]; then
  echo "failed on compiling exploit script"
  exit 1
fi
fsname="{}"
compressedfs="{}"
cp ./exploit ../challenge/$fsname/exploit
cp ./init ../challenge/$fsname/init
cd ../challenge/$fsname
find . -print0 |
  cpio --null -ov --format=newc |
  gzip -9 -q >$compressedfs
cd -
"""
GDB_CMD = """
sed -i "s/^target remote localhost:.*/target remote localhost:$PORT/" {}
if [ "$GDB" = "yes" ]; then
  if type zellij >/dev/null 2>&1; then
    zellij action new-pane -d right -c -- bash -c "sleep 3; {}"
  elif type tmux >/dev/null 2>&1; then
    tmux split-window -h -c "#{{pane_current_path}}" "bash -c 'sleep 3; {}'"
  fi
fi
"""


def get_qemu_options(command):
    """
    @command: a valid qemu command
    @return: list of options, a map with their corresponding values of the qemu command
    """
    parts = command.split()
    opts = {}
    i = 1  # skip the qemu bin name
    while i < len(parts):
        if not parts[i].startswith("-"):
            return None
        option = parts[i][1:]
        token = ""
        i += 1
        while i < len(parts) and not parts[i].startswith("-"):
            token += parts[i] + " "
            i += 1
        if option == "kernel":
            token = ctx.image.wspath
        elif option == "hda":
            token = ctx.qcow.wspath
        elif option == "append":
            token = token.replace("'", "").replace('"', "")
            token = f'"{token} $NOKASLR"'
        elif option == "initrd":
            token = ctx.ramfs.wspath
        elif option == "s" or option == "S":
            continue
        opts[option] = token.strip()
    return opts


def get_qemu_arch(command):
    """
    @command: a valid qemu command
    @return: the architecture used for the vm
    """
    bin = command.split()[0]
    if not bin.startswith(QEMU_MAGIC):
        logger.error("cannot find `qemu-system-` prefix")
    return bin[len(QEMU_MAGIC) :]


def get_qemu_cmd(file_bs):
    """
    @file_bs: the content of a file (run.sh)
    @return: the qemu command
    """
    idx = file_bs.find(QEMU_MAGIC)
    if idx < 0:
        logger.error("can't find qemu_magic in provided file content")
    return file_bs[idx:]


def mod_qemu_options(options):
    has_kernel = False
    for opt, _ in options.items():
        if opt == "kernel":
            has_kernel = True
    if not has_kernel:
        logger.error("kernel should be one of the tokens but is not")
    options["gdb"] = "tcp::$PORT"


def gen_launch():
    """
    @assume: the directory structure in README.md has been created
    @effect: generate the launch.sh file
                since this parses the run.sh, it will check the interesting qemu options
                **checks SMAP, SMEP, KPTI, KASLR, and panic_on_oops**
    """
    runsh_fpath = ctx.run_sh.get()
    launch_fpath = ctx.expdir("launch.sh")
    f = open(runsh_fpath, "r")
    content = f.read()
    qemu_cmd = get_qemu_cmd(content).replace("\\", " ")
    opts = get_qemu_options(qemu_cmd)
    if opts is None:
        logger.warn("Unexpected boot script format detected.")
        shutil.copy2(runsh_fpath, launch_fpath)
        return
    mod_qemu_options(opts)
    vmlinux_info = subprocess.run(
        ["file", ctx.vmlinux.wspath], stdout=subprocess.PIPE, text=True
    ).stdout
    script = HEADER
    script += OPTIONS
    compiler = "gcc"
    if "aarch64" in vmlinux_info:
        compiler = "aarch64-linux-gnu-gcc"
    script += COMPILE_EXPLOIT.format(compiler)
    if ctx.ramfs.wspath is not None:
        script += CPIO_SCRIPT.format(ctx.fsname(), ctx.ramfs.wspath)
    gdb = "gdb" if "x86" in vmlinux_info else "gdb-multiarch"
    gdb += f" -ix {ctx.challdir('debug.gdb')}"
    script += GDB_CMD.format(ctx.challdir("debug.gdb"), gdb, gdb)
    script += qemu_cmd.split()[0] + " "
    for option, token in opts.items():
        script += "\\\n\t" + "-" + option + " " + token + " "

    f = open(launch_fpath, "w")
    f.write(script)
    os.chmod(launch_fpath, 0o700)

    check_qemu_options(opts)
