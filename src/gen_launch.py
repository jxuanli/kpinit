import os
import re
from utils import warn, error, ctx
from checks import check_qemu
import shutil
import argparse
import shlex

QEMU_MAGIC = "qemu-system-"
HEADER = """#!/bin/bash
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
COMPILE_EXPLOIT = """
{} ./exploit.c ./util/io_helpers.c ./util/general.c ./util/bpf.c -g -o ./exploit -static
if [ $? -ne 0 ]; then
  echo "failed on compiling exploit script"
  exit 1
fi
"""
CPIO_SCRIPT = """
fsname="{}"
compressedfs="{}"
cp ./exploit ../challenge/$fsname/exploit
cp ./init ../challenge/$fsname/init
cd ../challenge/$fsname
find . -print0 |
  cpio --null -ov --format=newc -R root:root |
  gzip -9 -q >$compressedfs
cd -
"""
QCOW_SCRIPT = """
guestfish --rw -a {} <<_EOF_
run
mount /dev/sda /
copy-in {} /
unmount /
quit
_EOF_
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

parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)


def get_qemu_cmd(file_bs):
    """
    @file_bs: the content of a file (run.sh)
    @return: the qemu command
    """
    idx = file_bs.find(QEMU_MAGIC)
    if idx < 0:
        error("Cannot find qemu_magic in provided file content.")
    return file_bs[idx:]


def replace_paths(m):
    path = m.group(0)
    if os.path.isabs(path):
        return path
    if not os.path.exists("./" + path):
        return path
    # relative path
    return ctx.rootdir(path)


def replace_append(m):
    quote = m.group(1)
    cmdline = m.group(2).strip()
    return f"-append {quote}{cmdline} $NOKASLR{quote}"


def replace_qemuline(line):
    pattern = re.compile(r"(?:\.\.?/|/)[\w./\-\+@%~]+")
    line = pattern.sub(replace_paths, line)
    pattern = re.compile(r"(?<!/)[a-zA-Z0-9.]+")
    line = pattern.sub(replace_paths, line)
    pattern = re.compile(r'-append\s+([\'"])([ -~]*?)\1')
    line = pattern.sub(replace_append, line)
    if ctx.ramfs.wspath is not None:
        pattern = re.compile(r"-initrd\s+[\w./\-\_\+@%~\"]+")
        line = pattern.sub(f"-initrd {ctx.ramfs.wspath}", line)
    for option in (
        "s",
        "gdb",
        "S",
    ):
        pattern = re.compile(rf"-{option}(?:\s|$)[^-]*")
        line = pattern.sub("", line)
    return line


def gen_qemu_cmd():
    # TODO: add previous
    f = open(ctx.run_sh.get(), "r")
    content = f.read()
    qemucmd = get_qemu_cmd(content)
    opts = ["append", "smp", "cpu", "hda", "hdb", "hdc", "hdd"]
    opts_append = ["drive"]
    for opt in opts:
        parser.add_argument(f"-{opt}")
    for opt in opts_append:
        parser.add_argument(f"-{opt}", action="append")
    parser.add_argument("-s", action="store_true")
    parsed, _ = parser.parse_known_args(shlex.split(qemucmd))
    imgfile = check_qemu(parsed)
    if imgfile is not None and (fsimgs := ctx.fsimgs.get()) is not None:
        for img in fsimgs:
            if os.path.basename(imgfile) == os.path.basename(img):
                ctx.fsimg.set(ctx.rootdir(img))
    else:
        warn("Could not find root filesystem image")
    realcmd = ""
    for line in qemucmd.splitlines():
        line = line.strip()
        islast = "\\" != line[-1]
        if not islast:
            line = line[:-1]
            line = line.strip()
        line = replace_qemuline(line)
        if len(line) != 0:
            if len(realcmd) == 0:
                realcmd += line + " \\\n"
            else:
                realcmd += "\t" + line + " \\\n"
            if not islast:
                continue
        if islast:
            realcmd += "\t-gdb tcp::$PORT \n"
            break
    # TODO: add the remaining lines
    return realcmd


def gen_launch():
    """
    @assume: the directory structure in README.md has been created
    @effect: generate the launch.sh file
                since this parses the run.sh, it will check the interesting qemu options
                **checks SMAP, SMEP, KPTI, KASLR, panic_on_warn, and panic_on_oops**
    """
    launch_fpath = ctx.expdir("launch.sh")
    script = HEADER
    script += OPTIONS
    compiler = "gcc"
    qemucmd = gen_qemu_cmd()
    if qemucmd is None:
        warn("Unexpected boot script format detected.")
        shutil.copy2(ctx.run_sh.get(), launch_fpath)
        return
    if "aarch64" == ctx.arch:
        compiler = "aarch64-linux-gnu-gcc"
    script += COMPILE_EXPLOIT.format(compiler)
    if ctx.ramfs.wspath is not None:
        script += CPIO_SCRIPT.format(ctx.fsname(), ctx.ramfs.wspath)
    elif ctx.fsimg.get() is not None:
        script += QCOW_SCRIPT.format(ctx.fsimg.get(), ctx.expdir("exploit"))
    gdb = "gdb" if "x86" in ctx.arch else "gdb-multiarch"
    gdb += f" -ix {ctx.challdir('debug.gdb')}"
    script += GDB_CMD.format(ctx.challdir("debug.gdb"), gdb, gdb)
    script += qemucmd
    f = open(launch_fpath, "w")
    f.write(script)
    os.chmod(launch_fpath, 0o700)
