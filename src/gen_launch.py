import os
import re
from utils import warn, error, ctx
from checks import check_qemu
import shutil

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
            return opts
        option = parts[i][1:]
        token = ""
        i += 1
        while i < len(parts) and not parts[i].startswith("-"):
            token += parts[i] + " "
            i += 1
        opts[option] = token.strip()
    return opts


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
    pattern = re.compile(r"-initrd\s+(?:\.\.?/|/)[\w./\-\+@%~]+")
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
    opts = get_qemu_options(qemucmd.replace("\\", " "))
    check_qemu(opts)
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
                realcmd += "\t" + line + "\\\n"
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
                **checks SMAP, SMEP, KPTI, KASLR, and panic_on_oops**
    """
    launch_fpath = ctx.expdir("launch.sh")
    script = HEADER
    script += OPTIONS
    compiler = "gcc"
    if "aarch64" == ctx.arch:
        compiler = "aarch64-linux-gnu-gcc"
    script += COMPILE_EXPLOIT.format(compiler)
    if ctx.ramfs.wspath is not None:
        script += CPIO_SCRIPT.format(ctx.fsname(), ctx.ramfs.wspath)
    gdb = "gdb" if "x86" in ctx.arch else "gdb-multiarch"
    gdb += f" -ix {ctx.challdir('debug.gdb')}"
    script += GDB_CMD.format(ctx.challdir("debug.gdb"), gdb, gdb)
    qemucmd = gen_qemu_cmd()
    if qemucmd is None:
        warn("Unexpected boot script format detected.")
        shutil.copy2(ctx.run_sh.get(), launch_fpath)
        return
    script += qemucmd
    f = open(launch_fpath, "w")
    f.write(script)
    os.chmod(launch_fpath, 0o700)
