import os
import shutil
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from gen_launch import gen_launch
from gen_debug import gen_debug
from gen_exploit_src import gen_exploit_src
from extract_files import (
    decompress_ramfs,
    extract_vmlinux,
    extract_context,
    extract_init,
    extract_ko,
    extract_qcow,
)
from utils import logger, ctx
from checks import check_config


def gen_challenge():
    """
    generate the workspace/challenge directory
    """
    if not ctx.image.get():
        logger.error("cannot find kernel image file")
    shutil.copy2(ctx.image.get(), ctx.image.wspath)
    decompress_ramfs()
    extract_qcow()
    extract_vmlinux()


def gen_exploit():
    """
    generate the workspace/exploit directory
    """
    gen_launch()
    extract_init()
    extract_ko()
    gen_debug()
    gen_exploit_src()
    check_config()


def gen_workspace():
    """
    generate the workspace directory as specified in README.md
    """
    ws_path = ctx.wsdir()
    if os.path.exists(ws_path):
        ctx.create_logfile()
        if not os.path.isdir(ws_path):
            logger.error("previous workspace is not a directory")
        logger.warn(
            "removing existing workspace/challenge and workspace/exploit to generate a new one"
        )
        if os.path.isfile(ctx.expdir("exploit.c")):
            shutil.copy2(ctx.expdir("exploit.c"), ctx.wsdir("exploit.c"))
        if os.path.isdir(ctx.challdir()):
            shutil.rmtree(ctx.challdir())
        if os.path.isdir(ctx.expdir()):
            shutil.rmtree(ctx.expdir())
    else:
        os.mkdir(ws_path)
        ctx.create_logfile()
    os.mkdir(ctx.challdir())
    os.mkdir(ctx.expdir())
    extract_context()
    gen_challenge()
    gen_exploit()
    # preserves the old exploit
    if os.path.isfile(ctx.wsdir("exploit.c")):
        shutil.copy2(ctx.wsdir("exploit.c"), ctx.expdir("exploit.c"))
    logger.important("Finished generating workspace")


if __name__ == "__main__":
    gen_workspace()
    logger.important("happy hacking!")
