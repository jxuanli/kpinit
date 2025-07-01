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
    shutil.copy2(ctx.get_path_root(ctx.BZIMAGE), ctx.get_path(ctx.BZIMAGE))
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
    open(ctx.exploit_path("bps.gdb"), "w")
    check_config()


def gen_workspace():
    """
    generate the workspace directory as specified in README.md
    """
    ws_path = ctx.workspace_path()
    if os.path.exists(ws_path):
        assert os.path.isdir(ws_path)
        logger.warn(
            "removing existing workspace/challenge and workspace/exploit to generate a new one"
        )
        if os.path.isfile(ctx.exploit_path("exploit.c")):
            shutil.copy2(ctx.exploit_path("exploit.c"), ctx.workspace_path("exploit.c"))
        if os.path.isdir(ctx.challenge_path()):
            shutil.rmtree(ctx.challenge_path())
        if os.path.isdir(ctx.exploit_path()):
            shutil.rmtree(ctx.exploit_path())
    else:
        os.mkdir(ws_path)
    os.mkdir(ctx.challenge_path())
    os.mkdir(ctx.exploit_path())
    extract_context()
    gen_challenge()
    gen_exploit()
    # preserves the old exploit
    if os.path.isfile(ctx.workspace_path("exploit.c")):
        shutil.copy2(ctx.workspace_path("exploit.c"), ctx.exploit_path("exploit.c"))
    logger.important("Finished generating workspace")


if __name__ == "__main__":
    gen_workspace()
    logger.important("happy hacking!")
