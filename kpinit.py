import os, shutil, sys

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
    generate the workplace/challenge directory
    """
    os.mkdir(ctx.challenge_path())
    shutil.copy2(ctx.get_path_root(ctx.BZIMAGE), ctx.get_path(ctx.BZIMAGE))
    decompress_ramfs()
    extract_qcow()
    extract_vmlinux()


def gen_exploit():
    """
    generate the workplace/exploit directory
    """
    os.mkdir(ctx.exploit_path())
    gen_launch()
    extract_init()
    extract_ko()
    gen_debug()
    gen_exploit_src()
    check_config()


def gen_workplace():
    """
    generate the workplace directory as specified in README.md
    """
    wp_path = ctx.workplace_path()
    if os.path.exists(wp_path):
        assert os.path.isdir(wp_path)
        logger.warn(
            "removing existing workplace/challenge and workplace/exploit to generate a new one"
        )
        if os.path.isdir(ctx.challenge_path()):
            shutil.rmtree(ctx.challenge_path())
        if os.path.isdir(ctx.exploit_path()):
            shutil.rmtree(ctx.exploit_path())
    else:
        os.mkdir(wp_path)
    extract_context()
    gen_challenge()
    gen_exploit()
    logger.important("Finished generating workplace")


if __name__ == "__main__":
    gen_workplace()
    logger.important("happy hacking!")
