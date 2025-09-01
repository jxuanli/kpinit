import os
import json
from logger import Logger
from typing import Dict


CONTEXT_FILE = "context.json"


class Setting:
    def __init__(self, ctx, name, pathfunc=None):
        self.ctx = ctx
        self.name = name
        self.val = None
        self.notnone = False
        self.logger = ctx.logger
        self.pathfunc = pathfunc

    def get(self):
        return self.val

    def set(self, val: str, notnone=False):
        if not os.path.exists(val):
            return False
        self.setval(val, notnone)
        return True

    def setval(self, val: str, notnone=False):
        self.val = val
        self.notnone = notnone
        self.ctx.persist()
        return True

    @property
    def wspath(self):
        val = self.val
        if val is None:
            return None
        val = val.split("/")[-1]
        if self.pathfunc is not None:
            return self.pathfunc(val)
        else:
            self.logger.error(
                f"wspath called on setting {self.name} which is invalid. Raise a Github issue if you see this."
            )

    def check(self):
        if self.notnone and self.val is None:
            self.logger.error(
                f"The setting for {self.name} is invalid, change workspace/{CONTEXT_FILE} in order to proceed"
            )


class Context:
    """
    represents a kernel pwn challenge context
    """

    RAMFS = "ramfs"
    IMAGE = "kernel image"
    RUN_SH = "run.sh"
    VMLINUX = "vmlinux"
    VULN_KO = "vuln module"
    CONFIG = "kernel config"
    EXTRAFILES = "extra files"
    LINUX_SRC = "linux source folder"
    ORIG_LINUX_PATH = "original linux source path"

    settings: Dict[str, Setting]

    def __init__(self):
        self.rootpath = os.getcwd()  # challenge root path
        self.arch = None
        self.logger = Logger()
        self.ramfs = Setting(self, self.RAMFS, self.challdir)
        self.image = Setting(self, self.IMAGE)
        self.run_sh = Setting(self, self.RUN_SH)
        self.vmlinux = Setting(self, self.VMLINUX)
        self.vuln_ko = Setting(self, self.VULN_KO, self.expdir)
        self.config = Setting(self, self.CONFIG)
        self.linux_src = Setting(self, self.LINUX_SRC)
        self.build_path = Setting(self, self.ORIG_LINUX_PATH)
        self.settings = (
            self.ramfs,
            self.image,
            self.run_sh,
            self.vmlinux,
            self.vuln_ko,
            self.config,
            self.linux_src,
            self.build_path,
        )

    def rootdir(self, fname=None):
        """
        get cwd file path, just a wrapper!
        """
        if fname is None:
            fname = ""
        path = os.path.join(self.rootpath, fname)
        return os.path.abspath(path)

    def wsdir(self, fname=None):
        if fname is None:
            fname = ""
        return self.rootdir(os.path.join("workspace", fname))

    def challdir(self, fname=None):
        if fname is None:
            fname = ""
        return self.wsdir(os.path.join("challenge", fname))

    def expdir(self, fname=None):
        if fname is None:
            fname = ""
        return self.wsdir(os.path.join("exploit", fname))

    def load(self):
        """
        return true if can load successfully
        """
        path = self.wsdir(CONTEXT_FILE)
        if os.path.exists(path):
            deserialized = json.load(open(path, "r"))
            for name, val in deserialized.items():
                for setting in self.settings:
                    if setting.name == name and val is not None:
                        if setting.set(val):
                            continue
                        val = self.rootdir(val.split("/")[-1])
                        if not setting.set(val):
                            return False
            if self.vmlinux.get() is not None:
                self.update_arch()
            else:
                return False
            return True
        return False

    def persist(self):
        f = open(self.wsdir(CONTEXT_FILE), "w")
        json.dump(self.serialize(), f, indent=4)
        f.flush()

    def fsname(self):
        return os.path.basename(self.ramfs.wspath).split(".")[0]

    def check(self):
        for setting in self.settings:
            setting.check()

    def serialize(self):
        serialized = {}
        for setting in self.settings:
            serialized[setting.name] = setting.val
        return serialized

    def create_logfile(self):
        logfile_path = self.wsdir("log.txt")
        self.logger.logfile = open(logfile_path, "w")

    def update_arch(self):
        from utils import runcmd

        vmlinux = self.vmlinux.get()
        if vmlinux is not None:
            vmlinux_info = runcmd("file", vmlinux)
            self.arch = "x86-64"
            if "aarch64" in vmlinux_info:
                self.arch = "aarch64"

    def __repr__(self):
        return f"Context: \n{json.dumps(self.serialize(), indent=4)}\n"
