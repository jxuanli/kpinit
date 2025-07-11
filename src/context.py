import os
import json
from logger import Logger
from typing import Dict


CONTEXT_FILE = "context.json"


class Setting:
    def __init__(self, ctx, name):
        self.ctx = ctx
        self.name = name
        self.val = None
        self.is_strict = False
        self.logger = ctx.logger

    def get(self):
        return self.val

    def set(self, val: str, is_strict=False):
        if not os.path.exists(val):
            return False
        self.setval(val, is_strict)

    def setval(self, val: str, is_strict=False):
        self.val = val
        self.is_strict = is_strict
        self.ctx.persist()
        return True

    @property
    def wspath(self):
        val = self.val
        if val is None:
            return None
        val = val.split("/")[-1]
        if self.name in [
            self.ctx.RAMFS,
            self.ctx.IMAGE,
            self.ctx.QCOW,
            self.ctx.VMLINUX,
        ]:
            return self.ctx.challdir(val)
        elif self.name in [self.ctx.VULN_KO]:
            return self.ctx.expdir(val)
        else:
            self.logger.error(f"Invalid setting for: {self.name}")

    def check(self):
        if self.is_strict and self.val is None:
            self.logger.error(
                f"the setting for {self.name} is invalid, change workspace/{CONTEXT_FILE} in order to proceed"
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
    QCOW = "qcow"
    LINUX_SRC = "linux source folder"
    ORIG_LINUX_PATH = "original linux source path"

    settings: Dict[str, Setting]

    def __init__(self):
        self.arch = None
        self.settings = {}  # a map of settings
        self.logger = Logger()
        self.ramfs = Setting(self, self.RAMFS)
        self.image = Setting(self, self.IMAGE)
        self.run_sh = Setting(self, self.RUN_SH)
        self.vmlinux = Setting(self, self.VMLINUX)
        self.vuln_ko = Setting(self, self.VULN_KO)
        self.config = Setting(self, self.CONFIG)
        self.qcow = Setting(self, self.QCOW)
        self.linux_src = Setting(self, self.LINUX_SRC)
        self.build_path = Setting(self, self.ORIG_LINUX_PATH)
        self.settings = (
            self.ramfs,
            self.image,
            self.run_sh,
            self.vmlinux,
            self.vuln_ko,
            self.config,
            self.qcow,
            self.linux_src,
            self.build_path,
        )
        self.rootpath = os.getcwd() # challenge root path

    def rootdir(self, name=None):
        """
        get cwd file path, just a wrapper!
        """
        if name is None:
            name = ""
        return os.path.join(self.rootpath, name)

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
                        setting.set(val)
                        break
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

    def __repr__(self):
        return f"Context: \n{json.dumps(self.serialize(), indent=4)}\n"
