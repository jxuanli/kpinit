import os, json
from logger import Logger
from typing import List, Dict


CONTEXT_FILE = "context.json"
logger = Logger()


class Setting:
    key: str
    val: str
    isStrict: bool

    def __init__(self, key, val: str = None, isStrict=False):
        self.key = key
        self.val = val
        self.isStrict = isStrict

    def check(self):
        if self.isStrict and self.val is None:
            logger.error(
                f"the setting for {self.key} is invalid, change workspace/{CONTEXT_FILE} in order to proceed"
            )


class Context:
    """
    represents a kernel pwn challenge context
    """

    RAMFS = "initramfs.cpio.gz"
    BZIMAGE = "bzImage"
    RUN_SH = "run.sh"
    VMLINUX = "vmlinux"
    VULN_KO = "vuln"
    LIBSLUB = "libslub"
    LIBKERNEL = "libkernel"
    CONFIG = "kernel_config"
    QCOW = "qcow"
    LINUX_SRC = "linux source folder"
    GDB_PLUGIN = "custom gdb plugin"
    ORIG_LINUX_PATH = "original linux source path"

    settings: Dict[str, Setting]

    def __init__(
        self,
        settings: List[str] = [
            RAMFS,
            BZIMAGE,
            RUN_SH,
            VMLINUX,
            VULN_KO,
            LIBSLUB,
            LIBKERNEL,
            CONFIG,
            QCOW,
            LINUX_SRC,
            GDB_PLUGIN,
            ORIG_LINUX_PATH,
        ],
    ):
        self.settings = {}  # a map of settings
        for setting in settings:
            self.settings[setting] = Setting(setting)

    def set(self, setting, val=None, isStrict=False):
        self.settings[setting] = Setting(setting, val, isStrict)
        self.persist()

    def set_path(self, setting, path, isStrict=False):
        if os.path.exists(path):
            self.set(setting, path, isStrict)
            self.persist()
            return True
        return False

    def get(self, setting):
        if setting not in self.settings:
            return None
        return self.settings[setting].val

    def get_path(self, setting):
        val = self.get(setting)
        if val is None:
            return None
        val = val.split("/")[-1]
        if setting in [self.RAMFS, self.BZIMAGE, self.QCOW, self.VMLINUX]:
            return self.challenge_path(val)
        elif setting in [self.VULN_KO]:
            return self.exploit_path(val)
        else:
            logger.error(f"Invalid setting {setting}")

    def root_path(self, name=None):
        """
        get cwd file path, just a wrapper!
        """
        if name is None:
            name = ""
        return os.path.join(os.getcwd(), name)

    def workspace_path(self, fname=None):
        if fname is None:
            fname = ""
        return self.root_path(os.path.join("workspace", fname))

    def challenge_path(self, fname=None):
        if fname is None:
            fname = ""
        return self.workspace_path(os.path.join("challenge", fname))

    def exploit_path(self, fname=None):
        if fname is None:
            fname = ""
        return self.workspace_path(os.path.join("exploit", fname))

    def get_path_root(self, setting):
        val = self.get(setting)
        if val is None:
            return None
        return self.root_path(val)

    def load(self):
        """
        return true if can load successfully
        """
        path = self.workspace_path(CONTEXT_FILE)
        if os.path.exists(path):
            deserialized = json.load(open(path, "r"))
            for key, val in deserialized.items():
                self.set(key, val)

    def persist(self):
        f = open(self.workspace_path(CONTEXT_FILE), "w")
        json.dump(self.serialize(), f, indent=4)
        f.flush()

    def check(self):
        for setting in self.settings.values():
            setting.check()

    def serialize(self):
        serialized = {}
        for name, setting in self.settings.items():
            serialized[name] = setting.val
        return serialized

    def __repr__(self):
        return f"Context: \n{json.dumps(self.serialize(), indent=4)}\n"
