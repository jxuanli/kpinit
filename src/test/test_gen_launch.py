import sys
from os import path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from gen_launch import *
import unittest 

class TestQemuParsing(unittest.TestCase):
    cmd0 = "qemu-system-aarch64 -nice nice haha -ok haha"
    cmd1 = "qemu-system-x86_64 -hda disk.img -m 2048 -smp 2 -net nic,user"
    cmd2 = """
    /usr/bin/qemu-system-x86_64 \
        -kernel linux-5.4/arch/x86/boot/bzImage \
        -initrd $PWD/initramfs.cpio.gz \
        -fsdev local,security_model=passthrough,id=fsdev0,path=$HOME \
        -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare \
        -nographic \
        -monitor none \
        -s \
        -append "console=ttyS0 nokaslr"
    """
    invalid0 = "a -nice nice"
    invalid1 = "qemu-system-aarch64 -nice -nice"

    def test_get_qemu_options(self):
        expected0 = {
            "nice": "nice haha ",
            "ok": "haha "
        }
        _, res = get_qemu_options(self.cmd0)
        self.assertEqual(res, expected0)
        expected1 = {
            "hda": "disk.img ",
            "m": "2048 ", 
            "smp": "2 ",
            "net": "nic,user "
        }
        _, res = get_qemu_options(self.cmd1)
        self.assertEqual(res, expected1)
        expected2 = {
            'kernel': 'linux-5.4/arch/x86/boot/bzImage ', 
            'initrd': '$PWD/initramfs.cpio.gz ',
            'fsdev': 'local,security_model=passthrough,id=fsdev0,path=$HOME ',
            'device': 'virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare ',
            'nographic': "",
            'monitor': 'none ',
            's': "",
            'append': '\"console=ttyS0 nokaslr\" ',
        }
        _, res = get_qemu_options(self.cmd2)
        self.assertEqual(res, expected2)

    def test_get_qemu_arch(self):
        self.assertEqual(get_qemu_arch(self.cmd0), "aarch64")
        self.assertEqual(get_qemu_arch(self.cmd1), "x86_64")

    
if __name__ == '__main__':
    unittest.main()
