# kpinit

WIP, heavily inspired by [kernelinit](https://github.com/Myldero/kernelinit)

The aim is to streamline the kernel pwn setup and debug process. 

TODO:
- [ ] create a new directory structure: 
```
chall/
│
├── workplace/
│   ├── challenge/
│   │   ├── vmlinux (maybe)
│   │   ├── bzImage
│   │   ├── initramfs/
│   │   └── initramfs.cpio.gz
│   └── exploit/
│       ├── util/
│       │   ├── common.c
│       │   └── common.c
│       ├── launch.sh (improved run.sh)
│       ├── init
│       ├── vuln.ko (maybe)
│       ├── debug.gdb
│       └── exploit.c (imports functions in util/)
│
├── bzImage
├── run.sh
├── initramfs.cpio.gz
├── (optional) vmlinux
└── (optional) vuln.ko
```
- [x] generate `./chall/workplace/challenge`
  - [x] find and cp `./chall/bzImage ./chall/initramfs.cpio.gz`
  - [x] decompress `./chall/initramfs.cpio.gz`
  - [x] extra `init`
- [ ] generate `./chall/workplace/exploit/launch.sh` (rwx)
  - [x] parse the `qemu` command in `./chall/run.sh`
    - options 
  - [ ] allow `--debug` mode
    - `init.stay-root`
    - `nokaslr` (need to check if it is already an option)
    - `-s`
  - [x] build `./chall/workplace/exploit/exploit.c`
    - include it in `./chall/workplace/challenge/initramfs`
    - recompress `./chall/workplace/challenge/initramfs.cpio.gz` 
- [ ] extract `vmlinux`
- [ ] run checks on `.config`
- [ ] extra `vuln.ko` if needed 
- [ ] generate `debug.gdb`
- [ ] generate exploit helpers 
  - [ ] converting between asm and their bytecode
