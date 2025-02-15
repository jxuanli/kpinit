# kpinit

WIP, heavily inspired by [kernelinit](https://github.com/Myldero/kernelinit)

The aim is to streamline the kernel pwn setup and debug process. 

### Features
- [ ] create a new directory structure: 
```
chall/
├── workplace/ (generated)
│   ├── naming.json
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
├── bzImage
├── run.sh
├── initramfs.cpio.gz
├── (optional) vmlinux
└── (optional) vuln.ko
```
- [x] generate `./workplace/naming.json` to get the names of provided files
- [x] generate `./workplace/challenge`
  - [x] find and cp `./bzImage ./initramfs.cpio.gz`
  - [x] decompress `./initramfs.cpio.gz`
  - [x] extract `init`
- [ ] generate `./workplace/exploit/launch.sh` (rwx)
  - [x] parse the `qemu` command in `./chall/run.sh`
    - options 
  - [ ] allow `--debug` mode
    - `init.stay-root`
    - `nokaslr` (need to check if it is already an option)
    - `-s`
  - [x] build `./workplace/exploit/exploit.c`
    - include it in `./workplace/challenge/initramfs`
    - recompress `./workplace/challenge/initramfs.cpio.gz` 
- [ ] extract `vmlinux`
- [ ] run checks on `.config`
  - [ ] else if `vmlinux` is not stripped, run checks on that
- [ ] extra `vuln.ko` if needed 
- [ ] generate `debug.gdb`
  - [ ] source `vmlinux`
  - [ ] import `libslub`
  - [ ] add `vuln.ko` symbols if exists
  - [ ] add debug symbols if `vmlinux` is stripped and `kallsyms` is not disabled 
- [ ] generate exploit helpers 
  - [ ] converting between asm and their bytecode
- [ ] compiles kernel if `.config` is provided

