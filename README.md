# kpinit

WIP, heavily inspired by [kernelinit](https://github.com/Myldero/kernelinit)

The aim is to streamline the kernel pwn setup and debug process. 

### Features
- [ ] create a new directory structure: 
```
chall/
├── workplace/ (generated)
│   ├── settings.json
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
- [ ] generate `./workplace/settings.json` to get the names of provided files
  - [x] auto-generation
  - [ ] allow custom `settings.json`
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
- [ ] extract `vmlinux` if not already provided
- [ ] run checks on `.config` if exists
  - [ ] else if `vmlinux` is not stripped, run checks on that
- [ ] extract `vuln.ko` if needed 
- [ ] generate `debug.gdb`
  - [x] source `vmlinux`
  - [ ] source `libslub`
  - [ ] add `vuln.ko` symbols if exists 
  - [ ] maybe need to check if `vmlinux` is stripped or not in order to add `vuln.ko` symbols 
  - [ ] add debug symbols if `vmlinux` is stripped and `kallsyms` is not disabled 
    - probably requires running qemu commands inside the gdb session 
- [ ] generate exploit helpers 
  - [ ] converting between asm and their machine code
- [ ] compiles kernel if `.config` is provided

