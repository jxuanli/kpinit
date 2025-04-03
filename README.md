# kpinit

WIP, heavily inspired by [kernelinit](https://github.com/Myldero/kernelinit)

The aim is to streamline the kernel pwn setup and debug process. 

### Features
- [x] create a new directory structure: 
```
chall/
├── workplace/ (generated)
│   ├── context.json
│   ├── challenge/
│   │   ├── vmlinux
│   │   ├── bzImage
│   │   ├── debug.gdb
│   │   ├── initramfs/
│   │   └── initramfs.cpio.gz
│   └── exploit/
│       ├── util/
│       │   ├── common.h
│       │   └── common.c
│       ├── launch.sh (improved run.sh)
│       ├── bps.gdb 
│       ├── init
│       ├── vuln.ko
│       └── exploit.c (imports functions in util/)
├── bzImage
├── run.sh
├── initramfs.cpio.gz
├── (optional) .config
├── (optional) vmlinux
└── (optional) vuln.ko
```
- [x] generate `./workplace/settings.json` to get the names of provided files
  - [x] auto-generation
  - [x] allow custom `settings.json`
- [x] generate `./workplace/challenge`
  - [x] find and cp `./bzImage ./initramfs.cpio.gz`
  - [x] decompress `./initramfs.cpio.gz`
  - [x] extract `init`
- [x] generate `./workplace/exploit/launch.sh` (rwx)
  - [x] parse the `qemu` command in `./chall/run.sh`
    - options 
  - [x] allow `--debug` mode
    - `nokaslr` (need to check if it is already an option)
    - `-s`
  - [x] build `./workplace/exploit/exploit.c`
    - include it in `./workplace/challenge/initramfs`
    - recompress `./workplace/challenge/initramfs.cpio.gz` 
  - [x] Autostart two panes
    - support either [`zellij`](https://github.com/zellij-org/zellij) or `tmux`
    - support custom GDB plugin path (this is mainly because the author wants to test out his own pwndbg contributions and it might be different from the one used for userland pwn)
- [ ] extract `vmlinux` if not already provided
- [ ] run checks on `.config` if exists
  - [ ] else if `vmlinux` is not stripped, run checks on that
- [x] extract `vuln.ko` if needed 
- [ ] generate `debug.gdb`
  - [x] source `vmlinux`
  - [x] source `libslub`
  - [x] add `vuln.ko` symbols if exists
  - [ ] maybe need to check if `vmlinux` is stripped or not in order to add `vuln.ko` symbols 
  - [ ] add debug symbols if `vmlinux` is stripped and `kallsyms` is not disabled 
    - probably requires running qemu commands inside the gdb session
  - [ ] add useful structures in gdb
  - [x] source Linux source code
  - [x] support custom breakpoints
- [ ] generate exploit helpers 
  - [ ] converting between asm and their machine code
  - [ ] Makefile
- [ ] compiles kernel if `.config` is provided
- [x] `qcow` file format support (instead of `cpio`)
- [ ] enable envvar to specify file paths (for gdb plugins, etc)
- [ ] unintended?
