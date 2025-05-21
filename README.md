# kpinit

WIP, heavily inspired by [kernelinit](https://github.com/Myldero/kernelinit)

The aim is to streamline the kernel pwn setup and debug process. 

### Installation

```bash
git clone https://github.com/jxuanli/kpinit.git
echo "alias kpinit='python3 $PWD/kpinit/kpinit.py'" >>~/.bash_aliases
```

### Usage
```bash
cd <CHALLENGE_DIR>
kpinit
cd workspace/exploit
./launch.sh [--gdb] [--nokaslr]
```


### Features
- [x] create a new directory structure: 
```
chall/
├── workspace/ (generated)
│   ├── context.json
│   ├── challenge/
│   │   ├── vmlinux
│   │   ├── bzImage
│   │   ├── debug.gdb
│   │   ├── initramfs/
│   │   └── initramfs.cpio.gz
│   └── exploit/
│       ├── util/
│       │   └── (utility files)
│       ├── launch.sh (improved run.sh)
│       ├── bps.gdb 
│       ├── init
│       ├── vuln.ko
│       └── exploit.c (imports files in util/)
├── bzImage
├── run.sh
├── initramfs.cpio.gz
├── (optional) .config
├── (optional) vmlinux
└── (optional) vuln.ko
```
- [x] generate `./workspace/settings.json` to get the names of provided files
  - [x] auto-generation
  - [x] allow custom `settings.json`
- [x] generate `./workspace/challenge`
  - [x] find and cp `./bzImage ./initramfs.cpio.gz`
  - [x] decompress `./initramfs.cpio.gz`
  - [x] extract `init`
- [x] generate `./workspace/exploit/launch.sh` (rwx)
  - [x] parse the `qemu` command in `./chall/run.sh`
    - options 
  - [x] allow `--debug` mode
    - `nokaslr` (need to check if it is already an option)
    - `-s`
  - [x] build `./workspace/exploit/exploit.c`
    - include it in `./workspace/challenge/initramfs`
    - recompress `./workspace/challenge/initramfs.cpio.gz` 
  - [x] Autostart two panes
    - support either [`zellij`](https://github.com/zellij-org/zellij) or `tmux`
    - support custom GDB plugin path (this is mainly because the author wants to test out his own pwndbg contributions and it might be different from the one used for userland pwn)
  - [x] Regeneration preserves old `exploit.c`
- [x] extract `vmlinux` if not already provided
- [x] run checks on `.config` if exists
  - [x] else if `vmlinux` is not stripped, run checks on that
- [x] extract `vuln.ko` if needed 
- [-] generate `debug.gdb`
  - [x] source `vmlinux`
    - load `vmlinux` at the correct KASLR offset
  - [x] source `libslub`
  - [x] add `vuln.ko` symbols if exists
  - [x] maybe need to check if `vmlinux` is stripped or not in order to add `vuln.ko` symbols 
  - [-] add debug symbols if `bzImage`/`vmlinux` is stripped and `kallsyms` is not disabled (I might implement this in pwndbg instead)
    - probably requires running qemu commands inside the gdb session
  - [x] source Linux source code
  - [x] support custom breakpoints
- [ ] generate exploit helpers
  - [-] io helpers
    - `info`, `warn`, `error`, `important`, `input`, etc (similar to those in pwntools)
    - [-] cyclic
  - [-] general exploit helpers
    - retspill
    - `modprobe_path`
    - `core_dump`
    - [-] slubstick
    - [-] microarch
  - [ ] kheap spray helpers
    - `GFP_KERNEL_ACCOUNT`
      - `pipe_buffer`
      - `msg_msgseg` (`msg_msg` got its own dedicated cache as of the latest kernel)
      - `simple_xattr`
    - `GFP_KERNEL`
      - `unix_address`
      - `poll_list`
  - [ ] Makefile
- [x] `qcow` file format support (instead of `cpio`)
- [ ] support environment variables for specifying file paths (for gdb plugins, etc)
- [ ] unintended
- [ ] ngrok


### [`vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf) installation
```bash
sudo apt -y install python3-pip liblzo2-dev
pip3 install --upgrade git+https://github.com/marin-m/vmlinux-to-elf
```
