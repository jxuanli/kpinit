# kpinit

WIP, heavily inspired by [kernelinit](https://github.com/Myldero/kernelinit)

One of the most barring aspect of kernel pwning from my experience is its difficulty in setting up an efficient debugging environment. Therefore, the aim of this project is to streamline the kernel pwning setup and debugging process.

### Design philosophies

A kernel pwning workspace
- should be localized
  - generated files should be easy to remove and regenerate for maintaining a clean workspace
  - should retain copies of provided files in case a workspace needs to be regenerated
- should require minimal manual setup
  - should work without modifications of provided files under most circumstances
  - e.g. works with only a kernel image, a system directory archive or disk image file, and a script that contains a QEMU command
- should be robust against slight variations of file names and formats
  - e.g. files from different CTF challenges might vary in formats
- directories/files should be organized and generated to accelerate exploit development
  - should enable fast experimentations on various kernel exploits
  - should make the kernelland pwning experience similar to the userland pwning experience
    - e.g. contains a subset of helpers provided by `pwntools`
- should be as customizable as possible
  - all files including those responsible for performing static checks and generating helper files are changeable

### Installation

```bash
git clone https://github.com/jxuanli/kpinit.git
echo "alias kpinit='python3 $PWD/kpinit/kpinit.py'" >>~/.bash_aliases
```

### Usage
With only one command, `kpinit` sets up the kernel pwning workspace that you need!
```bash
cd <CHALLENGE_DIR>
kpinit
cd workspace/exploit
./launch.sh [--gdb] [--nokaslr] [--port <port>]
```

Removing all generated files is as simple as:
```bash
rm -rf ./workspace
```


### Features
- [x] create a new directory structure: 
```
challenge root/
├── workspace/ (generated)
│   ├── context.json
│   ├── log.txt
│   ├── vmlinux (if not provided)
│   ├── challenge/
│   │   ├── debug.gdb
│   │   ├── initramfs/
│   │   └── initramfs.cpio.gz
│   └── exploit/
│       ├── util/
│       │   └── (utility files)
│       ├── launch.sh (improved run.sh)
│       ├── serve.sh
│       ├── extra.gdb
│       ├── init
│       ├── vuln.ko
│       └── exploit.c (imports files in util/)
├── bzImage
├── run.sh
├── initramfs.cpio.gz
├── .config (optional)
├── vuln.ko (optional)
├── vmlinux (optional)
└── ...
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
    - supports different ports
  - [x] build `./workspace/exploit/exploit.c`
    - include it in `./workspace/challenge/initramfs`
    - recompress `./workspace/challenge/initramfs.cpio.gz` 
  - [x] Autostart two panes ([`zellij`](https://github.com/zellij-org/zellij) or `tmux`)
  - [x] Regeneration preserves old `exploit.c`
- [x] extract `vmlinux` if not already provided
- [x] run checks on `.config` if exists
  - [x] else if `vmlinux` is not stripped, run checks on that
- [x] extract `vuln.ko` if needed 
- [x] generate `debug.gdb`
  - [x] source `vmlinux`
    - load `vmlinux` at the correct KASLR offset
  - [x] add `vuln.ko` symbols if exists
  - [x] maybe need to check if `vmlinux` is stripped or not in order to add `vuln.ko` symbols 
  - [x] source Linux source code
  - [x] support custom breakpoints
- [ ] generate exploit helpers
  - [x] io helpers
    - `info`, `warn`, `error`, `important`, `input`, etc (similar to those in pwntools)
    - cyclic
  - [ ] general exploit helpers
    - retspill
    - `modprobe_path`
    - `core_dump`
    - [ ] slubstick
    - [ ] microarch
  - [ ] bpf
- [x] support `x86-64` and `aarch64`
- [ ] extract files from `.qcow` or `.img` files
- [x] automatic exploit file serving script
  - the localhost can then be exposed/tunneled with tools such as `ngrok`
- [x] preserve log

Currently only supports gdb.

### [`vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf) installation
```bash
sudo apt -y install python3-pip liblzo2-dev
pip3 install --upgrade git+https://github.com/marin-m/vmlinux-to-elf
```
