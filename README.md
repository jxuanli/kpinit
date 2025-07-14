# kpinit

One of the most challenging aspects of kernel pwning, from my experience, is setting up an efficient debugging environment. Therefore, this project aims to streamline the kernel pwning setup and debugging process. It generates a kernel-pwning workspace that accelerates exploit development by enabling fast experimentation on various kernel exploits.

### Design philosophies

A kernel pwning workspace
- is localized: easy to remove and regenerate
- requires minimal manual setup: works with just one command in most cases (similar to `pwninit`)
- is robust against slight variations of file names and formats (from different CTF challenges)
- is organized and generated to accelerate exploit development: contains a subset of helpers provided by `pwntools`
- is as customizable as possible

### Acknowledgements

This project is inspired by [`kernelinit`](https://github.com/Myldero/kernelinit).

Lots of thanks to [`Jacob`](https://github.com/jacobgnewman) for early testing.

### Installation

```bash
git clone https://github.com/jxuanli/kpinit.git
echo "alias kpinit='python3 $PWD/kpinit/kpinit.py'" >>~/.bash_aliases
```

#### [`vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf) installation
```bash
sudo apt -y install python3-pip liblzo2-dev
pip3 install --upgrade git+https://github.com/marin-m/vmlinux-to-elf
```

### Demo


https://github.com/user-attachments/assets/4d62da41-29a4-4f8d-8c3e-95a849c8a613


### Usage
With only one command, `kpinit` sets up the kernel pwning workspace that you need!
```bash
cd <challenge directory>
kpinit
cd workspace/exploit
./launch.sh [--gdb] [--nokaslr] [--port <port>]
```

Removing all generated files is as simple as:
```bash
rm -rf ./workspace
```

#### File paths detection

`workspace/context.json` contains file paths used to extract information for static analysis and file generation. Instead of having to specify paths with command options, `kpinit` automatically detects needed files for creating a kernel-pwning workspace. This reduces the need for manual setup. When detection fails, the user can manually specify the paths.

#### GDB scripting
Generic GDB scripts for adding symbol files (vmlinux and loadable modules) are included in `workspace/challenge/debug.gdb`. Offsets are automatically computed when KASLR is enabled. Extra GDB scripting can be added in `workspace/exploit/extra.gdb`.

#### Known issues
`kpinit` parses and regenerates `qemu` commands for modifying the `qemu` command and placing the generated `launch.sh` in a different directory. Although it correctly parses most launch files (that contain the `qemu` command), it occasionally fails and generates incorrect `qemu` commands. In those cases, users need to manually fix `launch.sh`. Because the launch file format does not follow a consistent pattern, I believe this is acceptable.

See [`Features`](https://github.com/jxuanli/kpinit/tree/main?tab=readme-ov-file#features) section for more usages.

### Features
- [x] generates a new directory with the following structure: 
```
challenge dir/
├── workspace/ (generated)
│   ├── context.json
│   ├── log.txt
│   ├── vmlinux (if not provided)
│   ├── challenge/
│   │   ├── debug.gdb
│   │   ├── initramfs/
│   │   └── initramfs.cpio.gz (if used)
│   └── exploit/
│       ├── util/
│       │   └── (utility files)
│       ├── launch.sh (improved run.sh)
│       ├── serve.sh
│       ├── extra.gdb
│       ├── init
│       ├── vuln.ko
│       └── exploit.c (imports files in util/)
├── bzImage (required)
├── run.sh (required)
└── ... (optional: vmlinux, ramfs, .qcow2, ...)
```
- [x] supports `x86-64` and `aarch64`
- [x] auto-generates `./workspace/context.json` and allows customization
- [x] generates `./workspace/challenge`
  - [x] decompresses `./initramfs.cpio.gz` if it exists and extracts `init` from it
- [x] generates `./workspace/exploit/launch.sh` (rwx)
  - [x] contains the parsed `qemu` command
  - [x] `--nokaslr`
  - [x] supports different ports
  - [x] compiles `./workspace/exploit/exploit.c`
    - includes it in `./workspace/challenge/initramfs`
    - recompresses `./workspace/challenge/initramfs.cpio.gz` 
  - [x] autostarts two panes ([`zellij`](https://github.com/zellij-org/zellij) or `tmux`)
  - [x] regeneration preserves old `exploit.c`
- [x] extracts `vmlinux` if not already provided (`vmlinux-to-elf`)
- [x] runs checks on the kernel configuration file if it exists
  - [x] runs checks on `vmlinux` if the configuration file does not exist and `vmlinux` is not stripped
- [x] extracts `vuln.ko` if needed 
- [x] generates `debug.gdb`
  - [x] sources `vmlinux` at the correct offset even if KASLR is enabled
  - [x] adds `vuln.ko` symbols if they exist (when `vmlinux` contains `debug_info`)
  - [x] sources Linux source code
  - [x] supports custom breakpoints
- [ ] generates exploit helpers (See [DOC.md](https://github.com/jxuanli/kpinit/blob/main/DOC.md) for documentations)
  - `info`, `warn`, `error`, `important`, `input`, `cyclic`, etc (similar to those in pwntools)
  - retspill, `modprobe_path`, `core_dump`
  - [ ] bpf
- [ ] extracts files from `.qcow` or `.img` files
- [x] generates an exploit file serving script
  - The localhost can then be exposed with tools such as `ngrok`
- [x] preserves log

Only GDB is currently supported.
