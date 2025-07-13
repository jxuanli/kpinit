from utils import logger, ctx
import subprocess

ko_gdb_template = """
python
import gdb
TARGET_MODULE = '{module_name}'
inferior = gdb.inferiors()[0]
module_struct = {{ field.name: field.bitpos for field in gdb.parse_and_eval('*(struct module*)0').type.fields() }}
shifted_by = module_struct['list'] // 8
module_list = int(gdb.parse_and_eval('&modules'))
print(module_list)
head = module_list
target_text_addr = None
while True:
    head = int(gdb.parse_and_eval(f'((struct list_head *) ({{head}}))->next'))
    module = head - shifted_by
    module_name_addr = int(gdb.parse_and_eval(f'(void *)(&((struct module *) ({{module}}))->name[0])'))
    module_name = inferior.read_memory(module_name_addr, 32).tobytes() # Could be longer, but oh well
    module_name = module_name.rstrip(b'\\0')
    module_load = int(gdb.parse_and_eval(f'((struct module *) ({{module}}))->mem[0].base')) # 0: MOD_TEXT
    print(module_name)
    if module_name == TARGET_MODULE.encode():
        target_text_addr = module_load
    if head == module_list or target_text_addr is not None:
        break
if target_text_addr is None:
    raise ValueError(f'Module {{TARGET_MODULE!r}} not found - not loading symbol files')
gdb.execute(f'add-symbol-file {ko_path} {{target_text_addr:#x}}')
end
"""

kbase_template = """
python
import gdb
kbase = 0
vmlinux = "{}"
try:
  kbase = int(gdb.execute("kbase", to_string=True).strip().split(" ")[-1][:18], 16)
  print(f"found kbase: {{hex(kbase)}}")
  offset = kbase - {}
  gdb.execute(f"symbol-file {{vmlinux}} -o {{hex(offset)}}")
except:
  gdb.execute(f"add-symbol-file {{vmlinux}}")
  print("cannot find kbase")
end
"""

finished_msg = """
python
print("finished sourcing files")
end
c
"""


def get_ko_gdb(module_name, ko_path):
    return ko_gdb_template.format(module_name=module_name, ko_path=ko_path)


def gen_debug():
    vmlinux_info = subprocess.run(
        ["readelf", "-l", ctx.vmlinux.get()], capture_output=True, text=True
    ).stdout
    base = None
    for line in vmlinux_info.splitlines():
        if "LOAD" in line:
            base = int(line.split()[2], 16)
            break
    if not base:
        logger.error(f"Cannot find kernel base: {vmlinux_info}")
    if ctx.arch == "aarch64":
        # for some reason the first 0x10000 bytes of an aarch64 kernel is not mappped
        base += 0x10000
    content = ""
    content += "target remote localhost:$PORT\n"
    content += kbase_template.format(ctx.vmlinux.get(), base)
    if ctx.linux_src.get() is not None:
        content += f"set substitute-path ./ {ctx.linux_src.get()}\n"
        if ctx.build_path.get() is not None:
            content += (
                f"set substitute-path {ctx.build_path.get()} {ctx.linux_src.get()}\n"
            )
    content += f"add-symbol-file {ctx.expdir('exploit')}\n"
    vmlinux_info = subprocess.run(
        ["file", ctx.vmlinux.get()], capture_output=True, text=True
    ).stdout
    if "debug_info" in vmlinux_info:
        if ctx.vuln_ko.get() is not None:
            out = (
                subprocess.check_output(
                    ["strings", ctx.vuln_ko.wspath], stderr=subprocess.DEVNULL
                )
                .decode()
                .strip()
            )
            name = ""
            for line in out.splitlines():
                if len(line) < 20 and line.startswith("name=") and line[5:].isalnum():
                    name = line[5:]
            if len(name) > 0:
                logger.info(f"Found module {name}")
            else:
                logger.warn("Module name not found")
            content += get_ko_gdb(name, ctx.vuln_ko.wspath)
    else:
        logger.warn("no debug info 😢")

    extra = ctx.expdir("extra.gdb")
    content += f"source {extra}\n"
    content += finished_msg
    f = open(ctx.challdir("debug.gdb"), "w")
    f.write(content)
    f = open(extra, "w")
    # this prob only works on pwndbg
    content = ""
    content += "set show-flag on\n"
    content += "set exception-debugger on\n"
    f.write(content)
