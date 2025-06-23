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
  print(f"found kbase: {hex(kbase)}")
  offset = kbase - 0xffffffff81000000
  gdb.execute(f"symbol-file {{vmlinux}} -o {{hex(offset)}}")
except:
  gdb.execute(f"add-symbol-file {{vmlinux}}")
  print("cannot find kbase")
end
"""

libslub_template = f"""
python
import gdb
try:
    gdb.execute("source {{}}")
except:
    print("failed to load libslub")
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
    content = ""
    if ctx.get(ctx.GDB_PLUGIN) is not None:
        content += f"source {ctx.get(ctx.GDB_PLUGIN)}\n"
        content += "set show-flag on\n"
        content += "set exception-debugger on\n"
    content += "target remote localhost:1234\n"
    if ctx.get(ctx.LIBKERNEL) is not None:
        content += f"source {ctx.get(ctx.LIBKERNEL)}\n"
    content += kbase_template.format(ctx.get(ctx.VMLINUX))
    if ctx.get(ctx.LINUX_SRC) is not None:
        content += f"set substitute-path ./ {ctx.get(ctx.LINUX_SRC)}\n"
        if ctx.get(ctx.ORIG_LINUX_PATH) is not None:
            content += f"set substitute-path {ctx.get(ctx.ORIG_LINUX_PATH)} {ctx.get(ctx.LINUX_SRC)}\n"
    content += f"add-symbol-file {ctx.exploit_path('exploit')}\n"
    out = subprocess.run(["readelf", "-SW", ctx.get_path(ctx.VMLINUX)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout            
    if b"debug_info" in out:
        if ctx.get(ctx.VULN_KO) is not None:
            out = (
                subprocess.check_output(
                    ["strings", ctx.get_path(ctx.VULN_KO)], stderr=subprocess.DEVNULL
                )
                .decode()
                .strip()
            )
            name = ""
            for line in out.splitlines():
                if len(line) < 20 and line.startswith("name=") and line[5:].isalnum():
                    name = line[5:]
            if len(name) > 0:
                logger.info(f"found module {name}")
            else:
                logger.warn("module name not found")
            content += get_ko_gdb(name, ctx.get_path(ctx.VULN_KO))
    else:
        logger.warn("no debug info 😢")

    content += f"source {ctx.exploit_path('bps.gdb')}\n"
    content += finished_msg
    f = open(ctx.challenge_path("debug.gdb"), "w")
    f.write(content)
