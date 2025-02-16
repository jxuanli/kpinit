import sys
from os import path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from gen_debug import *
import unittest 

expected_gdb_ko = """
python
import gdb
TARGET_MODULE = 'vuln'
inferior = gdb.inferiors()[0]
module_struct = { field.name: field.bitpos for field in gdb.parse_and_eval('*(struct module*)0').type.fields() }
shifted_by = module_struct['list'] // 8
module_list = int(gdb.parse_and_eval('&modules'))
print(module_list)
head = module_list
target_text_addr = None
while True:
    head = int(gdb.parse_and_eval(f'((struct list_head *) ({head}))->next'))
    module = head - shifted_by
    module_name_addr = int(gdb.parse_and_eval(f'(void *)(&((struct module *) ({module}))->name[0])'))
    module_name = inferior.read_memory(module_name_addr, 32).tobytes() # Could be longer, but oh well
    module_name = module_name.rstrip(b'\\0')
    module_load = int(gdb.parse_and_eval(f'((struct module *) ({module}))->mem[0].base')) # 0: MOD_TEXT
    print(module_name)
    if module_name == TARGET_MODULE.encode():
        target_text_addr = module_load
    if head == module_list or target_text_addr is not None:
        break
if target_text_addr is None:
    raise ValueError(f'Module {TARGET_MODULE!r} not found - not loading symbol files')
gdb.execute(f'add-symbol-file nice.ko {target_text_addr:#x}')
end
"""

class TestFormattingGdbScripts(unittest.TestCase):
    def test_get_ko_gdb(self):
        expected = expected_gdb_ko.splitlines()
        result = get_ko_gdb("vuln", "nice.ko").splitlines()
        n = len(expected)
        self.assertEqual(n, len(result))
        for i in range(n):
            self.assertEqual(result[i], expected[i])


if __name__ == '__main__':
    unittest.main()
