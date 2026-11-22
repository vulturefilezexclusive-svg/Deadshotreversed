#!/usr/bin/env python3
import sys, bisect
sys.path.insert(0, "tools")
from xrefs_fn import Image
import subprocess
img = Image(sys.argv[1])
addr = int(sys.argv[2], 0)
i = bisect.bisect_right(img.starts, addr) - 1
start = img.starts[i]
end = img.starts[i+1] if i+1 < len(img.starts) else img.text.virtual_address + img.text.size
print(f"# function {start:#x} .. {end:#x}  ({(end-start)//4} insns)")
from disasm import main as dis
dis(sys.argv[1], start, end)
