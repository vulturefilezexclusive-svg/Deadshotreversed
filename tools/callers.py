#!/usr/bin/env python3
"""Find call sites (bl) to a target address, per function."""
import sys
sys.path.insert(0, "tools")
from capstone import CS_OP_IMM
from xrefs_fn import Image

def callers(img, target):
    out = []
    for fstart in img.starts:
        for ins in img.md.disasm(img.code_of(fstart), fstart):
            if ins.mnemonic in ("bl", "b") and ins.operands and ins.operands[0].type == CS_OP_IMM and ins.operands[0].imm == target:
                out.append((fstart, ins.address, ins.mnemonic))
    return out

if __name__ == "__main__":
    img = Image(sys.argv[1])
    for t in [int(x, 0) for x in sys.argv[2:]]:
        cs = callers(img, t)
        print(f"=== {t:#x}: {len(cs)} call sites")
        for f, a, m in cs[:25]:
            print(f"   fn {f:#x}  {a:#x}  {m}")
