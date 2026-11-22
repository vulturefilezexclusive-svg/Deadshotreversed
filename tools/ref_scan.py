#!/usr/bin/env python3
"""Find per-function references (adrp+add/ldr) to a list of absolute VAs."""
import sys
sys.path.insert(0, "tools")
from capstone import CS_OP_REG, CS_OP_IMM, CS_OP_MEM
from xrefs_fn import Image

def scan(img, targets):
    tset = set(targets); hits = {}
    md = img.md
    for fstart in img.starts:
        code = img.code_of(fstart)
        regs = {}
        for ins in md.disasm(code, fstart):
            m, ops = ins.mnemonic, ins.operands
            if m == "adrp" and len(ops) == 2 and ops[0].type == CS_OP_REG:
                regs[ops[0].reg] = ops[1].imm
            elif m in ("add", "ldr") and len(ops) >= 2 and ops[1].type == CS_OP_REG and ops[1].reg in regs:
                base = regs[ops[1].reg]; tgt = None
                if m == "add" and len(ops) == 3 and ops[2].type == CS_OP_IMM:
                    tgt = base + ops[2].imm
                elif m == "ldr" and len(ops) == 3 and ops[2].type == CS_OP_MEM and ops[2].mem.base == ops[1].reg:
                    tgt = base + ops[2].mem.disp
                elif m == "ldr" and len(ops) == 2:
                    tgt = base
                if tgt in tset:
                    hits.setdefault(tgt, []).append((fstart, ins.address, f"{m} {ins.op_str}"))
    return hits

if __name__ == "__main__":
    img = Image(sys.argv[1])
    targets = [int(x, 0) for x in sys.argv[2:]]
    h = scan(img, targets)
    for t in targets:
        hs = h.get(t, [])
        print(f"=== {t:#x}: {len(hs)} refs in {len({x[0] for x in hs})} functions")
        for f, a, s in hs[:30]:
            print(f"   fn {f:#x}  {a:#x}  {s}")
