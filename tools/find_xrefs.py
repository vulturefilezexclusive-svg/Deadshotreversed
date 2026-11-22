#!/usr/bin/env python3
"""Find ARM64 code references (ADRP+ADD/LDR) to given virtual addresses in a Mach-O __text."""
import sys, collections
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_OP_REG, CS_OP_IMM

def load(path):
    b = lief.MachO.parse(path).at(0)
    sec = b.get_section("__text")
    data = open(path, "rb").read()
    code = data[sec.offset:sec.offset+sec.size]
    return b, sec, code

def xrefs(path, targets):
    b, sec, code = load(path)
    base, size = sec.virtual_address, sec.size
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    regs = {}
    out = collections.defaultdict(list)
    targetset = set(targets)
    addr = base
    for ins in md.disasm(code, base):
        m = ins.mnemonic
        ops = ins.operands
        if m == "adrp" and len(ops) == 2 and ops[0].type == CS_OP_REG and ops[1].type == CS_OP_IMM:
            regs[ops[0].reg] = ops[1].imm
        elif m in ("add", "ldr", "adr") and len(ops) >= 2:
            dst, src = ops[0], ops[1]
            tgt = None
            if m == "adr" and src.type == CS_OP_IMM:
                tgt = src.imm
            elif src.type == CS_OP_REG and src.reg in regs:
                if len(ops) == 3 and ops[2].type == CS_OP_IMM:
                    tgt = regs[src.reg] + ops[2].imm
                elif m == "ldr" and len(ops) == 2:
                    # ldr Xd, [Xn] - only page-aligned hits
                    tgt = regs[src.reg]
            if tgt in targetset:
                out[tgt].append((ins.address, f"{ins.mnemonic} {ins.op_str}"))
        if m in ("bl", "b") or m.startswith("ret"):
            pass
    return out

if __name__ == "__main__":
    path = sys.argv[1]
    targets = [int(x, 0) for x in sys.argv[2:]]
    res = xrefs(path, targets)
    for t in targets:
        hits = res.get(t, [])
        print(f"\n=== {t:#x} : {len(hits)} xrefs ===")
        for a, s in hits:
            print(f"  {a:#x}  {s}")
