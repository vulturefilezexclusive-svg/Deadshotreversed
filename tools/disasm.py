#!/usr/bin/env python3
"""Disassemble one function range of a Mach-O, annotating adrp+add string targets."""
import sys, re
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_OP_REG, CS_OP_IMM

def cstr_at(blob, bin, va, n=120):
    off = None
    for seg in bin.segments:
        if seg.virtual_address <= va < seg.virtual_address + seg.virtual_size and seg.file_size:
            off = seg.file_offset + (va - seg.virtual_address)
            break
    if off is None: return None
    raw = blob[off:off+n]
    s = raw.split(b"\x00")[0]
    try: t = s.decode("utf-8")
    except: return None
    if len(t) < 3 or not all(31 < ord(c) < 127 or ord(c) > 127 for c in t): return None
    return t

def main(path, start, end):
    blob = open(path,"rb").read()
    bin = lief.MachO.parse(path).at(0)
    text = bin.get_section("__text")
    off = text.offset + (start - text.virtual_address)
    code = blob[off: off + (end-start)]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
    regs = {}
    for ins in md.disasm(code, start):
        note = ""
        m, ops = ins.mnemonic, ins.operands
        if m == "adrp" and len(ops)==2 and ops[0].type==CS_OP_REG:
            regs[ops[0].reg] = ops[1].imm
            note = f"; page {ops[1].imm:#x}"
        elif m in ("add","ldr","adr") and len(ops)>=2:
            src = ops[1]; tgt=None
            if m=="adr" and src.type==CS_OP_IMM: tgt=src.imm
            elif src.type==CS_OP_REG and src.reg in regs:
                if len(ops)==3 and ops[2].type==CS_OP_IMM: tgt=regs[src.reg]+ops[2].imm
                elif m=="ldr": tgt=regs[src.reg]
            if tgt is not None:
                s = cstr_at(blob, bin, tgt)
                if s: note = f'; "{s}"'
                else: note = f"; -> {tgt:#x}"
        elif m.startswith("b") and ops and ops[0].type==CS_OP_IMM:
            note = f"; -> {ops[0].imm:#x}"
        print(f"{ins.address:#012x}  {ins.mnemonic:<8} {ins.op_str:<40} {note}")

if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2],0), int(sys.argv[3],0))
