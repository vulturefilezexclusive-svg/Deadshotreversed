#!/usr/bin/env python3
"""Per-function ARM64 xref scanner: finds code that materializes a target VA
(adrp+add/ldr, adr, or movz/movk pairs). Avoids linear-sweep desync by
disassembling each function from LC_FUNCTION_STARTS separately."""
import sys, collections, struct
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_OP_REG, CS_OP_IMM

class Image:
    def __init__(self, path):
        self.path = path
        self.blob = open(path, "rb").read()
        self.bin = lief.MachO.parse(path).at(0)
        self.text = self.bin.get_section("__text")
        self.fn = [c for c in self.bin.commands if type(c).__name__ == "FunctionStarts"][0]
        starts = [self.bin.imagebase + f for f in self.fn.functions]
        # function_starts may be relative to imagebase already
        if starts[0] < self.text.virtual_address:
            starts = [f for f in self.fn.functions]
        starts.sort()
        self.starts = starts
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True

    def func_at(self, addr):
        import bisect
        i = bisect.bisect_right(self.starts, addr) - 1
        return self.starts[i] if i >= 0 else None

    def code_of(self, addr):
        i = self.starts.index(addr)
        end = self.starts[i+1] if i+1 < len(self.starts) else self.text.virtual_address + self.text.size
        off = addr - self.text.virtual_address + self.text.offset
        return self.blob[off: off + (end-addr)]

    def scan(self, targets):
        tset = set(targets)
        hits = collections.defaultdict(list)
        for fstart in self.starts:
            code = self.code_of(fstart)
            regs = {}
            for ins in self.md.disasm(code, fstart):
                m, ops = ins.mnemonic, ins.operands
                if m == "adrp" and len(ops) == 2 and ops[0].type == CS_OP_REG:
                    regs[ops[0].reg] = ops[1].imm
                    if ops[1].imm in tset:
                        hits[ops[1].imm].append((fstart, ins.address, "adrp-page"))
                elif m in ("add", "ldr", "adr") and len(ops) >= 2:
                    src = ops[1]
                    tgt = None
                    if m == "adr" and src.type == CS_OP_IMM:
                        tgt = src.imm
                    elif src.type == CS_OP_REG and src.reg in regs:
                        if len(ops) == 3 and ops[2].type == CS_OP_IMM:
                            tgt = regs[src.reg] + ops[2].imm
                        elif m == "ldr":
                            tgt = regs[src.reg]
                    if tgt in tset:
                        hits[tgt].append((fstart, ins.address, f"{m} {ins.op_str}"))
                if m in ("movz","movk") and ops and ops[0].type == CS_OP_REG:
                    pass
        return hits

if __name__ == "__main__":
    path = sys.argv[1]
    targets = [int(x,0) for x in sys.argv[2:]]
    img = Image(path)
    hits = img.scan(targets)
    for t in targets:
        hs = hits.get(t, [])
        print(f"=== {t:#x}: {len(hs)} hits ===")
        for fstart, a, kind in hs[:20]:
            print(f"   fn {fstart:#x}  {a:#x}  {kind}")
