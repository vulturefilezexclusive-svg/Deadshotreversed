#!/usr/bin/env python3
"""Map ObjC selector -> implementation addresses using relative method lists."""
import sys, struct, collections
from fixups import Fixups

class SelMap:
    def __init__(self, path):
        self.f = Fixups(path)
        b = self.b = self.f.b
        self.blob = self.f.blob
        self.selrefs = b.get_section("__objc_selrefs")
        self.methname = b.get_section("__objc_methname")
        self.sr_lo = self.selrefs.virtual_address
        self.sr_hi = self.sr_lo + self.selrefs.size
        self.mn_lo = self.methname.virtual_address
        self.mn_hi = self.mn_lo + self.methname.size
        self.map = collections.defaultdict(list)
        self._build()

    def off_of(self, va):
        for seg in self.b.segments:
            if seg.virtual_address <= va < seg.virtual_address + seg.file_size:
                return seg.file_offset + (va - seg.virtual_address)

    def cstr(self, va):
        o = self.off_of(va)
        if o is None: return None
        try: return self.blob[o:self.blob.index(b"\x00", o)].decode("utf-8")
        except Exception: return None

    def selname_via_selref(self, sref_va):
        fx = self.f.by_addr.get(sref_va)
        if not fx: return None
        kind, tgt = fx[0], fx[1]
        if kind in ("rebase", "rebase_auth") and isinstance(tgt, int) and self.mn_lo <= tgt < self.mn_hi:
            return self.cstr(tgt)
        return None

    def _build(self):
        for secname in ("__objc_methlist", "__objc_const"):
            sec = self.b.get_section(secname)
            if sec is None: continue
            base = sec.virtual_address
            for off in range(0, sec.size - 12, 4):
                p = base + off
                name_off, types_off, imp_off = struct.unpack_from("<iii", self.blob, sec.offset + off)
                sref = p + name_off
                if not (self.sr_lo <= sref < self.sr_hi):
                    continue
                name = self.selname_via_selref(sref)
                if not name:
                    continue
                imp = p + 8 + imp_off  # each offset is relative to its own field
                self.map[name].append((p, imp))

if __name__ == "__main__":
    m = SelMap(sys.argv[1])
    print("selectors:", len(m.map), "entries:", sum(len(v) for v in m.map.values()))
    for s in sys.argv[2:]:
        print(f"=== {s}")
        for p, imp in m.map.get(s, []):
            print(f"   entry {p:#x}  imp {imp:#x}")
