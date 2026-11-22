#!/usr/bin/env python3
"""Build selector -> [(method_list_entry_va, imp_va)] using dyld chained fixups."""
import sys
from fixups import Fixups

class ObjcMap:
    def __init__(self, path):
        self.f = Fixups(path)
        b = self.f.b
        self.b = b
        self.mn = b.get_section("__objc_methname")
        self.mn_lo = self.mn.virtual_address
        self.mn_hi = self.mn.virtual_address + self.mn.size
        self.blob = self.f.blob
        self.sel = {}
        for va, (kind, tgt, auth, val) in self.f.by_addr.items():
            if kind not in ("rebase", "rebase_auth"):
                continue
            if not (self.mn_lo <= tgt < self.mn_hi):
                continue
            # candidate method-list name field; the imp field is 16 bytes later
            imp = self.f.by_addr.get(va + 16)
            if imp is None:
                continue
            name = self.cstr(tgt)
            if not name:
                continue
            imp_va = imp[1] if imp[0] in ("rebase", "rebase_auth") else None
            self.sel.setdefault(name, []).append((va, imp_va, imp[0]))

    def cstr(self, va):
        off = None
        for seg in self.b.segments:
            if seg.virtual_address <= va < seg.virtual_address + seg.file_size:
                off = seg.file_offset + (va - seg.virtual_address)
                break
        if off is None:
            return None
        end = self.blob.index(b"\x00", off)
        try:
            return self.blob[off:end].decode("utf-8")
        except Exception:
            return None

if __name__ == "__main__":
    m = ObjcMap(sys.argv[1])
    print("selectors with impls:", len(m.sel))
    for s in sys.argv[2:]:
        hits = m.sel.get(s, [])
        print(f"=== {s}: {len(hits)}")
        for entry, imp, kind in hits[:10]:
            print(f"   entry {entry:#x} imp {imp if imp is None else hex(imp)} ({kind})")
