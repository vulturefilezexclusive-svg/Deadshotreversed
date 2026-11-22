#!/usr/bin/env python3
"""Resolve ObjC (relative) method list entries by selector name -> IMP address."""
import sys, struct, collections
import lief

class Objc:
    def __init__(self, path):
        self.path = path
        self.blob = open(path, "rb").read()
        self.b = lief.MachO.parse(path).at(0)
        self.base = self.b.imagebase
        mn = self.b.get_section("__objc_methname")
        self.methname_off = mn.offset
        self.methname_va = mn.virtual_address
        self.names = {}   # va -> name
        blob = self.blob[mn.offset:mn.offset+mn.size]
        o = 0
        for raw in blob.split(b"\x00"):
            if raw:
                self.names[mn.virtual_address + o] = raw.decode("utf-8", "replace")
            o += len(raw) + 1
        self.mn_size = mn.size
        self.mn_lo = mn.virtual_address
        self.mn_hi = mn.virtual_address + mn.size

    def va_to_off(self, va):
        for seg in self.b.segments:
            if seg.virtual_address <= va < seg.virtual_address + seg.virtual_size and seg.file_size:
                return seg.file_offset + (va - seg.virtual_address)
        return None

    def find_methods(self, selector):
        """Find relative method-list entries naming `selector`; return (entry_va, imp_va)."""
        target_vas = [va for va, n in self.names.items() if n == selector]
        out = []
        for tva in target_vas:
            pat = struct.pack("<i", 0)  # placeholder
            # scan whole file for int32 rel refs resolving to tva
            for off in range(0, len(self.blob) - 12, 4):
                v = struct.unpack_from("<i", self.blob, off)[0]
                # entry VA accounting for segment mapping: entry_va = va_of_off(off)
                eva = None
                for seg in self.b.segments:
                    if seg.file_offset <= off < seg.file_offset + seg.file_size:
                        eva = seg.virtual_address + (off - seg.file_offset)
                        break
                if eva is None:
                    continue
                if eva + v == tva:
                    types_off, imp_off = struct.unpack_from("<ii", self.blob, off+4)
                    imp = eva + imp_off
                    out.append((eva, imp, eva + types_off))
        return out

if __name__ == "__main__":
    o = Objc(sys.argv[1])
    for sel in sys.argv[2:]:
        hits = o.find_methods(sel)
        print(f"=== {sel}: {len(hits)} method entries")
        for eva, imp, tva in hits[:10]:
            tn = o.names.get(tva, "?")
            print(f"   entry {eva:#x}  imp {imp:#x}  types={tn}")
