#!/usr/bin/env python3
"""Map ObjC class name -> methods (name, imp) using chained fixups + relative method lists."""
import sys, struct, collections
from fixups import Fixups

class ClassMap:
    def __init__(self, path):
        self.f = Fixups(path); b = self.b = self.f.b; self.blob = self.f.blob
        self.mn = b.get_section("__objc_methname"); self.mn_lo = self.mn.virtual_address
        self.mn_hi = self.mn_lo + self.mn.size
        self.sr = b.get_section("__objc_selrefs")
        self.sr_lo = self.sr.virtual_address; self.sr_hi = self.sr_lo + self.sr.size
        self.cn = b.get_section("__objc_classname")
        self.cn_lo = self.cn.virtual_address; self.cn_hi = self.cn_lo + self.cn.size
        self.classes = {}
        self._build()
    def off_of(self, va):
        for seg in self.b.segments:
            if seg.virtual_address <= va < seg.virtual_address + seg.file_size:
                return seg.file_offset + (va - seg.virtual_address)
    def cstr(self, va):
        if va is None: return None
        o = self.off_of(va)
        if o is None: return None
        try: return self.blob[o:self.blob.index(b"\x00", o)].decode("utf-8", "replace")
        except Exception: return None
    def deref(self, va):
        fx = self.f.by_addr.get(va)
        if fx and isinstance(fx[1], int): return fx[1]
        return None
    def in_image(self, va):
        for seg in self.b.segments:
            if seg.virtual_address <= va < seg.virtual_address + seg.file_size:
                return True
        return False
    def methods(self, ml_va):
        o = self.off_of(ml_va)
        if o is None or o + 8 > len(self.blob): return
        entsize, count = struct.unpack_from("<II", self.blob, o)
        if entsize < 12 or entsize > 64 or count > 20000: return
        o += 8
        for i in range(count):
            p = ml_va + 8 + i*entsize
            if not self.in_image(p): break
            name_off, types_off, imp_off = struct.unpack_from("<iii", self.blob, o + i*entsize)
            name = self.cstr(self.deref(p + name_off))
            if not name: continue
            imp = p + 8 + imp_off
            yield name, imp
    def _build(self):
        sec = self.b.get_section("__objc_classlist")
        base = sec.virtual_address
        for i in range(sec.size // 8):
            cls = self.deref(base + i*8)
            if cls is None: continue
            if not cls: continue
            o = self.off_of(cls)
            if o is None: continue
            # class_t: isa, superclass, cache, vtable, data
            data = self.deref(cls + 0x20)
            if not data: continue
            cname = self.cstr(self.deref(data + 0x18))  # class_ro_t.name
            if not cname: continue
            ro = self.off_of(data)
            if ro is None: continue
            # class_ro_t: flags(4) instanceStart(4) instanceSize(4) reserved(4) ivarLayout(8) name(8) baseMethods(8)
            baseMethods = self.deref(data + 0x20)
            meths = []
            if baseMethods: meths = list(self.methods(baseMethods))
            # class methods
            meta = self.deref(cls)
            if meta:
                mdata = self.deref(meta + 0x20)
                if mdata:
                    mb = self.deref(mdata + 0x20)
                    if mb:
                        meths = [("+"+n, imp) for n, imp in self.methods(mb)] + meths
            self.classes[cname] = (cls, meths)

if __name__ == "__main__":
    cm = ClassMap(sys.argv[1])
    names = sorted(cm.classes)
    if len(sys.argv) == 2:
        for n in names: print(n)
    else:
        import re
        pat = re.compile(sys.argv[2], re.I)
        for n in names:
            if pat.search(n):
                print(f"### {n}  cls={cm.classes[n][0]:#x}")
                for mn, imp in cm.classes[n][1]:
                    print(f"    {mn}  -> {imp:#x}")
