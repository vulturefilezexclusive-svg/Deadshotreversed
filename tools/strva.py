#!/usr/bin/env python3
"""List C strings in a file-offset window, with their VM addresses."""
import sys, re, lief
path = sys.argv[1]; lo = int(sys.argv[2],0); hi = int(sys.argv[3],0)
b = lief.MachO.parse(path).at(0)
blob = open(path,'rb').read()
segs = [(s.file_offset, s.file_offset+s.file_size, s.virtual_address) for s in b.segments if s.file_size]
def va_of(off):
    for fo, fe, vma in segs:
        if fo <= off < fe: return vma + (off-fo)
    return None
for m in re.finditer(rb'[ -~]{4,}', blob[lo:hi]):
    off = lo+m.start(); va = va_of(off)
    print(f"{off:#09x} va={va:#x}  {m.group().decode()[:110]}" if va else f"{off:#09x} va=?  {m.group().decode()[:110]}")
