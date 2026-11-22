#!/usr/bin/env python3
"""Find Swift-5.9 style relative-pointer literals (4-byte offsets stored in __const)
that point at the given target VAs."""
import sys, struct, collections
import lief

def scan(path, targets):
    b = lief.MachO.parse(path).at(0)
    data = open(path, "rb").read()
    tset = {t: hex(t) for t in targets}
    hits = collections.defaultdict(list)
    for seg in b.segments:
        for s in seg.sections:
            if s.size == 0 or s.offset == 0:
                continue
            if not (s.name.startswith("__const") or s.name in ("__data","__cstring","__swift5_reflstr","__constg_swiftt")):
                continue
            blob = data[s.offset:s.offset+s.size]
            for off in range(0, len(blob)-3, 4):
                v = struct.unpack_from("<i", blob, off)[0]
                fa = s.virtual_address + off
                if fa + v in tset:
                    hits[fa+v].append((fa, s.name))
    return hits

if __name__ == "__main__":
    path = sys.argv[1]
    targets = [int(x,0) for x in sys.argv[2:]]
    hits = scan(path, targets)
    for t in targets:
        hs = hits.get(t, [])
        print(f"=== {t:#x}: {len(hs)} relative refs ===")
        for fa, sec in hs:
            print(f"   field {fa:#x} in {sec}")
