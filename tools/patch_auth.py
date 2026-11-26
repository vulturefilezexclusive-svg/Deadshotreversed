#!/usr/bin/env python3
"""Force the local authTokenSig validation to resolve trusted (dev bypass).

One in-place patch inside __text:

  0x10008f088  tbz w23, #0, 0x10008f0c0  -> nop

The nil/empty-token guards above the decision still run, so an absent token
still fails; a token whose local signature check disagrees is now accepted.
Useful while the aov.anhvu.cc config sync is out of step with the local check.

Page hashes are recomputed with patch_gate.resign() so the CodeDirectory stays
self-consistent. Run after tools/patch_gate.py, on its output binary.
"""
import sys

import lief

from patch_gate import NOP, resign, va_to_off

# decision branch of the local token validator (see AUTH_PATCH_FINDINGS.txt)
DECISION_VA = 0x10008F088
TBZ_W23 = 0x360001D7  # tbz w23, #0, <imm14>


def main(src, dst):
    blob = bytearray(open(src, "rb").read())
    bin_ = lief.MachO.parse(src).at(0)

    off = va_to_off(bin_, DECISION_VA)
    before = bytes(blob[off:off + 4])
    if before == NOP:
        print("authTokenSig decision %#x already patched" % DECISION_VA)
    else:
        word = int.from_bytes(before, "little")
        if word >> 24 != TBZ_W23 >> 24 or word & 0x1F != 23:
            raise SystemExit(
                "unexpected instruction at %#x: %s (want tbz w23,#0)"
                % (DECISION_VA, before.hex()))
        blob[off:off + 4] = NOP
        print("authTokenSig decision %#x %s -> %s"
              % (DECISION_VA, before.hex(), NOP.hex()))

    n = resign(blob, bin_)
    print("recomputed page hashes for %d CodeDirectory blob(s)" % n)

    open(dst, "wb").write(bytes(blob))
    print("wrote", dst, len(blob), "bytes")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
