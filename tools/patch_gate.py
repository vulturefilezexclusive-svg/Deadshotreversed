#!/usr/bin/env python3
"""Neutralise the TrollGame key gate in DSGames.

Three in-place patches, all inside __text, all on tiny property getters / one branch:

  0x10008e704  -[TGResult valid]            ldrb w0,[x0,#8]  -> mov w0,#1 ; ret
  0x10008e874  -[... tgOfflineValidated]    ldrb w0,[x0,#0xa] -> mov w0,#1 ; ret
  0x100095db8  startValidationFlow block    b.ne revalidate   -> nop

With `valid` always true and the activationState comparison ignored, the
validation block takes its success path (0x100095e84) and calls onSuccess
instead of prompting for a key or re-polling the server.

The CodeDirectory page hashes are then recomputed in place so the binary still
carries a self-consistent signature (the CMS blob is left as-is).
"""
import hashlib
import struct
import sys

import lief

MOV_W0_1_RET = bytes.fromhex("20008052c0035fd6")  # mov w0,#1 ; ret
NOP = bytes.fromhex("1f2003d5")

PATCHES = [
    (0x10008E704, MOV_W0_1_RET, "TGResult.valid -> true"),
    (0x10008E874, MOV_W0_1_RET, "tgOfflineValidated -> true"),
    (0x100095DB8, NOP, "activationState compare -> always equal"),
]


def va_to_off(bin_, va):
    for seg in bin_.segments:
        if seg.virtual_address <= va < seg.virtual_address + seg.file_size:
            return seg.file_offset + (va - seg.virtual_address)
    raise ValueError("unmapped va %#x" % va)


def resign(blob, bin_):
    """Recompute the CodeDirectory page hashes after the code bytes changed."""
    sc = bin_.code_signature
    base = sc.data_offset
    d = bytearray(blob[base:base + sc.data_size])
    magic, length, count = struct.unpack_from(">III", d, 0)
    assert magic == 0xFADE0CC0, hex(magic)

    fixed = 0
    for i in range(count):
        btype, boff = struct.unpack_from(">II", d, 12 + i * 8)
        if btype != 0:
            continue
        bmagic = struct.unpack_from(">I", d, boff)[0]
        assert bmagic == 0xFADE0C02, hex(bmagic)
        (_, _, _, _, hash_off, _, n_special, n_code, code_limit,
         hash_size, hash_type, _, page_shift, _, _) = struct.unpack_from(
            ">IIIIIIIIIBBBBII", d, boff)
        assert hash_type == 2 and hash_size == 32, (hash_type, hash_size)
        page = 1 << page_shift
        for slot in range(n_code):
            start = slot * page
            end = min(start + page, code_limit)
            digest = hashlib.sha256(blob[start:end]).digest()
            struct.pack_into(">32s", d, boff + hash_off + slot * hash_size, digest)
        fixed += 1

    blob[base:base + sc.data_size] = bytes(d)
    return fixed


def main(src, dst):
    blob = bytearray(open(src, "rb").read())
    bin_ = lief.MachO.parse(src).at(0)

    for va, data, label in PATCHES:
        off = va_to_off(bin_, va)
        before = bytes(blob[off:off + len(data)])
        if before == data:
            print("%-45s %#x already patched" % (label, va))
            continue
        blob[off:off + len(data)] = data
        print("%-45s %#x %s -> %s" % (label, va, before.hex(), data.hex()))

    n = resign(blob, bin_)
    print("recomputed page hashes for %d CodeDirectory blob(s)" % n)

    open(dst, "wb").write(bytes(blob))
    print("wrote", dst, len(blob), "bytes")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
