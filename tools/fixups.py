#!/usr/bin/env python3
"""Parse LC_DYLD_CHAINED_FIXUPS into a map: vm address -> bound symbol name or rebased target."""
import struct, collections
import lief

CHAINED_IMPORT = 1
CHAINED_IMPORT_ADDEND = 2
CHAINED_IMPORT_ADDEND64 = 3

class Fixups:
    def __init__(self, path):
        self.blob = open(path, "rb").read()
        self.b = lief.MachO.parse(path).at(0)
        self.base = self.b.imagebase
        cmd = [c for c in self.b.commands if type(c).__name__ == "DyldChainedFixups"][0]
        self.off = getattr(cmd, "data_offset", 0) or getattr(cmd, "command_offset", 0)
        self.data_offset = cmd.data_offset
        self.size = cmd.data_size
        d = self.blob[self.data_offset:self.data_offset+self.size]
        (ver, starts_off, imports_off, symbols_off,
         imports_count, imports_format, symbols_fmt) = struct.unpack_from("<7I", d, 0)
        self.ver = ver; self.imports_format = imports_format
        self.imports = []
        for i in range(imports_count):
            if imports_format in (CHAINED_IMPORT, CHAINED_IMPORT_ADDEND):
                raw = struct.unpack_from("<I", d, imports_off + i*4)[0]
                lib_ord = raw & 0xFF
                weak = (raw >> 8) & 1
                name_off = raw >> 9
                addend = 0
                if imports_format == CHAINED_IMPORT_ADDEND:
                    addend = struct.unpack_from("<i", d, imports_off + imports_count*4 + i*4)[0]
                name = self._str(d, symbols_off + name_off)
                self.imports.append(name)
            elif imports_format == CHAINED_IMPORT_ADDEND64:
                raw, addend = struct.unpack_from("<QQ", d, imports_off + i*16)
                name_off = raw >> 32
                self.imports.append(self._str(d, symbols_off + name_off))
        # walk chains
        self.by_addr = {}
        seg_count = struct.unpack_from("<I", d, starts_off)[0]
        for si in range(seg_count):
            seg_info_off = struct.unpack_from("<I", d, starts_off + 4 + si*4)[0]
            if seg_info_off == 0:
                continue
            p = starts_off + seg_info_off
            size, page_size, ptr_format, segment_offset, max_valid, page_count = struct.unpack_from("<IHHQIH", d, p)
            seg = self.b.segments[si]
            for pi in range(page_count):
                page_start = struct.unpack_from("<H", d, p + 22 + pi*2)[0]
                if page_start == 0xFFFF:
                    continue
                pos = segment_offset + pi*page_size + page_start
                while True:
                    va0 = self.base + pos
                    fo = seg.file_offset + (va0 - seg.virtual_address)
                    val = struct.unpack_from("<Q", self.blob, fo)[0]
                    nxt = (val >> 51) & 0x7FF
                    bind = (val >> 62) & 1
                    auth = (val >> 63) & 1
                    va = va0
                    if bind:
                        if ptr_format == 12:  # ARM64E_USERLAND24
                            ordinal = val & 0xFFFFFF
                        else:
                            ordinal = val & 0xFFFF
                        name = self.imports[ordinal] if ordinal < len(self.imports) else f"<ord {ordinal}>"
                        self.by_addr[va] = ("bind", name, auth, val)
                    else:
                        if auth:
                            target = (val & 0xFFFFFFFF) | 0  # 32-bit target for auth rebase
                            # auth rebase target is a 32-bit vm offset from imagebase
                            target = self.base + (val & 0xFFFFFFFF)
                            self.by_addr[va] = ("rebase_auth", target, auth, val)
                        else:
                            target = self.base + (val & 0x7FFFFFFFFFF)
                            self.by_addr[va] = ("rebase", target, auth, val)
                    if nxt == 0:
                        break
                    pos += nxt * 8  # arm64e: next is in 8-byte strides

    @staticmethod
    def _str(d, off):
        end = d.index(b"\x00", off)
        return d[off:end].decode("utf-8", "replace")

    def read_ptr(self, va):
        return self.by_addr.get(va)
