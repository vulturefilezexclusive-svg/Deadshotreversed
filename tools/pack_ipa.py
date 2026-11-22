#!/usr/bin/env python3
"""Repack a Payload/*.app tree into an .ipa, mirroring the original entry order."""
import os
import sys
import zipfile


def main(app_dir, out_ipa):
    root = os.path.dirname(os.path.dirname(app_dir.rstrip("/")))
    with zipfile.ZipFile(out_ipa, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for dirpath, dirnames, filenames in os.walk(app_dir):
            dirnames.sort()
            rel_dir = os.path.relpath(dirpath, root)
            if not filenames:
                z.writestr(rel_dir.replace(os.sep, "/") + "/", b"")
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                info = zipfile.ZipInfo(rel)
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(full, "rb") as fh:
                    z.writestr(info, fh.read())
    print("wrote", out_ipa, os.path.getsize(out_ipa), "bytes")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
