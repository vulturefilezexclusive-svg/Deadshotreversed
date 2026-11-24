#!/usr/bin/env python3
"""Repack a Payload/*.app tree into an .ipa, mirroring the original entry order.

Entry metadata is preserved rather than flattened: the main executable keeps its
executable bit (iOS refuses to launch a bundle whose main binary is 0644), every
other file is 0644, and every directory gets its own 0755 entry, including
`Payload/` above the .app.
"""
import os
import stat
import sys
import zipfile

DIR_MODE = 0o40755
FILE_MODE = 0o100644
EXEC_MODE = 0o100755


def add_dir(z, rel):
    info = zipfile.ZipInfo(rel.replace(os.sep, "/") + "/")
    info.external_attr = DIR_MODE << 16
    info.compress_type = zipfile.ZIP_STORED
    z.writestr(info, b"")


def main(app_dir, out_ipa):
    app_dir = app_dir.rstrip("/")
    root = os.path.dirname(os.path.dirname(app_dir))
    # The app bundle's own executable: Payload/<Name>.app/<Name>
    app_name = os.path.basename(app_dir)
    main_exe = os.path.join(app_dir, app_name[:-4] if app_name.endswith(".app") else app_name)

    with zipfile.ZipFile(out_ipa, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for parent in (os.path.join(root, "Payload"), app_dir):
            add_dir(z, os.path.relpath(parent, root))
        for dirpath, dirnames, filenames in os.walk(app_dir):
            dirnames.sort()
            if dirpath != app_dir:
                add_dir(z, os.path.relpath(dirpath, root))
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                executable = full == main_exe or os.stat(full).st_mode & stat.S_IXUSR
                info = zipfile.ZipInfo(rel)
                info.external_attr = (EXEC_MODE if executable else FILE_MODE) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(full, "rb") as fh:
                    z.writestr(info, fh.read())
    print("wrote", out_ipa, os.path.getsize(out_ipa), "bytes")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
