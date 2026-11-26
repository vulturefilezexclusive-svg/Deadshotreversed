# Deadshotreversed

iOS arm64 Mach-O reverse-engineering workspace for the DSGames build shipped as
`deadshot_dev_build.ipa` (bundle `com.dsgames.app`, Swift + ObjC, SwiftUI).

## Status

Updated 2026-11-26. Gate neutralised, plus the dev auth bypass below; IPA
rebuilt and pushed to origin (`main` and `master` both at the patch commit).
`tools/pack_ipa.py` preserves entry modes and directory entries; the earlier
repack shipped `DSGames` as 0644, which iOS will not launch.

`tools/patch_auth.py` nops the decision branch of the local `authTokenSig`
validator (0x10008f088), so a token whose local check disagrees is accepted
while a missing/empty token still fails. Not yet proven to be the
`aov.anhvu.cc` config-sync comparison and not verified on a device: see
`AUTH_PATCH_FINDINGS.txt`.

## Run

```
export PYTHONPATH=$PWD/pylibs
python3 tools/patch_gate.py work/Payload/DSGames.app/DSGames work/patched/Payload/DSGames.app/DSGames
python3 tools/patch_auth.py work/patched/Payload/DSGames.app/DSGames work/patched/Payload/DSGames.app/DSGames
python3 tools/pack_ipa.py work/patched/Payload/DSGames.app deadshot_dev_build_unlocked.ipa
```

`pylibs/` holds lief and capstone; there is no system `file`, `strings`, `zip`
or `codesign` on this image, so every step is Python.

## Map

- `work/Payload/DSGames.app/` original extract, `work/patched/Payload/` patched tree.
- `tools/fixups.py` parses `LC_DYLD_CHAINED_FIXUPS`; `classmap.py`, `selmap.py`,
  `objc.py` resolve ObjC classes, selectors and IMPs.
- `tools/xrefs_fn.py`, `ref_scan.py`, `callers.py` walk per-function (from
  `LC_FUNCTION_STARTS`) so a linear sweep does not desync.
- `tools/disasm.py`, `dumpfn.py` annotate adrp+add string targets.
- `tools/patch_gate.py` and `tools/patch_auth.py` the patches, `tools/pack_ipa.py`
  the repack.

## Decisions

- Selector xrefs are found by decoding `__objc_stubs` (32-byte entries, raw
  adrp+ldr) and then looking for `bl` to that stub. `bl` to an IMP finds
  nothing: Swift classes dispatch through stubs and vtables.
- Method lists are relative (`int32` offsets from each field), so entry
  resolution must add the field address, not deref a chained fixup.
- The key gate is TrollGameKit. `-[TGResult valid]` (0x10008e704) and
  `tgOfflineValidated` (0x10008e874) are one-instruction getters; the
  validation block at 0x100095da0 does `valid && activationState == 0xa` before
  taking its success path. Making both getters return 1 and nop-ing the
  `b.ne` at 0x100095db8 means the flow always calls onSuccess.
- The binary carries a real CMS signature; patching code invalidates the
  CodeDirectory page hashes, so `patch_gate.py` recomputes them in place
  (same blob size, CMS untouched). 4458/4458 pages verify afterwards.
- `.dsi-m1` stores a sha256 that does not match the shipped binary, so it is
  not a live integrity check of `DSGames` as-is. It holds
  `e8590eab…`; the original `DSGames` hashes to `d8fb516b…` and the patched
  one to `e8b00bd7…`. Neither matches, so it is left untouched.
- The main executable must stay 0755 inside the zip. `pack_ipa.py` writes
  `Payload/`, `Payload/DSGames.app/` and `Frameworks/` directory entries and
  sets `Payload/DSGames.app/DSGames` to 0755; the patched IPA then has the same
  16 entries as the original.
