# Deadshotreversed

Reverse-engineering notes and patch tooling for the DSGames iOS build
(`com.dsgames.app`) that ships in this repo as an `.ipa`.

The build carries a TrollGameKit key gate: at launch it asks for a licence key,
validates it against `https://trollgame.app`, and only then lets the rest of the
app run. `tools/patch_gate.py` removes that requirement from the binary and
`tools/pack_ipa.py` repacks the result.

## Patch

```
export PYTHONPATH=$PWD/pylibs
python3 tools/patch_gate.py work/Payload/DSGames.app/DSGames work/patched/Payload/DSGames.app/DSGames
python3 tools/pack_ipa.py work/patched/Payload/DSGames.app deadshot_dev_build_unlocked.ipa
```

Three instructions change:

| address | before | after |
| --- | --- | --- |
| 0x10008e704 | `ldrb w0,[x0,#8]` (`-[TGResult valid]`) | `mov w0,#1` |
| 0x10008e874 | `ldrb w0,[x0,#0xa]` (`tgOfflineValidated`) | `mov w0,#1` |
| 0x100095db8 | `b.ne` on `activationState == 0xa` | `nop` |

The CodeDirectory page hashes are recomputed in place afterwards, so the
patched binary still carries a self-consistent signature: 4458/4458 pages
verify in `work/patched/Payload/DSGames.app/DSGames` (the shipped original has
3 stale pages).

## Install

`deadshot_dev_build_unlocked.ipa` is the patched build. Install it the same way
as the original (TrollStore or a re-sign of your choice).

Python 3.8+ with `lief` and `capstone` (vendored in `pylibs/`).
