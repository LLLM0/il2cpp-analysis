# IL2CPP Binary Analysis

Binary and metadata files for IL2CPP reverse engineering research.

## Files

- `metadata.dat` — Encrypted IL2CPP global metadata (73 MB)
- `startup-metadata.dat` — Startup metadata (3.6 MB)
- `il2cpp_game.exe.part_00` through `part_04` — Game executable split into 5 parts (383 MB total)
- `mscorlib.dll-resources.dat` — mscorlib resources (330 KB)
- `Newtonsoft.Json.dll-resources.dat` — Newtonsoft.Json resources (639 B)
- `System.Memory.dll-resources.dat` — System.Memory resources (1.8 KB)

## Reassembly

```bash
bash reassemble.sh
```

This produces `il2cpp_game.exe` (383 MB).

## Verification

```
il2cpp_game.exe: 400,801,192 bytes
metadata.dat:    75,645,272 bytes
startup-metadata.dat: 3,713,300 bytes
```

## Notes

The metadata uses a custom encryption scheme. See `ANALYSIS.md` and `CRITICAL_FINDING.md` for details.
