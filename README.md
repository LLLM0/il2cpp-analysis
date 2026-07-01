# IL2CPP Binary Analysis

Binary and metadata files for IL2CPP reverse engineering research.

## Files

- `metadata.dat` — Encrypted IL2CPP global metadata (73 MB)
- `il2cpp_game.exe.part_00` through `part_04` — Game executable split into 5 parts (383 MB total)

## Reassembly

```bash
bash reassemble.sh
```

This produces `il2cpp_game.exe` (383 MB).

## Verification

```
il2cpp_game.exe: 400,801,192 bytes
metadata.dat:    75,645,272 bytes
```

## Notes

The metadata uses a custom encryption scheme. Analysis scripts are in the `scripts/` directory of the analysis project.
