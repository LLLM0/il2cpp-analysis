# IL2CPP Metadata Decryption Analysis

## File Structure

The metadata file has the following structure:
- **Offset 0-31**: MHY header (`MHY\0\0\0\0\0` + 24 bytes key material)
- **Offset 32+**: Encrypted IL2CPP metadata (75,645,240 bytes)
- **Total size**: 75,645,272 bytes

The file is divided into 256 blocks of 0x48240 bytes each.

## Encryption Scheme

The encryption uses a custom cipher chain:

### 1. PRNG (MT19937-64 Modified)
- **Seed**: `malloc(0x4000)` address (runtime heap address)
- **Seeding**: SplitMix64 with multiplier 0x5851F42D4C957F2D
- **State**: 312 x 64-bit values
- **Tempering** (modified):
  - `x ^= (x >> 29) & 0x5555555555555555`
  - `x ^= (x << 17) & 0x71D67FFFEDA60000`
  - `x ^= ((x & 0xFFFFFFFF) & 0x07FFBF77) << 37` (non-standard mask)
  - `x ^= x >> 43`
- **Output**: 4 x 64-bit PRNG values

### 2. SipHash (Modified)
- **Key**: All zeros (16 bytes)
- **Constants** (non-standard):
  - v0 = `0x736f6d6570736575` ^ k0 ("somepseu")
  - v1 = `0x646f72616e646f6d` ^ k1 ("dorandom")
  - v2 = `0x6c7967656e657261` ^ k0 (NON-STANDARD! "arenegyl")
  - v3 = `0x7465646279746573` ^ k1 ("byteste")
- **Round structure** (modified):
  - v3 ^= m happens AFTER v0/v1 update (not before)
  - Extra v3 ^= v0 between rounds
  - Round 2 does NOT have v3 ^= m
- **Finalization** (4 rounds, modified):
  - v2 ^= 0xFF at specific point
  - Round 4 is PARTIAL (missing some operations)
  - Result = `v1 ^ v2 ^ v3 ^ rotl(v2, 32)` (NOT v0^v1^v2^v3)
- **Output**: 32-byte cipher_state (4 SipHash calls with lengths 0x20, 0x18, 0x10, 0x08)

### 3. Key Block Processing
- **Hardcoded key**: 0xB00 bytes at VA 0x144D76E60 in the binary
- **keyblock_init**: Processes the hardcoded key using the cipher_state
- **Output**: 0xE50-byte processed key block

### 4. Block Cipher (cipher_process)
- **cipher_init**: Processes cipher_state into a 0xB00-byte temp buffer
  - Uses constants 0xDEADCAFEFACEB00C and 0x0CB0CEFAFECAADDE
  - Magic constant 0x19260817 (Chinese meme number)
- **byte_expansion**: Expands each input byte to 16 bytes using MT19937-32 (seed 103) lookup table
- **3-way XOR**: `output = temp_buf XOR byte_expansion(input) XOR key_block`
- **CBC mode**: 256 blocks of 64 bytes

## Key Functions

| Function | Address | Description |
|----------|---------|-------------|
| decrypt_main | 0x140838640 | Main decrypt function |
| PRNG_init | 0x140837750 | MT19937-64 initialization |
| PRNG_next | 0x140835800 | MT19937-64 next value |
| SipHash | 0x140837220 | Modified SipHash-2-4 |
| cipher_state_init | 0x140835880 | Derive cipher_state from PRNG |
| keyblock_init | 0x1408359C0 | Process hardcoded key |
| cipher_process | 0x1408359F0 | Decrypt 16-byte block |
| cipher_init | 0x14082F150 | Initialize cipher state buffer |
| byte_expansion | 0x14082E3C0 | Expand byte to 16 bytes |
| MT19937-32_init | 0x14082E150 | MT19937-32 (seed 103) for lookup table |

## Important Notes

1. **key4/5/6 are NEVER READ**: The PRNG-derived keys (which depend on malloc address) are computed but never used. The ONLY PRNG dependency is through the cipher_state.

2. **rand() is non-deterministic**: The rand() function reads from a system source (urandom/RtlGenRandom). The magic 0xFC2E check in the file tail likely fails, so the hardcoded key IS used.

3. **Stack alignment**: keyblock_init requires 16-byte aligned stack for `movaps` instructions.

4. **Python implementations verified**: MT19937-64 and SipHash match Unicorn output exactly.

## Current Status

- Full cipher chain implemented and verified
- Brute-force speed: 48/s with 4 workers (Python PRNG + Unicorn cipher)
- Scanned: 0x0 - 0x60000000 (1.5GB) with no match
- The PRNG seed (malloc address) is the only remaining unknown

## Files

- `siphash_v6.py` - Verified SipHash implementation
- `reverse_cipher.py` - Python cipher chain (MT19937-64 + SipHash)
- `brute_force_v4.py` - Fixed brute-force with stack alignment
- `metadata.dat` - Encrypted metadata file
- `il2cpp_game.exe.part_*` - Binary split into 5 parts
