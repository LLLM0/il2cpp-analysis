# Critical Finding: Cipher XOR Structure

## The Key Discovery

The decrypt loop applies an **ADDITIONAL XOR** after `cipher_process`:

```
plaintext = cipher_process(ciphertext) XOR ciphertext
```

This means `cipher_process` generates a **keystream**, and the final
decryption is a simple XOR of keystream with ciphertext.

## Target Value

For block 0, third 16-byte chunk (file[32:48]):
- Ciphertext first 4 bytes: `0x2607257A`
- Target plaintext first 4 bytes: `0xFAB11BAF` (IL2CPP magic)
- **Needed cipher_process output: `0xDCB63ED5`**

This is the SAME value as the 4-byte XOR key found in the first session!
The `0xDCB63ED5` is NOT a simple repeating key — it's the first 4 bytes
of a 16-byte keystream produced by `cipher_process`.

## Brute-Force Target

Instead of checking for `0xFAB11BAF` in the output, we need to check for
`0xDCB63ED5` as the cipher_process output (before the XOR with ciphertext).

## File Structure

- 256 blocks at stride `0x48240` (295,488 bytes)
- Each block: 4 × 16-byte chunks = 64 bytes encrypted
- Total encrypted: 16,384 bytes (0.02% of file)
- Rest is plaintext (string literals, numeric data)

## Cipher Chain

1. `MT19937-64(seed=malloc_addr)` → 4 PRNG values
2. `SipHash(PRNG, key=0)` → 32-byte cipher_state (5 calls, modified constants)
3. `keyblock_init(cipher_state, hardcoded_key)` → processed key
4. `cipher_process(processed_key, cipher_state, input)` → 16-byte keystream
5. `plaintext = keystream XOR ciphertext`
