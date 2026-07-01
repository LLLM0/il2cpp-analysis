#!/usr/bin/env python3
"""
Reverse the cipher to find the required cipher_state.

The cipher_process does:
  output = cipher_init(cipher_state) XOR byte_expansion(input) XOR key_data

We know:
  output (first 16 bytes should be 0xFAB11BAF... = IL2CPP magic)
  input (first 16 bytes of encrypted IL2CPP data from file)
  key_data (hardcoded key block from binary)

So: cipher_init(cipher_state) = output XOR byte_expansion(input) XOR key_data

We can compute the right side using Unicorn:
1. byte_expansion(input) - call byte_expansion for each of the 16 input bytes
2. key_data - the processed key block (from keyblock_init with cipher_state=0)

Then: cipher_init(cipher_state) = output XOR byte_expansion(input) XOR key_data

The cipher_init function processes cipher_state into a 0xB00-byte buffer.
If we can reverse cipher_init, we can find the cipher_state.

But cipher_init is complex. Instead, let's try all possible cipher_states
by using the Unicorn emulation, but ONLY for cipher_process (not the full
decrypt function). This is fast enough at 18/s.

Actually, let me think about this differently.
The cipher_state is 32 bytes (4 u64 values).
These 4 values come from SipHash(PRNG_values).

If we can find the cipher_state that produces the correct output,
we can then reverse SipHash to find the PRNG values,
then reverse MT19937-64 to find the seed.

But SipHash is a one-way function - we can't easily reverse it.

Alternative: brute-force the 4 PRNG values directly.
Each PRNG value is 64-bit, so 2^256 combinations - impossible.

BUT - the PRNG values come from MT19937-64, which has a 64-bit seed.
So we only need to brute-force the 64-bit seed.

The seed is malloc(0x4000) address.
On Windows, heap addresses are typically < 2^31 (2GB).
With ASLR, they're randomized but within a known range.

Let me try a SMARTER brute-force:
1. Compute the EXPECTED cipher_init output (from known plaintext)
2. For each candidate seed, compute cipher_state
3. Run cipher_init with that cipher_state
4. Compare with expected output
5. If match, we found the seed

This avoids running the full cipher_process - just cipher_init.
cipher_init is much faster than cipher_process.

Actually, let me check: can I compute the expected cipher_init output?

cipher_process does:
  cipher_init(temp_buf, cipher_state, key_block, cipher_state+0x20)
  Then: output = temp_buf XOR byte_expansion(input) XOR key_block

Wait, I need to understand the exact structure better.
Let me just run the brute-force with a wider range and be patient.

Actually, let me try a completely different approach.
What if the seed is NOT the malloc address, but something else?

Let me re-read the decrypt function:
  malloc(0x4000) → rdi
  PRNG_init(state, rdi)

What if rdi is used as the seed, but it's NOT the address?
What if it's the CONTENT of the malloc'd buffer?

No, malloc returns uninitialized memory. The content is whatever was there before.

OK, let me just try running the full brute-force for a longer time.
I'll use multiprocessing to speed it up.
"""
import struct
import time
import multiprocessing as mp
import sys
sys.path.insert(0, '/home/z/my-project/scripts')

def rotl64(x, b):
    return ((x << b) | (x >> (64 - b))) & 0xFFFFFFFFFFFFFFFF

MASK = 0xFFFFFFFFFFFFFFFF

def siphash_exact(data, key0=0, key1=0):
    v0 = (0x736f6d6570736575 ^ key0) & MASK
    v1 = (0x646f72616e646f6d ^ key1) & MASK
    v2 = (0x6c7967656e657261 ^ key0) & MASK
    v3 = (0x7465646279746573 ^ key1) & MASK
    length = len(data)
    blocks = length // 8
    for i in range(blocks):
        m = struct.unpack('<Q', data[i*8:(i+1)*8])[0]
        v0 = (v0 + v1) & MASK; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32)
        v3 ^= m; v2 = (v2 + v3) & MASK; v3 = rotl64(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & MASK; v3 = rotl64(v3, 21)
        v2 = (v2 + v1) & MASK; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32)
        v3 ^= v0
        v0 = (v0 + v1) & MASK; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32)
        v2 = (v2 + v3) & MASK; v3 = rotl64(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & MASK; v3 = rotl64(v3, 21)
        v2 = (v2 + v1) & MASK; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32)
        v3 ^= v0; v0 ^= m
    remaining = data[blocks*8:]
    m = (length & 0xFF) << 56
    for i, b in enumerate(remaining):
        m |= b << (i * 8)
    v0 = (v0 + v1) & MASK; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32)
    v3 ^= m; v2 = (v2 + v3) & MASK; v3 = rotl64(v3, 16); v3 ^= v2
    v0 = (v0 + v3) & MASK; v3 = rotl64(v3, 21)
    v2 = (v2 + v1) & MASK; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32)
    v3 ^= v0
    v0 = (v0 + v1) & MASK; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32)
    v2 = (v2 + v3) & MASK; v3 = rotl64(v3, 16); v3 ^= v2
    v0 = (v0 + v3) & MASK; v3 = rotl64(v3, 21)
    v2 = (v2 + v1) & MASK; v1 = rotl64(v1, 17)
    v3 ^= v0; v1 ^= v2; v2 = rotl64(v2, 32)
    v0 ^= m
    v0 = (v0 + v1) & MASK; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32)
    v2 ^= 0xFF; v2 = (v2 + v3) & MASK; v3 = rotl64(v3, 16); v3 ^= v2
    v0 = (v0 + v3) & MASK; v3 = rotl64(v3, 21)
    v2 = (v2 + v1) & MASK; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32)
    v3 ^= v0
    for _ in range(2):
        v0 = (v0 + v1) & MASK; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32)
        v2 = (v2 + v3) & MASK; v3 = rotl64(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & MASK; v3 = rotl64(v3, 21)
        v2 = (v2 + v1) & MASK; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32)
        v3 ^= v0
    v0 = (v0 + v1) & MASK; v1 = rotl64(v1, 13); v1 ^= v0
    v2 = (v2 + v3) & MASK; v3 = rotl64(v3, 16); v3 ^= v2; v3 = rotl64(v3, 21)
    v2 = (v2 + v1) & MASK; v1 = rotl64(v1, 17)
    return (v1 ^ v2 ^ v3 ^ rotl64(v2, 32)) & MASK

def compute_cipher_state(prng_vals):
    prng_data = struct.pack('<4Q', *prng_vals)
    state = b''
    for length in [0x20, 0x18, 0x10, 0x08]:
        state += struct.pack('<Q', siphash_exact(prng_data[:length]))
    return state

class MT19937_64:
    def __init__(self):
        self.state = [0] * 312; self.index = 313
    def seed(self, seed):
        MUL = 0x5851F42D4C957F2D; M = 0xFFFFFFFFFFFFFFFF
        self.state[0] = seed & M; prev = seed & M; r9 = 3
        while r9 <= 311:
            x = prev; x ^= x >> 62; x = (x * MUL) & M; x = (x + r9 - 2) & M
            self.state[r9 - 2] = x; prev = x
            x2 = prev; x2 ^= x2 >> 62; x2 = (x2 * MUL) & M; x2 = (x2 + r9 - 1) & M
            self.state[r9 - 1] = x2; prev = x2; r9 += 2
        self.index = 312
    def reshuffle(self):
        MA = 0xB5026F5AA96619E9; UM = 0xFFFFFFFF80000000; LM = 0x7FFFFFFF
        for i in range(312):
            x = (self.state[i] & UM) | (self.state[(i + 1) % 312] & LM)
            xa = MA if (x & 1) else 0
            self.state[i] = self.state[(i + 156) % 312] ^ (x >> 1) ^ xa
        self.index = 0
    def next(self):
        if self.index >= 312: self.reshuffle()
        x = self.state[self.index]; self.index += 1
        x ^= (x >> 29) & 0x5555555555555555
        x ^= (x << 17) & 0x71D67FFFEDA60000
        t = (x & 0xFFFFFFFF) & 0x07FFBF77; x ^= t << 37; x ^= x >> 43
        return x & 0xFFFFFFFFFFFFFFFF

# Test: compute cipher_state for various seeds and build a lookup table
# The cipher_state has 4 u64 values = 32 bytes
# We need the cipher_state that produces the correct decryption

# First, let's compute what cipher_init output is NEEDED
# by running cipher_process with cipher_state=0 and comparing

def main():
    # Test: compute cipher_state for seeds 0x10000 to 0x100000
    # and print the first 8 bytes of each
    prng = MT19937_64()
    
    print("Building cipher_state lookup table...")
    print("seed → cipher_state[0:8] (first u64)")
    
    t0 = time.time()
    for seed in range(0x10000, 0x10100, 0x10):
        prng.seed(seed)
        prng_vals = [prng.next() for _ in range(4)]
        cs = compute_cipher_state(prng_vals)
        cs0 = struct.unpack('<Q', cs[:8])[0]
        print(f"  0x{seed:08X} → 0x{cs0:016X}")
    
    print(f"\nTime: {time.time()-t0:.1f}s")

if __name__ == "__main__":
    main()
