#!/usr/bin/env python3
"""
EXACT SipHash implementation - instruction-by-instruction match.

Key findings from complete disassembly:
1. v2 constant = 0x6c7967656e657261 (non-standard)
2. NO v3 ^= v0 after v3 = rotl(v3, 21) in any round
3. v3 ^= v0 is a SEPARATE operation BETWEEN rounds (not inside rounds)
4. Round 2 does NOT have v3 ^= m
5. Finalization: 4 rounds, v2 ^= 0xFF at start of round 1
6. Round 4 is PARTIAL: missing v0=rotl(v0,32), v0+=v3, and v1^=v2 is part of result
7. Result = v1 ^ v2 ^ v3 ^ rotl(v2, 32)

Register mapping:
  rbp = v0, rdi = v1, rsi = v2, rbx = v3
  r14 = message block m
"""
import struct

def rotl64(x, b):
    return ((x << b) | (x >> (64 - b))) & 0xFFFFFFFFFFFFFFFF

MASK = 0xFFFFFFFFFFFFFFFF

def siphash_exact(data, key0=0, key1=0):
    v0 = (0x736f6d6570736575 ^ key0) & MASK  # rbp
    v1 = (0x646f72616e646f6d ^ key1) & MASK  # rdi
    v2 = (0x6c7967656e657261 ^ key0) & MASK  # rsi (NON-STANDARD!)
    v3 = (0x7465646279746573 ^ key1) & MASK  # rbx
    
    length = len(data)
    blocks = length // 8
    
    for i in range(blocks):
        m = struct.unpack("<Q", data[i*8:(i+1)*8])[0]
        
        # Round 1 (with v3 ^= m)
        v0 = (v0 + v1) & MASK          # add rbp, rdi
        v1 = rotl64(v1, 13); v1 ^= v0  # rol rdi,13; xor rdi,rbp
        v0 = rotl64(v0, 32)            # rol rbp,32
        v3 ^= m                        # xor rbx, rax
        v2 = (v2 + v3) & MASK          # add rsi, rbx
        v3 = rotl64(v3, 16); v3 ^= v2  # rol rbx,16; xor rbx,rsi
        v0 = (v0 + v3) & MASK          # add rbp, rbx
        v3 = rotl64(v3, 21)            # rol rbx,21  (NO v3 ^= v0!)
        v2 = (v2 + v1) & MASK          # add rsi, rdi
        v1 = rotl64(v1, 17); v1 ^= v2  # rol rdi,17; xor rdi,rsi
        v2 = rotl64(v2, 32)            # rol rsi,32
        
        # Extra XOR between rounds
        v3 ^= v0                       # xor rbx, rbp
        
        # Round 2 (NO v3 ^= m)
        v0 = (v0 + v1) & MASK
        v1 = rotl64(v1, 13); v1 ^= v0
        v0 = rotl64(v0, 32)
        v2 = (v2 + v3) & MASK
        v3 = rotl64(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & MASK
        v3 = rotl64(v3, 21)            # (NO v3 ^= v0!)
        v2 = (v2 + v1) & MASK
        v1 = rotl64(v1, 17); v1 ^= v2
        v2 = rotl64(v2, 32)
        
        # Extra XOR + v0 ^= m
        v3 ^= v0
        v0 ^= m
    
    # Last block (with length byte)
    remaining = data[blocks*8:]
    m = (length & 0xFF) << 56
    for i, b in enumerate(remaining):
        m |= b << (i * 8)
    
    # Round 1 (with v3 ^= m)
    v0 = (v0 + v1) & MASK
    v1 = rotl64(v1, 13); v1 ^= v0
    v0 = rotl64(v0, 32)
    v3 ^= m
    v2 = (v2 + v3) & MASK
    v3 = rotl64(v3, 16); v3 ^= v2
    v0 = (v0 + v3) & MASK
    v3 = rotl64(v3, 21)
    v2 = (v2 + v1) & MASK
    v1 = rotl64(v1, 17); v1 ^= v2
    v2 = rotl64(v2, 32)
    
    v3 ^= v0  # extra
    
    # Round 2 (NO v3 ^= m)
    v0 = (v0 + v1) & MASK
    v1 = rotl64(v1, 13); v1 ^= v0
    v0 = rotl64(v0, 32)
    v2 = (v2 + v3) & MASK
    v3 = rotl64(v3, 16); v3 ^= v2
    v0 = (v0 + v3) & MASK
    v3 = rotl64(v3, 21)
    v2 = (v2 + v1) & MASK
    v1 = rotl64(v1, 17)
    v3 ^= v0  # extra (order doesn't matter - independent of v1^=v2)
    v1 ^= v2
    v2 = rotl64(v2, 32)
    
    v0 ^= m
    
    # === Finalization (4 rounds) ===
    # Round 1 (with v2 ^= 0xFF)
    v0 = (v0 + v1) & MASK
    v1 = rotl64(v1, 13); v1 ^= v0
    v0 = rotl64(v0, 32)
    v2 ^= 0xFF
    v2 = (v2 + v3) & MASK
    v3 = rotl64(v3, 16); v3 ^= v2
    v0 = (v0 + v3) & MASK
    v3 = rotl64(v3, 21)
    v2 = (v2 + v1) & MASK
    v1 = rotl64(v1, 17); v1 ^= v2
    v2 = rotl64(v2, 32)
    v3 ^= v0  # extra
    
    # Round 2
    v0 = (v0 + v1) & MASK
    v1 = rotl64(v1, 13); v1 ^= v0
    v0 = rotl64(v0, 32)
    v2 = (v2 + v3) & MASK
    v3 = rotl64(v3, 16); v3 ^= v2
    v0 = (v0 + v3) & MASK
    v3 = rotl64(v3, 21)
    v2 = (v2 + v1) & MASK
    v1 = rotl64(v1, 17); v1 ^= v2
    v2 = rotl64(v2, 32)
    v3 ^= v0  # extra
    
    # Round 3
    v0 = (v0 + v1) & MASK
    v1 = rotl64(v1, 13); v1 ^= v0
    v0 = rotl64(v0, 32)
    v2 = (v2 + v3) & MASK
    v3 = rotl64(v3, 16); v3 ^= v2
    v0 = (v0 + v3) & MASK
    v3 = rotl64(v3, 21)
    v2 = (v2 + v1) & MASK
    v1 = rotl64(v1, 17); v1 ^= v2
    v2 = rotl64(v2, 32)
    v3 ^= v0  # extra
    
    # Round 4 (PARTIAL)
    v0 = (v0 + v1) & MASK
    v1 = rotl64(v1, 13); v1 ^= v0
    # NO v0 = rotl64(v0, 32)
    v2 = (v2 + v3) & MASK
    v3 = rotl64(v3, 16); v3 ^= v2
    # NO v0 += v3
    v3 = rotl64(v3, 21)
    v2 = (v2 + v1) & MASK
    v1 = rotl64(v1, 17)
    # NO v1 ^= v2 here (done in result)
    # NO v2 = rotl64(v2, 32) (done in result)
    
    # Result = v1 ^ v2 ^ v3 ^ rotl(v2, 32)
    result = v1 ^ v2 ^ v3 ^ rotl64(v2, 32)
    return result & MASK

class MT19937_64:
    def __init__(self):
        self.state = [0] * 312; self.index = 313
    def seed(self, seed):
        MUL = 0x5851F42D4C957F2D; MASK = 0xFFFFFFFFFFFFFFFF
        self.state[0] = seed & MASK; prev = seed & MASK; r9 = 3
        while r9 <= 311:
            x = prev; x ^= x >> 62; x = (x * MUL) & MASK; x = (x + r9 - 2) & MASK
            self.state[r9 - 2] = x; prev = x
            x2 = prev; x2 ^= x2 >> 62; x2 = (x2 * MUL) & MASK; x2 = (x2 + r9 - 1) & MASK
            self.state[r9 - 1] = x2; prev = x2; r9 += 2
        self.index = 312
    def reshuffle(self):
        MATRIX_A = 0xB5026F5AA96619E9; UM = 0xFFFFFFFF80000000; LM = 0x7FFFFFFF
        for i in range(312):
            x = (self.state[i] & UM) | (self.state[(i + 1) % 312] & LM)
            x_a = MATRIX_A if (x & 1) else 0
            self.state[i] = self.state[(i + 156) % 312] ^ (x >> 1) ^ x_a
        self.index = 0
    def next(self):
        if self.index >= 312: self.reshuffle()
        x = self.state[self.index]; self.index += 1
        x ^= (x >> 29) & 0x5555555555555555
        x ^= (x << 17) & 0x71D67FFFEDA60000
        temp = (x & 0xFFFFFFFF) & 0x07FFBF77; x ^= temp << 37; x ^= x >> 43
        return x & 0xFFFFFFFFFFFFFFFF

def test():
    prng = MT19937_64(); prng.seed(0x60010000)
    prng_vals = [prng.next() for _ in range(4)]
    prng_data = struct.pack("<4Q", *prng_vals)
    
    state = b''
    for length in [0x20, 0x18, 0x10, 0x08]:
        result = siphash_exact(prng_data[:length])
        state += struct.pack("<Q", result)
    
    print(f"Python cipher_state: {state.hex()}")
    expected = bytes.fromhex("16a719acda42335e4fcb0043b50e24bd5261f21aef7cb76c54c09d3ca930f4f2")
    print(f"Expected (Unicorn):  {expected.hex()}")
    print(f"Match: {state == expected}")
    
    if state != expected:
        print("\n  Individual SipHash outputs:")
        for length in [0x20, 0x18, 0x10, 0x08]:
            result = siphash_exact(prng_data[:length])
            print(f"    length=0x{length:02X}: 0x{result:016X}")
        
        # Expected individual outputs (from cipher_state):
        # 16a719acda42335e 4fcb0043b50e24bd 5261f21aef7cb76c 54c09d3ca930f4f2
        expected_parts = ["16a719acda42335e", "4fcb0043b50e24bd", "5261f21aef7cb76c", "54c09d3ca930f4f2"]
        print(f"\n  Expected individual outputs:")
        for i, length in enumerate([0x20, 0x18, 0x10, 0x08]):
            print(f"    length=0x{length:02X}: 0x{expected_parts[i]}")

if __name__ == "__main__":
    test()
