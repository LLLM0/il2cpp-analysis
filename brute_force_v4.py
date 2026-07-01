#!/usr/bin/env python3
"""
Fixed brute-force with proper stack alignment.
keyblock_init requires 16-byte aligned stack for movaps instructions.
"""
import struct
import time
import sys
sys.path.insert(0, '/home/z/my-project/scripts')
from reverse_cipher import MT19937_64, compute_cipher_state
from brute_force_v3 import setup_unicorn
from unicorn import *
from unicorn.x86_const import *

def try_seed_fixed(uc, SB, BB, RA, malloc_addr, input_data, hardcoded_key_addr):
    """Try a single malloc address with fixed stack alignment."""
    # Step 1: Python MT19937-64 + SipHash → cipher_state
    prng = MT19937_64()
    prng.seed(malloc_addr)
    prng_vals = [prng.next() for _ in range(4)]
    cipher_state = compute_cipher_state(prng_vals)
    
    CS_ADDR = BB + 0x1000
    PK_ADDR = BB + 0x2000
    OUT_ADDR = BB + 0x3000
    IN_ADDR = BB + 0x4000
    TMP_ADDR = BB + 0x5000
    
    # Use 16-byte aligned stack
    SB_aligned = (SB & ~0xF) - 8
    
    # Step 2: keyblock_init
    uc.mem_write(CS_ADDR, cipher_state)
    uc.mem_write(PK_ADDR, b'\x00' * 0xE50)
    uc.reg_write(UC_X86_REG_RCX, PK_ADDR)
    uc.reg_write(UC_X86_REG_RDX, CS_ADDR)
    uc.reg_write(UC_X86_REG_R8, hardcoded_key_addr)
    uc.reg_write(UC_X86_REG_RSP, SB_aligned)
    uc.mem_write(SB_aligned, struct.pack('<Q', RA))
    try:
        uc.emu_start(0x1408359C0, RA, timeout=5*1000000, count=500000)
    except:
        return 0
    
    # Step 3: cipher_process
    uc.mem_write(OUT_ADDR, b'\x00' * 64)
    uc.mem_write(IN_ADDR, input_data)
    uc.mem_write(TMP_ADDR, b'\x00' * 0xB00)
    uc.reg_write(UC_X86_REG_RSP, SB_aligned)
    uc.mem_write(SB_aligned, struct.pack('<Q', RA))
    uc.mem_write(SB_aligned + 0x28, struct.pack('<Q', TMP_ADDR))
    uc.reg_write(UC_X86_REG_RCX, PK_ADDR)
    uc.reg_write(UC_X86_REG_RDX, CS_ADDR)
    uc.reg_write(UC_X86_REG_R8, IN_ADDR)
    uc.reg_write(UC_X86_REG_R9, OUT_ADDR)
    try:
        uc.emu_start(0x1408359F0, RA, timeout=5*1000000, count=5000000)
    except:
        return 0
    
    output = bytes(uc.mem_read(OUT_ADDR, 4))
    return struct.unpack('<I', output)[0]

def main():
    print("=== Fixed Brute-Force (with stack alignment) ===\n")
    
    uc, SB, BB, RA = setup_unicorn()
    hk = 0x144D76E60
    
    with open('/tmp/my-project/hk4e_download/GenshinImpact_Data/Native/Data/Metadata/global-metadata.dat', 'rb') as f:
        meta = f.read()
    input_data = meta[32:32+16]
    
    # Test with a known seed first
    print("Test: seed=0x10000")
    magic = try_seed_fixed(uc, SB, BB, RA, 0x10000, input_data, hk)
    print(f"  magic = 0x{magic:08X}")
    
    # Brute-force
    t0 = time.time()
    count = 0
    
    for addr in range(0x10000, 0x200000, 0x10):
        count += 1
        magic = try_seed_fixed(uc, SB, BB, RA, addr, input_data, hk)
        
        if magic == 0xFAB11BAF:
            elapsed = time.time() - t0
            print(f"\n[+] FOUND! malloc_addr = 0x{addr:X}")
            print(f"    Tested {count} addresses in {elapsed:.1f}s")
            return addr
        
        if count % 100 == 0:
            elapsed = time.time() - t0
            rate = count / elapsed if elapsed > 0 else 0
            print(f"  {count} ({rate:.1f}/s) last=0x{addr:X} m=0x{magic:08X}", flush=True)
    
    elapsed = time.time() - t0
    print(f"\nTested {count} in {elapsed:.1f}s ({count/elapsed:.0f}/s)")

if __name__ == "__main__":
    main()
