#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kuznyechik (GOST R 34.12-2015) cipher in GCM mode - Reusable module for secure mail exchange.

This module implements the standard Kuznyechik block cipher in Galois/Counter Mode (GCM)
for authenticated encryption. It provides a clean API for encrypting and
decrypting byte sequences with support for authenticated additional data (AAD).

Key Requirements:
- Key: 32 bytes (256 bits) - standard Kuznyechik key size
- IV: 12 bytes recommended (standard GCM), but any length supported
- Tag: 16 bytes (128 bits) - fixed authentication tag length
- AAD: Optional authenticated but not encrypted data

No external crypto libraries are used - only Python standard library.
"""

import os
import sys

# ---------------------- Kuznyechik (GOST R 34.12-2015) cipher ----------------------

# Official Pi S-box from GOST R 34.12-2015 (Kuznyechik)
# This is a permutation of {0,1,...,255}
PI = [
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
]

# Inverse Pi S-box
PI_INV = [0] * 256
for i in range(256):
    PI_INV[PI[i]] = i

# Linear transformation: GF(2^8) with reduction polynomial x^8 + x^7 + x^6 + x + 1 = 0xC3
REDUCTION_POLY = 0xC3

def _gf_mul_x(b):
    """Multiply by x in GF(2^8) modulo x^8 + x^7 + x^6 + x + 1."""
    if b & 0x80:
        return ((b << 1) ^ REDUCTION_POLY) & 0xFF
    return (b << 1) & 0xFF

def _gf_mul(b, poly):
    """Multiply byte by polynomial value in GF(2^8)."""
    result = 0
    temp = b
    for i in range(8):
        if (poly >> i) & 1:
            result ^= temp
        temp = _gf_mul_x(temp)
    return result & 0xFF

# Official lvec coefficients for R transformation (GOST R 34.12-2015)
LVEC = bytes([148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1])

def _r_transform(state):
    """
    Standard R transformation per GOST R 34.12-2015.
    R(state): compute a = sum gf_mul(state[i], lvec[i]), then shift right.
    """
    # Compute a = sum_{i=0..15} gf_mul(state[i], lvec[i])
    a = 0
    for i in range(16):
        a ^= _gf_mul(state[i], LVEC[i])
    a &= 0xFF
    
    # Shift right: output[0] = a, output[1:] = state[:15]
    output = bytearray(16)
    output[0] = a
    output[1:] = state[:15]
    return bytes(output)

def _r_inv_transform(state):
    """
    Inverse R transformation per GOST R 34.12-2015.
    R_inv reverses the shift and computes the last byte.
    """
    output = bytearray(16)
    # Inverse shift: output[:15] = state[1:]
    output[:15] = state[1:16]
    
    # Compute output[15] so that applying R gives original:
    # state[0] = sum_{i=0..15} gf_mul(output[i], lvec[i])
    # Since lvec[15] == 1, we have:
    # output[15] = state[0] XOR sum_{i=0..14} gf_mul(output[i], lvec[i])
    acc = 0
    for i in range(15):
        acc ^= _gf_mul(output[i], LVEC[i])
    output[15] = (state[0] ^ acc) & 0xFF
    return bytes(output)

def _s_transform(state, sbox):
    """Apply S-box transformation to each byte."""
    return bytes([sbox[b] for b in state])

def _l_transform(state):
    """L transformation = R applied 16 times."""
    result = state
    for _ in range(16):
        result = _r_transform(result)
    return result

def _l_inv_transform(state):
    """Inverse L transformation = R_inv applied 16 times."""
    result = state
    for _ in range(16):
        result = _r_inv_transform(result)
    return result

def _lsx(state, constant):
    """LSX(x, c) = L(S(x XOR c)) per GOST standard. constant is 16 bytes."""
    xored = bytes([a ^ b for a, b in zip(state, constant)])
    s_applied = _s_transform(xored, PI)
    return _l_transform(s_applied)

def _key_schedule(key_256):
    """
    Generate round keys from 256-bit key per GOST R 34.12-2015.
    
    Args:
        key_256: 32 bytes (256 bits) key
    
    Returns:
        list of 10 round keys, each 16 bytes (128 bits)
    """
    if len(key_256) != 32:
        raise ValueError(f"Key must be exactly 32 bytes (256 bits), got {len(key_256)} bytes")
    
    # Split key into two 128-bit parts: K1, K2
    K1 = bytearray(key_256[:16])
    K2 = bytearray(key_256[16:32])
    
    round_keys = [bytes(K1), bytes(K2)]
    
    # Generate constants C1..C32: Ci = L(15 zero bytes || i)
    C = []
    for i in range(1, 33):
        const_block = bytearray(16)
        const_block[15] = i & 0xFF
        Ci = _l_transform(bytes(const_block))
        C.append(Ci)
    
    # Define F(k1, k2, Ci): t = L(S(k1 XOR Ci)), t = t XOR k2, return (t, k1)
    def F(k1_val, k2_val, Ci_val):
        t = _lsx(bytes(k1_val), Ci_val)
        t = bytearray([a ^ b for a, b in zip(t, k2_val)])
        return t, bytearray(k1_val)
    
    # Generate round keys: 32 steps grouped into 4 groups of 8
    for g in range(4):
        for j in range(8):
            K1, K2 = F(K1, K2, C[g * 8 + j])
        round_keys.append(bytes(K1))
        round_keys.append(bytes(K2))
    
    return round_keys[:10]

def kuznyechik_encrypt_block(block, round_keys):
    """
    Encrypt a 16-byte block using Kuznyechik per GOST R 34.12-2015.
    
    Args:
        block: 16 bytes input block
        round_keys: list of 10 round keys (each 16 bytes)
    
    Returns:
        16 bytes encrypted block
    """
    if len(block) != 16:
        raise ValueError(f"Block must be exactly 16 bytes, got {len(block)} bytes")
    
    state = bytearray(block)
    
    # 9 rounds: state = L(S(state XOR round_keys[i]))
    for i in range(9):
        # XOR with round key
        state = bytearray([a ^ b for a, b in zip(state, round_keys[i])])
        # Apply S-box
        state = bytearray(_s_transform(state, PI))
        # Apply L transformation
        state = bytearray(_l_transform(state))
    
    # Final transformation: XOR with last round key
    state = bytes([a ^ b for a, b in zip(state, round_keys[9])])
    
    return state

def kuznyechik_decrypt_block(block, round_keys):
    """
    Decrypt a 16-byte block using Kuznyechik per GOST R 34.12-2015.
    
    Args:
        block: 16 bytes input block
        round_keys: list of 10 round keys (each 16 bytes)
    
    Returns:
        16 bytes decrypted block
    """
    if len(block) != 16:
        raise ValueError(f"Block must be exactly 16 bytes, got {len(block)} bytes")
    
    state = bytearray(block)
    
    # XOR with last round key
    state = bytearray([a ^ b for a, b in zip(state, round_keys[9])])
    
    # 9 rounds in reverse: state = S_inv(L_inv(state)) XOR round_keys[i]
    for i in range(8, -1, -1):
        # Apply inverse L transformation
        state = bytearray(_l_inv_transform(state))
        # Apply inverse S-box
        state = bytearray(_s_transform(state, PI_INV))
        # XOR with round key
        state = bytearray([a ^ b for a, b in zip(state, round_keys[i])])
    
    return bytes(state)

# ---------------------- GCM helpers (128-bit ops) ----------------------

# typedef struct { uint64_t hi, lo; } be128; /* big-endian logical 128-bit */
MASK64 = (1 << 64) - 1

def load_be128(b: bytes):
    """Load 16 bytes as big-endian 128-bit value."""
    if len(b) != 16:
        raise ValueError(f"Block must be exactly 16 bytes, got {len(b)} bytes")
    hi = ((b[0] << 56) | (b[1] << 48) | (b[2] << 40) | (b[3] << 32) |
          (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]) & MASK64
    lo = ((b[8] << 56) | (b[9] << 48) | (b[10] << 40) | (b[11] << 32) |
          (b[12] << 24) | (b[13] << 16) | (b[14] << 8) | b[15]) & MASK64
    return (hi, lo)

def store_be128(x, outb: bytearray):
    """Store 128-bit value as 16 bytes in big-endian format."""
    hi, lo = x
    outb[0]  = (hi >> 56) & 0xFF; outb[1]  = (hi >> 48) & 0xFF
    outb[2]  = (hi >> 40) & 0xFF; outb[3]  = (hi >> 32) & 0xFF
    outb[4]  = (hi >> 24) & 0xFF; outb[5]  = (hi >> 16) & 0xFF
    outb[6]  = (hi >> 8)  & 0xFF; outb[7]  = hi & 0xFF
    outb[8]  = (lo >> 56) & 0xFF; outb[9]  = (lo >> 48) & 0xFF
    outb[10] = (lo >> 40) & 0xFF; outb[11] = (lo >> 32) & 0xFF
    outb[12] = (lo >> 24) & 0xFF; outb[13] = (lo >> 16) & 0xFF
    outb[14] = (lo >> 8)  & 0xFF; outb[15] = lo & 0xFF

def be128_xor(a, b):
    """XOR two 128-bit values."""
    return ((a[0] ^ b[0]) & MASK64, (a[1] ^ b[1]) & MASK64)

def be128_shr1(v):
    """Right shift by 1 bit (big-endian logical value)."""
    hi, lo = v
    new_lo = ((lo >> 1) | ((hi & 1) << 63)) & MASK64
    new_hi = (hi >> 1) & MASK64
    return (new_hi, new_lo)

def be128_shl1(v):
    """Left shift by 1 bit."""
    hi, lo = v
    new_hi = ((hi << 1) | (lo >> 63)) & MASK64
    new_lo = (lo << 1) & MASK64
    return (new_hi, new_lo)

def gf_mult(X, Y):
    """GF(2^128) multiplication per SP 800-38D, right-shift method."""
    Z = (0, 0)
    V = Y
    # R = 0xE1000000000000000000000000000000 (big-endian)
    R = (0xE100000000000000, 0x0000000000000000)
    for _ in range(128):
        msb = X[0] & 0x8000000000000000
        if msb:
            Z = be128_xor(Z, V)
        lsb = V[1] & 1
        V = be128_shr1(V)
        if lsb:
            V = be128_xor(V, R)
        X = be128_shl1(X)
    return Z

def ghash_update(Y_ref, H, block16: bytes):
    """GHASH update: Y <- (Y ^ X) * H"""
    if len(block16) != 16:
        raise ValueError(f"GHASH block must be exactly 16 bytes, got {len(block16)} bytes")
    X = load_be128(block16)
    Y = be128_xor(Y_ref[0], X)
    Y = gf_mult(Y, H)
    Y_ref[0] = Y  # use list for pass-by-reference semantics

def compute_H(round_keys):
    """Compute H = E_K(0^128)"""
    zero = bytes(16)
    return kuznyechik_encrypt_block(zero, round_keys)

def inc32(ctr: bytearray):
    """inc32 on the last 32 bits of a 128-bit counter (big-endian)."""
    if len(ctr) != 16:
        raise ValueError(f"Counter must be exactly 16 bytes, got {len(ctr)} bytes")
    c = ((ctr[12] << 24) | (ctr[13] << 16) | (ctr[14] << 8) | ctr[15]) & 0xFFFFFFFF
    c = (c + 1) & 0xFFFFFFFF
    ctr[12] = (c >> 24) & 0xFF
    ctr[13] = (c >> 16) & 0xFF
    ctr[14] = (c >> 8) & 0xFF
    ctr[15] = c & 0xFF

def derive_J0(iv: bytes, Hbe):
    """
    Derive J0 from IV per GCM specification.
    
    If len(iv) == 12: J0 = iv || 0x00000001
    Otherwise: J0 = GHASH(H, iv || pad || [len(iv)]_64)
    """
    if len(iv) == 12:
        # Standard GCM case: J0 = IV || 0x00000001
        J0 = bytearray(16)
        J0[:12] = iv
        J0[12] = 0x00
        J0[13] = 0x00
        J0[14] = 0x00
        J0[15] = 0x01
        return bytes(J0)
    else:
        # Generic case: J0 = GHASH(H, IV || pad || [len(IV)]_64)
        Y_ref = [(0, 0)]
        block = bytearray(16)
        off = 0
        ivlen = len(iv)
        while ivlen - off >= 16:
            ghash_update(Y_ref, Hbe, iv[off:off+16])
            off += 16
        if ivlen - off > 0:
            for i in range(16):
                block[i] = 0
            block[:ivlen - off] = iv[off:]
            ghash_update(Y_ref, Hbe, bytes(block))
        for i in range(16):
            block[i] = 0
        ivbits = (ivlen * 8) & ((1 << 64) - 1)
        block[8]  = (ivbits >> 56) & 0xFF
        block[9]  = (ivbits >> 48) & 0xFF
        block[10] = (ivbits >> 40) & 0xFF
        block[11] = (ivbits >> 32) & 0xFF
        block[12] = (ivbits >> 24) & 0xFF
        block[13] = (ivbits >> 16) & 0xFF
        block[14] = (ivbits >> 8) & 0xFF
        block[15] = ivbits & 0xFF
        ghash_update(Y_ref, Hbe, bytes(block))
        J0 = bytearray(16)
        store_be128(Y_ref[0], J0)
        return bytes(J0)

def ghash_lengths_update(Y_ref, Hbe, aad_bits: int, c_bits: int):
    """GHASH lengths block: [len(AAD)]_64 || [len(C)]_64 in bits, both big-endian."""
    lenblk = bytearray(16)
    # [len(AAD)]_64
    lenblk[0]  = (aad_bits >> 56) & 0xFF
    lenblk[1]  = (aad_bits >> 48) & 0xFF
    lenblk[2]  = (aad_bits >> 40) & 0xFF
    lenblk[3]  = (aad_bits >> 32) & 0xFF
    lenblk[4]  = (aad_bits >> 24) & 0xFF
    lenblk[5]  = (aad_bits >> 16) & 0xFF
    lenblk[6]  = (aad_bits >> 8)  & 0xFF
    lenblk[7]  = aad_bits & 0xFF
    # [len(C)]_64
    lenblk[8]  = (c_bits >> 56) & 0xFF
    lenblk[9]  = (c_bits >> 48) & 0xFF
    lenblk[10] = (c_bits >> 40) & 0xFF
    lenblk[11] = (c_bits >> 32) & 0xFF
    lenblk[12] = (c_bits >> 24) & 0xFF
    lenblk[13] = (c_bits >> 16) & 0xFF
    lenblk[14] = (c_bits >> 8)  & 0xFF
    lenblk[15] = c_bits & 0xFF
    ghash_update(Y_ref, Hbe, bytes(lenblk))

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison of two byte sequences.
    
    Returns True if sequences are equal and of the same length, False otherwise.
    This function runs in constant time to prevent timing attacks, even when
    lengths differ (no early return).
    """
    # Combine length difference into diff
    diff = len(a) ^ len(b)
    # Loop up to max length, using 0 for missing bytes
    max_len = max(len(a), len(b))
    for i in range(max_len):
        a_byte = a[i] if i < len(a) else 0
        b_byte = b[i] if i < len(b) else 0
        diff |= (a_byte ^ b_byte)
    return diff == 0

# ---------------------- High-level GCM API ----------------------

def gost_gcm_encrypt(plaintext: bytes, key: bytes, iv: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using Kuznyechik in GCM mode.
    
    Args:
        plaintext: bytes to encrypt
        key: 32 bytes (256 bits) key material
        iv: initialization vector (12 bytes recommended, but any length supported)
        aad: optional authenticated additional data (authenticated but not encrypted)
    
    Returns:
        tuple of (ciphertext, tag) where:
        - ciphertext: encrypted data (same length as plaintext)
        - tag: 16-byte authentication tag
    
    Raises:
        ValueError: if key length is not 32 bytes
    """
    if len(key) != 32:
        raise ValueError(f"Key must be exactly 32 bytes (256 bits), got {len(key)} bytes")
    
    # Generate round keys
    round_keys = _key_schedule(key)
    
    # Compute H = E_K(0^128)
    H = compute_H(round_keys)
    Hbe = load_be128(H)
    
    # Derive J0 from IV
    J0 = derive_J0(iv, Hbe)
    
    # GHASH accumulator (starts at 0)
    S_ref = [(0, 0)]
    
    # Process AAD first
    aad_off = 0
    aad_len = len(aad)
    while aad_len - aad_off >= 16:
        ghash_update(S_ref, Hbe, aad[aad_off:aad_off+16])
        aad_off += 16
    if aad_len - aad_off > 0:
        aad_block = bytearray(16)
        aad_block[:aad_len - aad_off] = aad[aad_off:]
        ghash_update(S_ref, Hbe, bytes(aad_block))
    
    # Counter starts from inc32(J0)
    ctr = bytearray(J0)
    inc32(ctr)
    
    # Encrypt plaintext using CTR mode
    ciphertext = bytearray()
    plaintext_off = 0
    plaintext_len = len(plaintext)
    
    while plaintext_off < plaintext_len:
        # Generate keystream block
        ks = kuznyechik_encrypt_block(bytes(ctr), round_keys)
        inc32(ctr)
        
        # XOR with plaintext and build ciphertext block for GHASH
        n = min(16, plaintext_len - plaintext_off)
        cblk = bytearray(16)  # GHASH block (padded with zeros)
        for i in range(n):
            cbyte = plaintext[plaintext_off + i] ^ ks[i]
            ciphertext.append(cbyte)
            cblk[i] = cbyte
        # Remaining bytes already zero (padded)
        
        # Update GHASH with ciphertext block (exact chunk produced, padded to 16 bytes)
        ghash_update(S_ref, Hbe, bytes(cblk))
        
        plaintext_off += n
    
    # Finalize GHASH with lengths block
    aad_bits = len(aad) * 8
    c_bits = len(ciphertext) * 8
    ghash_lengths_update(S_ref, Hbe, aad_bits, c_bits)
    
    # Compute tag: T = E_K(J0) XOR S
    EJ0 = kuznyechik_encrypt_block(J0, round_keys)
    Sbytes = bytearray(16)
    store_be128(S_ref[0], Sbytes)
    tag = bytes([(EJ0[i] ^ Sbytes[i]) & 0xFF for i in range(16)])
    
    return (bytes(ciphertext), tag)

def gost_gcm_decrypt(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt ciphertext using Kuznyechik in GCM mode.
    
    Args:
        ciphertext: encrypted data
        key: 32 bytes (256 bits) key material
        iv: initialization vector (must match the one used for encryption)
        tag: 16-byte authentication tag
        aad: optional authenticated additional data (must match the one used for encryption)
    
    Returns:
        decrypted plaintext bytes
    
    Raises:
        ValueError: if key length is not 32 bytes, tag length is not 16 bytes,
                    or authentication fails
    """
    if len(key) != 32:
        raise ValueError(f"Key must be exactly 32 bytes (256 bits), got {len(key)} bytes")
    if len(tag) != 16:
        raise ValueError(f"Tag must be exactly 16 bytes, got {len(tag)} bytes")
    
    # Generate round keys
    round_keys = _key_schedule(key)
    
    # Compute H = E_K(0^128)
    H = compute_H(round_keys)
    Hbe = load_be128(H)
    
    # Derive J0 from IV
    J0 = derive_J0(iv, Hbe)
    
    # GHASH accumulator (starts at 0)
    S_ref = [(0, 0)]
    
    # Process AAD first
    aad_off = 0
    aad_len = len(aad)
    while aad_len - aad_off >= 16:
        ghash_update(S_ref, Hbe, aad[aad_off:aad_off+16])
        aad_off += 16
    if aad_len - aad_off > 0:
        aad_block = bytearray(16)
        aad_block[:aad_len - aad_off] = aad[aad_off:]
        ghash_update(S_ref, Hbe, bytes(aad_block))
    
    # Counter starts from inc32(J0)
    ctr = bytearray(J0)
    inc32(ctr)
    
    # Decrypt ciphertext using CTR mode
    plaintext = bytearray()
    ciphertext_off = 0
    ciphertext_len = len(ciphertext)
    
    while ciphertext_off < ciphertext_len:
        # Generate keystream block
        ks = kuznyechik_encrypt_block(bytes(ctr), round_keys)
        inc32(ctr)
        
        # XOR with ciphertext
        n = min(16, ciphertext_len - ciphertext_off)
        for i in range(n):
            plaintext.append(ciphertext[ciphertext_off + i] ^ ks[i])
        
        # Update GHASH with exact ciphertext chunk read in this iteration (padded to 16 bytes)
        cblk = bytearray(16)
        cblk[:n] = ciphertext[ciphertext_off:ciphertext_off+n]
        # Remaining bytes already zero (padded)
        ghash_update(S_ref, Hbe, bytes(cblk))
        
        ciphertext_off += n
    
    # Finalize GHASH with lengths block
    aad_bits = len(aad) * 8
    c_bits = len(ciphertext) * 8
    ghash_lengths_update(S_ref, Hbe, aad_bits, c_bits)
    
    # Compute expected tag: T = E_K(J0) XOR S
    EJ0 = kuznyechik_encrypt_block(J0, round_keys)
    Sbytes = bytearray(16)
    store_be128(S_ref[0], Sbytes)
    tag_calc = bytes([(EJ0[i] ^ Sbytes[i]) & 0xFF for i in range(16)])
    
    # Constant-time tag verification
    if not constant_time_compare(tag, tag_calc):
        raise ValueError("Authentication failed")
    
    return bytes(plaintext)

if __name__ == "__main__":
    # Simple CLI demo
    print("Kuznyechik (GOST R 34.12-2015) in GCM Mode")
    print("Usage: python unit_tests.py  # Run tests")
    print("       python gost_gcm.py    # Show this message")
    print()
    print("Example usage in code:")
    print("  from gost_gcm import gost_gcm_encrypt, gost_gcm_decrypt")
    print("  import os")
    print("  key = os.urandom(32)  # 32 bytes = 256 bits")
    print("  iv = os.urandom(12)   # 12 bytes recommended")
    print("  plaintext = b'Hello, world!'")
    print("  ciphertext, tag = gost_gcm_encrypt(plaintext, key, iv)")
    print("  decrypted = gost_gcm_decrypt(ciphertext, key, iv, tag)")
    print()
    print("For CLI demo with hex key:")
    print("  key_hex = '0123456789abcdef...'  # 64 hex chars = 32 bytes")
    print("  key = bytes.fromhex(key_hex)")
