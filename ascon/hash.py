from ascon.core import ascon_permutation
import struct

# ASCON-Hash256 IV calculated according to official pyascon
# IV bytes: [variant, 0, (pb<<4)+pa, taglen_high, taglen_low, rate, 0, 0]
# For ASCON-Hash256: variant=2, pa=pb=12, taglen=256 (0x0100), rate=8
# IV bytes = [0x02, 0x00, 0xcc, 0x01, 0x00, 0x08, 0x00, 0x00]
# As little-endian uint64: 0x0000080100cc0002
ASCON_HASH_IV = 0x0000080100cc0002

def ascon_hash(data: bytes) -> bytes:
    """
    ASCON-Hash256 implementation according to NIST SP 800-232.
    Returns 32-byte (256-bit) hash.
    Reference: https://github.com/ascon/ascon-c/tree/main/crypto_hash/asconhash256/ref
    
    CRITICAL: ASCON uses LITTLE-ENDIAN byte order (see ref/word.h LOADBYTES/STOREBYTES)
    CRITICAL: PAD(i) = 0x01 << (8 * i), not 0x80!
    CRITICAL: P12 happens AFTER padding, then squeeze WITHOUT initial P12
    """
    rate = 8  # 64 bits = 8 bytes
    
    # Initialize state: only s.x[0] gets IV, rest are zeros
    state = [ASCON_HASH_IV, 0, 0, 0, 0]
    ascon_permutation(state, rounds=12)
    
    # Absorb phase with padding (like official pyascon)
    # Padding: message + 0x01 + zeros to fill to rate boundary
    m_padding = b'\x01' + b'\x00' * (rate - (len(data) % rate) - 1)
    m_padded = data + m_padding
    
    # Process ALL blocks (including the one with padding)
    for pos in range(0, len(m_padded), rate):
        block = m_padded[pos:pos+rate]
        w = int.from_bytes(block, 'little')
        state[0] ^= w
        ascon_permutation(state, rounds=12)
    
    # Squeeze phase: extract 32 bytes (like official pyascon)
    out = b''
    while len(out) < 32:
        out += state[0].to_bytes(rate, 'little')
        ascon_permutation(state, rounds=12)
    
    return out[:32]
