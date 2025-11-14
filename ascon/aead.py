from typing import Tuple
from ascon.core import ascon_permutation
# ASCON-128 (encrypt/decrypt) - zgodne z interfejsem
BLOCK_SIZE = 8

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def pad(x: bytes, rate: int) -> bytes:
    if len(x) == 0:
        return b'\x80' + b'\x00'*(rate-1)
    rem = len(x) % rate
    if rem == 0:
        return x
    return x + b'\x80' + b'\x00'*(rate-1-rem)

def bytes_to_state(b: bytes) -> list:
    # convert 40 bytes to 5 x 8-byte words (little-endian)
    import struct
    words = list(struct.unpack('>5Q', b.ljust(40, b'\x00')))
    return words

def state_to_bytes(state: list) -> bytes:
    import struct
    return struct.pack('>5Q', *state)

class Ascon128:
    """
    Clean Python implementation of ASCON-128 AEAD (mode from spec).
    Not constant-time, intended for benchmarking and correctness tests.
    """
    def __init__(self, key: bytes):
        assert len(key) == 16
        self.key = key

    def _init_state(self, nonce):
        state_bytes = self.key + nonce
        state_bytes = state_bytes.ljust(40, b'\x00')  # pad to 40 bytes for 5xQ
        state = bytes_to_state(state_bytes)
        return state


    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes=b'') -> Tuple[bytes, bytes]:
        state = self._init_state(nonce)
        rate = 8
        if aad:
            padded = pad(aad, rate)
            for i in range(0, len(padded), rate):
                block = padded[i:i+rate]
                import struct
                w = int.from_bytes(block.ljust(8,b'\x00'), 'big')
                state[0] ^= w
                ascon_permutation(state, rounds=6)

        ciphertext = b''
        padded = pad(plaintext, rate)
        original_len = len(plaintext)
        for i in range(0, len(padded), rate):
            block = padded[i:i+rate]
            import struct
            s0 = state[0]
            s0_bytes = s0.to_bytes(8, 'big')
            cblock = xor_bytes(block, s0_bytes[:len(block)])
            ciphertext += cblock

            pblock = int.from_bytes(block.ljust(8,b'\x00'), 'big')
            state[0] = int.from_bytes(s0_bytes, 'big') ^ pblock
            ascon_permutation(state, rounds=6)

        ciphertext = ciphertext[:original_len]
        
        import struct
        k0,k1 = struct.unpack('>2Q', self.key)
        state[1] ^= k0
        state[2] ^= k1
        ascon_permutation(state, rounds=12)
        tag = state_to_bytes(state)[:16]
        return ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes) -> Tuple[bytes, bool]:
        state = self._init_state(nonce)
        rate = 8
        
        # Process AAD (same as encrypt)
        if aad:
            padded = pad(aad, rate)
            for i in range(0, len(padded), rate):
                block = padded[i:i+rate]
                import struct
                w = int.from_bytes(block.ljust(8,b'\x00'), 'big')
                state[0] ^= w
                ascon_permutation(state, rounds=6)
        
        # Decrypt ciphertext (process blocks, pad only last incomplete block for state)
        plaintext = b''
        import struct
        for i in range(0, len(ciphertext), rate):
            block = ciphertext[i:i+rate]
            s0 = state[0]
            s0_bytes = s0.to_bytes(8, 'big')
            
            # XOR to get plaintext block
            pblock = xor_bytes(block, s0_bytes[:len(block)])
            plaintext += pblock
            
            # Update state: need to pad plaintext block for state update
            if len(pblock) < rate:
                # Last incomplete block - pad it
                padded_pblock = pblock + b'\x80' + b'\x00' * (rate - 1 - len(pblock))
            else:
                padded_pblock = pblock
            
            pblock_int = int.from_bytes(padded_pblock.ljust(8,b'\x00'), 'big')
            state[0] = s0 ^ pblock_int
            ascon_permutation(state, rounds=6)
        
        # Compute tag
        import struct
        k0,k1 = struct.unpack('>2Q', self.key)
        state[1] ^= k0
        state[2] ^= k1
        ascon_permutation(state, rounds=12)
        calc_tag = state_to_bytes(state)[:16]
        
        ok = calc_tag == tag
        return plaintext, ok
