from typing import List
# permutacja i niskopoziomowe funkcje
# Minimalna, czytelna implementacja permutacji ASCON (320-bit state)
# Implementacja oparta na specyfikacji ASCON (permutation p_12 / p_6 parametry).
# Referencja: Ascon spec. See: ascon-spec-round2.pdf

ROUND_CONSTANTS = [
    0x00000000000000f0, 0x00000000000000e1, 0x00000000000000d2, 0x00000000000000c3,
    0x00000000000000b4, 0x00000000000000a5, 0x0000000000000096, 0x0000000000000087,
    0x0000000000000078, 0x0000000000000069, 0x000000000000005a, 0x000000000000004b
]

def rotr(x: int, r: int, w: int=64) -> int:
    """Rotate right"""
    r %= w
    return (x >> r) | ((x & ((1<<r)-1)) << (w-r))

def ascon_permutation(state: List[int], rounds: int = 12) -> None:
    """
    In-place permutation on 5 64-bit words (state length 5).
    state: list of 5 ints (64-bit)
    rounds: number of rounds (e.g., 12 for initialization/finalization)
    """
    assert len(state) == 5
    for r in range(12-rounds, 12):

        rc = ROUND_CONSTANTS[r]
        state[2] ^= rc

        x0,x1,x2,x3,x4 = state
        x0 ^= x4; x4 ^= x3; x2 ^= x1
        t0 = (~x0) & x1
        t1 = (~x1) & x2
        t2 = (~x2) & x3
        t3 = (~x3) & x4
        t4 = (~x4) & x0
        x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0
        x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = ~x2 & ((1<<64)-1)

        state[0] = x0 ^ rotr(x0, 19) ^ rotr(x0, 28)
        state[1] = x1 ^ rotr(x1, 61) ^ rotr(x1, 39)
        state[2] = x2 ^ rotr(x2, 1)  ^ rotr(x2, 6)
        state[3] = x3 ^ rotr(x3, 10) ^ rotr(x3, 17)
        state[4] = x4 ^ rotr(x4, 7)  ^ rotr(x4, 41)
