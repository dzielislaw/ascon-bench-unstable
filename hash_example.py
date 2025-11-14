#!/usr/bin/env python3
"""
Comparison of our ASCON-Hash implementation with the official one
"""

import sys
import importlib.util

# Our implementation
from ascon.hash import ascon_hash as our_hash

# Official implementation - load directly from file
spec = importlib.util.spec_from_file_location("official_ascon", "temp_pyascon/ascon.py")
official_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(official_module)
official_hash = official_module.ascon_hash

# Two test texts
text1 = b"The quick brown fox jumps over the lazy dog"
text2 = b"The quick brown fox jumps over the lazy dog."

print("=" * 80)
print("Comparison: Our Implementation vs Official pyascon")
print("=" * 80)
print()

for i, text in enumerate([text1, text2], 1):
    print(f"Test {i}: {text.decode()}")
    print("-" * 80)
    
    our = our_hash(text)
    official = official_hash(text)
    
    match = "✓ MATCH" if our == official else "✗ DIFFERENT"
    
    print(f"  Ours:     {our.hex()}")
    print(f"  Official: {official.hex()}")
    print(f"  Status:   {match}")
    print()

print("=" * 80)
