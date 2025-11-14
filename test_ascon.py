#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple test script for ASCON implementation correctness.
Tests encryption/decryption, hash, and MAC with several test cases.
"""

from ascon.aead import Ascon128
from ascon.hash import ascon_hash
from ascon.mac import AsconMAC


def test_aead():
    """Test ASCON-128 AEAD encryption and decryption"""
    print("=" * 60)
    print("TEST 1: ASCON-128 AEAD - Encryption/Decryption")
    print("=" * 60)
    
    key = b'\x00' * 16
    nonce = b'\x00' * 16
    
    # Test 1: Basic text
    plaintext1 = b"Hello, ASCON!"
    aad1 = b"metadata"
    
    cipher = Ascon128(key)
    ciphertext1, tag1 = cipher.encrypt(nonce, plaintext1, aad1)
    
    print(f"\n[Test 1a] Basic text")
    print(f"  Plaintext:  {plaintext1}")
    print(f"  AAD:        {aad1}")
    print(f"  Ciphertext: {ciphertext1.hex()}")
    print(f"  Tag:        {tag1.hex()}")
    
    # Decryption - should succeed
    decrypted1, ok1 = cipher.decrypt(nonce, ciphertext1, aad1, tag1)
    print(f"  Decrypted:  {decrypted1}")
    print(f"  ✓ Verification: {'PASS' if ok1 and decrypted1 == plaintext1 else 'FAIL'}")
    
    # Test 2: Longer text
    plaintext2 = b"This is a longer test text for ASCON-128 AEAD. " * 3
    aad2 = b""
    
    ciphertext2, tag2 = cipher.encrypt(nonce, plaintext2, aad2)
    
    print(f"\n[Test 1b] Longer text (without AAD)")
    print(f"  Plaintext:  {len(plaintext2)} bytes")
    print(f"  Ciphertext: {len(ciphertext2)} bytes, hex: {ciphertext2[:20].hex()}...")
    print(f"  Tag:        {tag2.hex()}")
    
    decrypted2, ok2 = cipher.decrypt(nonce, ciphertext2, aad2, tag2)
    print(f"  Decrypted:  {len(decrypted2)} bytes")
    print(f"  ✓ Verification: {'PASS' if ok2 and decrypted2 == plaintext2 else 'FAIL'}")
    
    # Test 3: INVALID TAG - should fail
    print(f"\n[Test 1c] Test with invalid tag (should FAIL)")
    wrong_tag = bytes([b ^ 0xFF for b in tag1])  # Flip all bits
    decrypted3, ok3 = cipher.decrypt(nonce, ciphertext1, aad1, wrong_tag)
    print(f"  Expected: verification FAILED")
    print(f"  Got:      {'FAILED' if not ok3 else 'PASSED (ERROR!)'}")
    print(f"  ✓ Verification: {'PASS (correctly rejected)' if not ok3 else 'FAIL (change not detected!)'}")
    
    return ok1 and ok2 and not ok3


def test_hash():
    """Test ASCON hash function"""
    print("\n" + "=" * 60)
    print("TEST 2: ASCON-Hash")
    print("=" * 60)
    
    # Test 1: Empty string
    data1 = b""
    hash1 = ascon_hash(data1)
    print(f"\n[Test 2a] Empty string")
    print(f"  Input:  (empty)")
    print(f"  Hash:   {hash1.hex()}")
    print(f"  Length: {len(hash1)} bytes")
    
    # Test 2: Short text
    data2 = b"ASCON"
    hash2 = ascon_hash(data2)
    print(f"\n[Test 2b] Short text")
    print(f"  Input:  {data2}")
    print(f"  Hash:   {hash2.hex()}")
    
    # Test 3: Longer text
    data3 = b"The quick brown fox jumps over the lazy dog"
    hash3 = ascon_hash(data3)
    print(f"\n[Test 2c] Classic test text")
    print(f"  Input:  {data3}")
    print(f"  Hash:   {hash3.hex()}")
    
    # Check determinism
    hash3_repeat = ascon_hash(data3)
    deterministic = (hash3 == hash3_repeat)
    print(f"  ✓ Determinism: {'PASS' if deterministic else 'FAIL'}")
    
    # Check uniqueness
    all_different = (hash1 != hash2 != hash3)
    print(f"  ✓ Different hashes for different data: {'PASS' if all_different else 'FAIL'}")
    
    return deterministic and all_different


def test_mac():
    """Test ASCON MAC function"""
    print("\n" + "=" * 60)
    print("TEST 3: ASCON-MAC")
    print("=" * 60)
    
    key = b'\x01\x02\x03\x04' * 4  # 16 bytes
    
    # Test 1: Basic message
    msg1 = b"Authenticate this message"
    mac_obj = AsconMAC(key)
    tag1 = mac_obj.mac(msg1)
    
    print(f"\n[Test 3a] Basic message")
    print(f"  Message: {msg1}")
    print(f"  MAC:     {tag1.hex()}")
    
    # Verify correct tag
    valid1 = mac_obj.verify(msg1, tag1)
    print(f"  ✓ Correct tag verification: {'PASS' if valid1 else 'FAIL'}")
    
    # Test 2: Verify incorrect tag
    print(f"\n[Test 3b] Verification with incorrect tag")
    wrong_tag = bytes([b ^ 0x01 for b in tag1])  # Flip first bit of each byte
    valid2 = mac_obj.verify(msg1, wrong_tag)
    print(f"  Expected: verification FAILED")
    print(f"  ✓ Verification: {'PASS (correctly rejected)' if not valid2 else 'FAIL (change not detected!)'}")
    
    # Test 3: Modified message
    print(f"\n[Test 3c] Verification with modified message")
    msg2 = b"Authenticate THIS message"  # Changed "this" -> "THIS"
    valid3 = mac_obj.verify(msg2, tag1)
    print(f"  Original: {msg1}")
    print(f"  Modified: {msg2}")
    print(f"  ✓ Verification: {'PASS (correctly rejected)' if not valid3 else 'FAIL (change not detected!)'}")
    
    return valid1 and not valid2 and not valid3


def main():
    print("\n" + "=" * 30)
    print("  ASCON IMPLEMENTATION CORRECTNESS TESTS")
    print("=" * 30 + "\n")
    
    results = []
    
    # Run all tests
    results.append(("AEAD", test_aead()))
    results.append(("Hash", test_hash()))
    results.append(("MAC", test_mac()))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    for name, passed in results:
        status = "✓ PASSED" if passed else "X FAILED"
        print(f"  {name:20s} {status}")
    
    all_passed = all(r[1] for r in results)
    print("\n" + "=" * 60)
    if all_passed:
        print("@@@@ ALL TESTS PASSED SUCCESSFULLY!")
    else:
        print("!!!!  SOME TESTS FAILED")
    print("=" * 60 + "\n")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    exit(main())
