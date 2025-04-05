# poc.sage
# Test script for the PKE class defined in pke.sage

from sage.all import *
import os

# Import the class definition from the pke.sage file
try:
    from pke import PKE
except ImportError:
    print("Error: Could not import PKE.")
    print("Make sure 'pke.sage' is in the same directory or your Python path.")
    exit()
except Exception as e:
    print(f"An unexpected error occurred during import: {e}")
    exit()


# --- Test Parameters ---
n = 8        # Dimension / Security parameter
r_int = 2    # Integer radius bound for error vectors (max component size)
# Choose q large enough for recovery. q > 2*r_int needed.
q = 101
print("--- PKE Test Script ---")
print(f"Parameters: n={n}, r_int={r_int}, q={q}")
if q <= 2 * r_int:
    print(f"Warning: q={q} might be too small relative to r_int={r_int}. Decryption might fail.")


# --- Test Execution ---

# 1. Instantiate the PKE
try:
    pke_instance = PKE(n, q, r_int)
    print("\nPKE Instance created successfully.")
except ValueError as e:
    print(f"\nError creating PKE instance: {e}")
    exit()
except Exception as e:
    print(f"\nUnexpected error creating PKE instance: {e}")
    exit()

# 2. Generate Keys
print("\n--- Testing Key Generation ---")
try:
    pk, sk = pke_instance.keygen()
    print(f"Public Key P generated (type: {type(pk)}, dimensions: {pk.dimensions()})")
    print(f"Secret Key U generated (type: {type(sk)}, dimensions: {sk.dimensions()})")
    # print(f"Determinant of sk (U): {sk.det()}") # Verify determinant is +/- 1
except RuntimeError as e:
    print(f"Error during key generation: {e}")
    exit()
except Exception as e:
    print(f"Unexpected error during key generation: {e}")
    exit()


# 3. Encrypt and Decrypt 0
print("\n--- Testing Encryption/Decryption of 0 ---")
try:
    print("Encrypting 0...")
    c0 = pke_instance.encrypt(pk, 0)
    print(f"Ciphertext c0 (first 5 components): {list(c0)[:5]}...")
    print("Decrypting c0...")
    m0_decrypted = pke_instance.decrypt(sk, c0)
    print(f"Decrypted message: {m0_decrypted}")

    if m0_decrypted == 0:
        print("SUCCESS: Decryption of 0 yielded 0.")
    elif m0_decrypted == 1:
        print("FAILURE: Decryption of 0 yielded 1.")
    else:
        print(f"FAILURE: Decryption of 0 failed (returned {m0_decrypted}).")

except Exception as e:
    print(f"Error during Encrypt/Decrypt test for 0: {e}")


# 4. Encrypt and Decrypt 1
print("\n--- Testing Encryption/Decryption of 1 ---")
try:
    print("Encrypting 1...")
    c1 = pke_instance.encrypt(pk, 1)
    print(f"Ciphertext c1 (first 5 components): {list(c1)[:5]}...")
    print("Decrypting c1...")
    m1_decrypted = pke_instance.decrypt(sk, c1)
    print(f"Decrypted message: {m1_decrypted}")

    if m1_decrypted == 1:
        print("SUCCESS: Decryption of 1 yielded 1.")
    elif m1_decrypted == 0:
        print("FAILURE: Decryption of 1 yielded 0.")
    else:
        print(f"FAILURE: Decryption of 1 failed (returned {m1_decrypted}).")

except Exception as e:
    print(f"Error during Encrypt/Decrypt test for 1: {e}")


print("\n--- Test Script Finished ---")