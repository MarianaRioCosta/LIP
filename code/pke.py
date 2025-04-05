# Implements the PKE class based on Protocol 1 (with simplifications)

from sage.all import *
import os
import math
import random # For Gaussian sampling and uniform sampling

# --- Helper Functions ---

def sample_discrete_gaussian(dim, s):
    """Approximates sampling from D_{Z^n, s}."""
    s_float = float(s)
    if s_float <= 0: raise ValueError("Gaussian parameter s must be positive")
    v = [round(random.gauss(0, s_float)) for _ in range(dim)]
    return vector(ZZ, v)

def lift_to_small_integers(v_mod_q, modulus):
    """Maps vector components from [0, q-1] to roughly [-q/2, q/2)."""
    q = modulus
    v_lifted = []
    q_half_strict = q / 2.0
    for x in v_mod_q:
        val = ZZ(x)
        v_lifted.append(val - q if val >= q_half_strict else val)
    return vector(ZZ, v_lifted)

# --- PKE Class Definition ---

class PKE:
    """
    Public Key Encryption for bits {0, 1} based on Protocol 1.
    Uses Dspr key generation and simplified encryption/decryption.
    """
    def __init__(self, n, q, r_int):
        """
        Initializes the PKE scheme. Assumes S=Identity.

        Args:
            n (int): Dimension / Security parameter.
            q (int): Modulus. Should be large enough relative to r_int (e.g., q > 2*r_int).
            r_int (int): Integer radius bound for error vectors (max component size).
        """
        if not isinstance(q, (int, Integer)) or q <= 1:
            raise ValueError("Modulus q must be an integer > 1")
        if not isinstance(r_int, (int, Integer)) or r_int < 0:
            raise ValueError("r_int must be a non-negative integer")
        if q <= 2 * r_int:
             print(f"Warning: q={q} may be too small relative to r_int={r_int} for reliable decryption.")

        self.n = n
        self.q = q
        self.r_int = r_int # Decoding radius / error bound
        self.S = identity_matrix(ZZ, n) # Base quadratic form (fixed)
        self.Zq = Integers(q) # Ring Z/qZ

    def keygen(self, max_retries=10):
        """
        Generate Public Key (pk) and Secret Key (sk) using Dspr.
        Ensures sk (U) is unimodular. pk = P, sk = U, where P = U^T S U.
        """
        # --- Dspr Sampling Logic ---
        print("Running KeyGen (using Dspr sampling)...")
        n = self.n
        Q = self.S # Base form is S=I
        s = float(n)
        if s <= 0: s = 1.0
        print(f"  Using Gaussian parameter s = {s:.2f}")
        C = 1.0 - 1.0 / (1.0 + exp(-math.pi))
        m = ceil(sqrt(2 * n / C))
        print(f"  Sampling m = {m} vectors")

        for retry in range(max_retries):
            print(f"  Attempt {retry + 1}/{max_retries}...")
            Y_list = [sample_discrete_gaussian(n, s) for _ in range(m)]
            Y = matrix(ZZ, Y_list).transpose()
            rank_Y = Y.rank()
            print(f"  Rank of sampled Y: {rank_Y}")
            if rank_Y < n:
                print("  Rank deficient, resampling...")
                continue
            try:
                basis_mat = Y.column_module().basis_matrix()
                B = basis_mat.transpose()
                if B.ncols() != n or B.rank() != n:
                     print("  Error: Extracted basis not full rank n x n.")
                     continue
                U = B.LLL() # Secret key sk
                det_U = U.det()
                print(f"  Determinant of U (LLL basis): {det_U}")
                if abs(det_U) == 1:
                    P = U.transpose() * self.S * U # Public key pk
                    pk = P
                    sk = U
                    print("KeyGen finished successfully.")
                    return pk, sk
                else:
                    print("  Warning: LLL basis is not unimodular. Retrying sampling.")
                    continue
            except Exception as e:
                print(f"  Error during basis extraction/LLL: {e}")
                continue
        print(f"KeyGen failed after {max_retries} retries.")
        raise RuntimeError("Failed to generate keys using Dspr after multiple attempts.")
        # --- End Dspr Sampling Logic ---

    def encrypt(self, pk, message):
        """
        Encrypts a message bit (0 or 1).
        """
        # P = pk # Public key isn't needed for simplified encryption sampling
        if message == 0:
            try:
                e_list = [randint(-self.r_int, self.r_int) for _ in range(self.n)]
                e = vector(ZZ, e_list)
                c = vector(self.Zq, e)
                return c
            except Exception as err:
                 print(f"Error during encryption of 0: {err}")
                 raise
        elif message == 1:
            try:
                c_list = [self.Zq.random_element() for _ in range(self.n)]
                c = vector(self.Zq, c_list)
                return c
            except Exception as err:
                 print(f"Error during encryption of 1: {err}")
                 raise
        else:
            raise ValueError("Message must be 0 or 1.")

    def decrypt(self, sk, c):
        """
        Decrypts the ciphertext c.
        """
        U = sk
        q = self.q
        Zq = self.Zq
        r_int = self.r_int

        if not isinstance(U, matrix.Matrix) or not U.is_square() or U.nrows() != self.n:
            print("Error: Invalid secret key format.")
            return -1
        if not isinstance(c, (vector.Vector_integer_mod, vector.Vector_dense_mod)) or \
           c.base_ring() != Zq or c.length() != self.n:
            print("Error: Invalid ciphertext format.")
            return -1

        try:
            det_U = U.det()
            if abs(det_U) != 1:
                 print(f"Error: Secret key U is not unimodular (det={det_U}). Cannot decrypt.")
                 return -1
            U_inv = U.inverse()
        except Exception as e:
             print(f"Error: Could not compute inverse of U: {e}")
             return -1

        try:
            U_inv_mod_q = U_inv.change_ring(Zq)
            z_mod_q = U_inv_mod_q * c
        except Exception as e:
             print(f"Error during matrix multiplication U_inv * c: {e}")
             return -1

        z = lift_to_small_integers(z_mod_q, q)
        is_small = all(abs(component) <= r_int for component in z)

        if is_small:
            return 0
        else:
            return 1