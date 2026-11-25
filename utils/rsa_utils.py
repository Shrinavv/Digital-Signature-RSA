"""RSA helpers: prime generation, key generation, PKCS#1 v1.5 (SHA-256) signing.

Educational implementation. Primes and keys come from the ``secrets`` module
(a CSPRNG), primality uses Miller-Rabin, and signatures use the standard
EMSA-PKCS1-v1_5 encoding instead of signing the bare hash.
"""
import hashlib
import hmac
import os
import secrets
from pathlib import Path

# Project root = parent of utils/. Scripts use it so they work from any directory.
ROOT = Path(__file__).resolve().parent.parent

PUBLIC_EXPONENT = 65537
DEFAULT_KEY_BITS = 2048

# DER prefix of DigestInfo for SHA-256 (RFC 8017, section 9.2, note 1)
_SHA256_DIGESTINFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
]


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def is_prime(n, k=40):
    """Miller-Rabin primality test with k random bases (error <= 4^-k)."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # a in [2, n-2]
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    """Random prime with exactly `bits` bits (top two bits set so p*q has full length)."""
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_prime(candidate):
            return candidate


def generate_keys(file_path, bits=DEFAULT_KEY_BITS):
    """Create an RSA key pair; write public_key.txt (e, n) and private_key.txt (d, n)."""
    if bits < 1024 or bits % 2:
        raise ValueError("bits must be an even number >= 1024")
    e = PUBLIC_EXPONENT
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if n.bit_length() != bits or gcd(e, phi) != 1:
            continue
        break
    d = pow(e, -1, phi)

    folder = Path(file_path)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "public_key.txt").write_text(f"{e}\n{n}")
    private_path = folder / "private_key.txt"
    private_path.write_text(f"{d}\n{n}")
    try:
        os.chmod(private_path, 0o600)  # owner-only where the OS supports it
    except OSError:
        pass
    return e, d, n


def read_key(path):
    """Read a key file written by generate_keys; returns (exponent, modulus)."""
    parts = Path(path).read_text().split()
    if len(parts) != 2:
        raise ValueError(f"{path} must contain exactly two integers")
    return int(parts[0]), int(parts[1])


def hash_message(message):
    """SHA-256 digest of the message as an integer (kept for reference)."""
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), "big")


def _emsa_pkcs1_v15(message, k):
    """EMSA-PKCS1-v1_5 encoding of SHA-256(message) into k bytes."""
    t = _SHA256_DIGESTINFO_PREFIX + hashlib.sha256(message.encode()).digest()
    if k < len(t) + 11:
        raise ValueError("RSA modulus too small for PKCS#1 v1.5 + SHA-256")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def sign_message(message, d, n):
    """Return the signature (integer) of `message` using private key (d, n)."""
    k = (n.bit_length() + 7) // 8
    m = int.from_bytes(_emsa_pkcs1_v15(message, k), "big")
    return pow(m, d, n)


def verify_signature(message, signature, e, n):
    """True if `signature` is a valid signature of `message` under public key (e, n)."""
    if not 0 <= signature < n:
        return False
    k = (n.bit_length() + 7) // 8
    recovered = pow(signature, e, n).to_bytes(k, "big")
    return hmac.compare_digest(recovered, _emsa_pkcs1_v15(message, k))


def parse_signed_text(text):
    """Split 'message\\nsignature' text into (message, signature_int).

    The signature is the last line; everything before it is the message.
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").strip("\n").split("\n")
    if len(lines) < 2:
        raise ValueError("expected the message first and the signature on the last line")
    signature_text = lines[-1].strip()
    if not signature_text.isdigit():
        raise ValueError("the last line must be the signature (digits only)")
    return "\n".join(lines[:-1]), int(signature_text)


def read_signed_file(path):
    return parse_signed_text(Path(path).read_text())
