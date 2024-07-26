import hashlib
import random
from sympy import isprime, mod_inverse

def generate_prime(bits):
    """Generate a prime number with a specific bit length."""
    while True:
        number = random.getrandbits(bits)
        if isprime(number):
            return number

def generate_keypair(bits):
    """Generate RSA keypair."""
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # Common choice for e
    d = mod_inverse(e, phi)

    return (e, n), (d, n)  # Public key and private key


def hash_message(message):
    """Hash a message using SHA-256."""
    hasher = hashlib.sha256()
    hasher.update(message.encode())
    return hasher.digest()


def sign_message(message, private_key):
    """Sign a message using RSA private key."""
    d, n = private_key
    # Convert message to integer
    hashed_message = hash_message(message)
    m = int.from_bytes(hashed_message, 'big')
    # Compute the signature
    s = pow(m, d, n)
    return s

def verify_signature(message, signature, public_key):
    """Verify an RSA signature."""
    e, n = public_key
    # Convert message to integer
    hashed_message = hash_message(message)
    # Convert the hash to an integer
    m = int.from_bytes(hashed_message, 'big')

    # Decrypt the signature
    s = pow(signature, e, n)
    return s == m

