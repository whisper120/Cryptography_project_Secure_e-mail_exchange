import struct
import os

# Constants for RC6
w = 32  # word size in bits
r = 20  # number of rounds
b = 16  # length of key in bytes
P32 = 0xB7E15163
Q32 = 0x9E3779B9


def rotate_left(x, y):
    y = y % w  # Ensure the shift amount is within the word size
    return ((x << y) & (2 ** w - 1)) | (x >> (w - y))


def rotate_right(x, y):
    y = y % w  # Ensure the shift amount is within the word size
    return (x >> y) | ((x << (w - y)) & (2 ** w - 1))


def rc6_key_schedule(key):
    # Key setup
    L = [0] * (b // 4)
    for i in range(b - 1, -1, -1):
        L[i // 4] = (L[i // 4] << 8) + key[i]

    S = [P32]
    for i in range(1, 2 * r + 4):
        S.append((S[i - 1] + Q32) % 2 ** w)

    # Mixing in the secret key
    A = B = i = j = 0
    for _ in range(3 * max(b // 4, 2 * r + 4)):
        A = S[i] = rotate_left((S[i] + A + B) % 2 ** w, 3)
        B = L[j] = rotate_left((L[j] + A + B) % 2 ** w, (A + B) % w)
        i = (i + 1) % (2 * r + 4)
        j = (j + 1) % (b // 4)

    return S


def rc6_encrypt(plaintext, S):
    # Assumes plaintext is a byte string of length 16
    A, B, C, D = struct.unpack('<4I', plaintext)

    B = (B + S[0]) % 2 ** w
    D = (D + S[1]) % 2 ** w

    for i in range(1, r + 1):
        t = rotate_left(B * (2 * B + 1) % 2 ** w, 5)
        u = rotate_left(D * (2 * D + 1) % 2 ** w, 5)
        A = (rotate_left(A ^ t, u) + S[2 * i]) % 2 ** w
        C = (rotate_left(C ^ u, t) + S[2 * i + 1]) % 2 ** w
        A, B, C, D = B, C, D, A

    A = (A + S[2 * r + 2]) % 2 ** w
    C = (C + S[2 * r + 3]) % 2 ** w

    return struct.pack('<4I', A, B, C, D)


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def pad(plaintext):
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding


def unpad(padded_plaintext):
    padding_len = padded_plaintext[-1]
    return padded_plaintext[:-padding_len]


def rc6_ofb_encrypt(key, iv, plaintext):
    # Key schedule
    S = rc6_key_schedule(key)

    # Initialize
    ciphertext = bytearray()
    feedback = iv
    padded_plaintext = pad(plaintext)

    for i in range(0, len(padded_plaintext), 16):
        # Generate the next keystream block
        keystream = rc6_encrypt(feedback, S)

        # XOR plaintext with keystream to produce ciphertext
        block = padded_plaintext[i:i + 16]
        ciphertext_block = xor_bytes(block, keystream)
        ciphertext.extend(ciphertext_block)

        # Update feedback
        feedback = keystream

    return bytes(ciphertext)


def rc6_ofb_decrypt(key, iv, ciphertext):
    # Key schedule
    S = rc6_key_schedule(key)

    # Initialize
    plaintext = bytearray()
    feedback = iv

    for i in range(0, len(ciphertext), 16):
        # Generate the next keystream block
        keystream = rc6_encrypt(feedback, S)

        # XOR ciphertext with keystream to produce plaintext
        block = ciphertext[i:i + 16]
        plaintext_block = xor_bytes(block, keystream)
        plaintext.extend(plaintext_block)

        # Update feedback
        feedback = keystream

    return unpad(bytes(plaintext))