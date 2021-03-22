import numpy as np
import struct
import hashlib
import secrets

# Chacha20 Matrix: 16 words, 32-bits each (4 bytes each) for a total of 64-bytes
# cccccccc  cccccccc  cccccccc  cccccccc    #constants
# kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk    #key
# kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk    #key
# bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn    #block_number and nonce


def circular_left(num, i):
    num = np.binary_repr(num, 32)
    val = num * 2
    return np.uint32(int(val[i : i + 32], 2))


def quarterround(a, b, c, d):
    a = np.add(a, b).astype(np.uint32)
    d ^= a
    d = circular_left(d, 16)
    c = np.add(c, d).astype(np.uint32)
    b ^= c
    b = circular_left(b, 12)
    a = np.add(a, b).astype(np.uint32)
    d ^= a
    d = circular_left(d, 8)
    c = np.add(c, d).astype(np.uint32)
    b ^= c
    b = circular_left(b, 7)
    return (a, b, c, d)


def rounds(matrix):
    steps = [
        [0, 4, 8, 12],
        [1, 5, 9, 13],
        [2, 6, 10, 14],
        [3, 7, 11, 15],
        [0, 5, 10, 15],
        [1, 6, 11, 12],
        [2, 7, 8, 13],
        [3, 4, 9, 14],
    ]
    for _ in range(10):
        for round in steps:
            matrix[round] = quarterround(*(matrix[round]))


password_str = "test"
password = password_str.encode("UTF-8")

# Create a random 128 bit salt (16 bytes) used in the key derivation function
# The salt will be stored as the first block of the ciphertext
salt = secrets.token_bytes(16)

matrix = np.empty(shape=16, dtype=np.uint32)

# constants values
# "expa", "nd 3", "2-by", "te k" but using little endian: "apxe", "3 dn", "yb-2", "k et"
matrix[:4] = np.array([0x61707865, 0x3320646E, 0x79622D32, 0x6B206574], dtype=np.uint32)

n_bytes = 32
# Generate 2 keys of 32-byte length from the password for use as encryption key and HMAC key
key_bytes = hashlib.scrypt(
    password, salt=salt, n=2 ** 15, r=8, p=1, maxmem=2 ** 26, dklen=n_bytes * 2
)

encryption_key = key_bytes[:n_bytes]
hmac_key = key_bytes[n_bytes:]

# Create a random 12-byte nonce
nonce = secrets.token_bytes(12)

# Add the 32-byte key. Use struct to unpack 8 4-bytes (Long) in little-endian order
matrix[4:12] = struct.unpack("<8L", encryption_key)

# Add the 12-byte nonce
matrix[13:] = struct.unpack("<3L", nonce)

counter = 0

# Add the 4-byte block number
matrix[12] = counter

state = matrix.copy()
rounds(state)
# Create the final state
final = state + matrix
# Serialize the final state
serial_out = struct.pack("<16L", *final)
