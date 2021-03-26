import numpy as np
import struct
import hashlib

# ChaCha20 Matrix: 16 words, 32-bits each (4 bytes each) for a total of 64-bytes
# cccccccc  cccccccc  cccccccc  cccccccc    #constants
# kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk    #key
# kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk    #key
# bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn    #block_number and nonce


class ChaCha20:
    def __init__(self, password_str, salt, nonce):
        self.block_size = 64
        self.key_size = 32
        self.password = password_str.encode("UTF-8")
        self.salt = salt
        self.nonce = nonce
        # Generate 2 keys of 32-byte length from the password for use as encryption key and HMAC key
        self.key_bytes = hashlib.scrypt(
            self.password,
            salt=self.salt,
            n=2 ** 15,
            r=8,
            p=1,
            maxmem=2 ** 26,
            dklen=self.block_size,
        )
        self.encryption_key = self.key_bytes[: self.key_size]
        self.hmac_key = self.key_bytes[self.key_size :]
        self.matrix = np.empty(shape=16, dtype=np.uint32)
        # constants values
        # "expa", "nd 3", "2-by", "te k" but using little endian: "apxe", "3 dn", "yb-2", "k et"
        self.matrix[:4] = np.array(
            [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574], dtype=np.uint32
        )
        # Add the 32-byte key. Use struct to unpack 8 4-bytes (Long) in little-endian order
        self.matrix[4:12] = struct.unpack("<8L", self.encryption_key)
        # Add the 12-byte nonce
        self.matrix[13:] = struct.unpack("<3L", self.nonce)

    def circular_left(self, num, i):
        num = np.binary_repr(num, self.key_size)
        val = num * 2
        return np.uint32(int(val[i : i + self.key_size], 2))

    def quarterround(self, a, b, c, d):
        a = np.add(a, b).astype(np.uint32)
        d ^= a
        d = self.circular_left(d, 16)
        c = np.add(c, d).astype(np.uint32)
        b ^= c
        b = self.circular_left(b, 12)
        a = np.add(a, b).astype(np.uint32)
        d ^= a
        d = self.circular_left(d, 8)
        c = np.add(c, d).astype(np.uint32)
        b ^= c
        b = self.circular_left(b, 7)
        return (a, b, c, d)

    def rounds(self, block):
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
                block[round] = self.quarterround(*(block[round]))
        return block

    def _xor(self, data_1, data_2):
        return [a ^ b for a, b in zip(data_1, data_2)]

    def encrypt(self, plaintext, counter):
        # Add the 4-byte block number
        self.matrix[12] = counter
        state = self.matrix.copy()
        state = self.rounds(state)
        # Create the final state
        final = state + self.matrix
        # Serialize the final state
        serial_out = struct.pack("<16L", *final)
        ciphertext = bytes(self._xor(serial_out, plaintext))
        return ciphertext

    def decrypt(self, ciphertext, counter):
        return self.encrypt(ciphertext, counter)
