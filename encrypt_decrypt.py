from chacha20 import ChaCha20
import getpass
import secrets
import argparse
import hmac
import hashlib


def encrypt_decrypt(func, in_stream, count_start):
    # ChaCha20 block size is 64 bytes
    block_size = 64
    return b"".join(
        [
            func(in_stream[i : i + block_size], i // block_size + count_start)
            for i in range(0, len(in_stream), block_size)
        ]
    )


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true")
    group.add_argument("-d", "--decrypt", action="store_true")
    parser.add_argument("input_file")
    parser.add_argument("output_file")
    args = parser.parse_args()

    passwd = getpass.getpass(
        "Enter {} password: ".format("encryption" if args.encrypt else "decryption")
    )

    # ChaCha20 key size is 32 bytes
    key_size = 32

    # Read input file into memory
    with open(args.input_file, "rb") as f_in:
        file_in = f_in.read()

    # Encryption
    if args.encrypt:
        # Create a random 256 bit salt (32 bytes) used in the key derivation function
        # The salt will be stored as half of the first block of the ciphertext
        salt = secrets.token_bytes(key_size)

        # Create a random 12-byte nonce
        nonce = secrets.token_bytes(12)

        # Create the IV from the nonce and the initial 4-byte counter value starting at 0
        # The IV will be stored as the second block of the ciphertext
        counter = 0

        IV = nonce + int.to_bytes(counter, 4, "big")

        # Start ChaCha20 cipher
        cipher = ChaCha20(password_str=passwd, salt=salt, nonce=nonce)
        file_out = salt + IV + encrypt_decrypt(cipher.encrypt, file_in, counter)

        # Create authentication HMAC and store it as the last 32 bytes of the file
        hmac_val = hmac.digest(key=cipher.hmac_key, msg=file_out, digest=hashlib.sha256)

        # Append HMAC to the ciphertext
        file_out += hmac_val

    # Decryption
    else:
        # Extract the salt from half of the first block of the ciphertext
        salt = file_in[0:key_size]

        # Extract nonce from the next 12 bytes of the ciphertext
        nonce = file_in[key_size : key_size + 12]

        # Extract the starting counter value from the next 4 bytes of the ciphertext
        counter = file_in[key_size + 12 : key_size + 12 + 4]
        counter = int.from_bytes(counter, "big")

        # Extract the HMAC value from the last 32 bytes of the ciphertext
        hmac_val = file_in[-key_size:]

        # Start ChaCha20 cipher
        cipher = ChaCha20(password_str=passwd, salt=salt, nonce=nonce)

        # Compare HMAC values (remove the HMAC value from the ciphertext before comparing)
        assert hmac.compare_digest(
            hmac_val,
            hmac.digest(
                key=cipher.hmac_key,
                msg=file_in[:-key_size],
                digest=hashlib.sha256,
            ),
        ), "HMAC check failed."

        # Strip the salt, IV and HMAC from the ciphertext
        file_in = file_in[key_size + 12 + 4 : -key_size]

        file_out = encrypt_decrypt(cipher.decrypt, file_in, counter)

    # Write output file
    with open(args.output_file, "wb") as f_out:
        f_out.write(file_out)

    print(
        "\n{0} successfully completed! {1} has been stored in: {2}".format(
            "Encryption" if args.encrypt else "Decryption",
            "Ciphertext" if args.encrypt else "Plaintext",
            args.output_file,
        )
    )


if __name__ == "__main__":
    main()
