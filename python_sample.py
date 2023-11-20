from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad, pad
from base64 import b64decode, b64encode
from Crypto.Random import get_random_bytes
import binascii

import hashlib
import hmac
import os
from hashlib import pbkdf2_hmac


def derive_key_from_passphrase(passphrase, salt, key_length, iterations):
    key = pbkdf2_hmac(
        hash_name="sha256",  # Use SHA-256 hash function
        password=passphrase.encode("utf-8"),
        salt=salt,
        dklen=key_length // 8,  # Convert bits to bytes
        iterations=iterations,
    )
    return key


def to_hex(_byte: bytes):
    return binascii.hexlify(_byte).decode("utf-8")


# def derive_key_from_passphrase(
#     passphrase: str, salt: bytes, key_length=16, iterations=1000
# ):
#     key = PBKDF2(passphrase, salt, dkLen=key_length, count=iterations)
#     return key


def encrypt_message(message, passphrase, encode=False):
    # salt = binascii.unhexlify("01380ccf6c17bb7b")
    salt = get_random_bytes(8)
    key = derive_key_from_passphrase(passphrase, salt)
    # Generate a random IV (Initialization Vector)
    iv = get_random_bytes(AES.block_size)

    # Create an AES cipher object with CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the message and encrypt it
    ciphertext = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))

    combined_hex = to_hex(salt) + to_hex(iv) + to_hex(key) + to_hex(ciphertext)
    breakpoint()
    if encode:
        return b64encode(salt + iv + ciphertext).decode("utf-8")
    return combined_hex
    # Combine IV, salt, and ciphertext and encode as base64
    encrypted_message = b64encode(salt + iv + ciphertext).decode("utf-8")

    return encrypted_message


def decrypt_encoded_message(encrypted_message: str, passphrase: str):
    # Decode the base64-encoded input
    encrypted_bytes = b64decode(encrypted_message)

    # Extract salt and IV
    salt = encrypted_bytes[:8]
    iv = encrypted_bytes[8 : 8 + AES.block_size]

    key = derive_key_from_passphrase(passphrase, salt)
    breakpoint()
    # Create an AES cipher object with CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and unpad the message
    decrypted_message = unpad(
        cipher.decrypt(encrypted_bytes[8 + AES.block_size :]), AES.block_size
    ).decode("utf-8")

    return decrypted_message


def decrypt_hex_message(encrypted_message: str, passphrase: str, with_key=False):
    # Decode the base64-encoded input
    encrypted_bytes = binascii.unhexlify(encrypted_message)
    # Extract salt and IV
    # Extract salt and IV
    salt = encrypted_bytes[:8]
    iv = encrypted_bytes[8 : 8 + AES.block_size]
    last_index = (8 + AES.block_size * 2) + 16
    key = encrypted_bytes[8 + AES.block_size : last_index]
    # Create an AES cipher object with CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and unpad the message
    decrypted_message = unpad(
        cipher.decrypt(encrypted_bytes[last_index:]), AES.block_size
    ).decode("utf-8")

    return decrypted_message


def decrypt_server_hex_message(encrypted_message: str, passphrase: str, with_key=False):
    # Decode the base64-encoded input
    # encrypted_bytes = binascii.unhexlify(encrypted_message)
    # Extract salt and IV
    # Extract salt and IV
    salt = binascii.unhexlify(encrypted_message[:16])
    iv = binascii.unhexlify(encrypted_message[16 : 16 + (AES.block_size * 2)])
    start = 16 + (AES.block_size * 2)
    end = start + 16 + 32 + 32 + 64
    p_hash = encrypted_message[start:end]
    password = decrypt_hex_message(p_hash, passphrase)
    key = derive_key_from_passphrase(password, salt, 256, 100000)
    remaining = binascii.unhexlify(encrypted_message[end:])

    # Create an AES cipher object with CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and unpad the message
    decrypted_message = unpad(cipher.decrypt(remaining), AES.block_size).decode("utf-8")

    return decrypted_message


def decrypt_message(encrypted_message: str, passphrase: str):
    # Decode the base64-encoded input
    encrypted_bytes = encrypted_message.encode("utf-8")
    # encrypted_bytes = b64decode(encrypted_message)

    # Extract salt and IV
    salt = encrypted_bytes[:16]
    iv = encrypted_bytes[16 : AES.block_size * 2]
    key = encrypted_bytes[AES.block_size * 2 : AES.block_size * 4]
    remaining = encrypted_bytes[AES.block_size * 4 :]
    # key = derive_key_from_passphrase(passphrase, salt, key_length=16, iterations=100000)
    # Create an AES cipher object with CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and unpad the message
    decrypted_message = cipher.decrypt(remaining)
    return decrypted_message


if __name__ == "__main__":
    message = "Hello World!"
    passphrase = "secret"
    # encrypted_message = "yhqN41DQAGvIde/DLfaCIZNCL8TzBNEItp+RywKJdK8DEGomQ1HsxQ=="
    encrypted_message = "0Y48UcEMECT+OAXZU2xeo6Dlb1f+ns8/gWlnDuWJTPhgbB62RSKoORysc9SAVf1FNC+Ak1IiqpVA2thQtIjZHaLc8P6N5x+XkiquFNPBXCIK4/r4XuQVnpflEDodChNoQB3OV98hI60ddubLdabRc6AgXcTq+wbgx4PWPo2YVlsgyc4N5YUx1hVX3UA4u1KWylEgsYjuAudJ9B4qIn61Z/83vm61DwSIo6AvbjtMK70g9GmxF4Ch+0GCkpcuSFhE+8Bsosg+UwJ0wOfzBab3OH1gSSvsEi2qk63BL2Z1KnUrNPVDtCwkdWNSptWglnux"
    # encrypted_message = "DMkevLT0iT8KUhuOAd29nLHv3BiJbvviAY0wCKnPgZGPDRl8+g8Fkg=="
    encrypted_message = to_hex(b64decode(encrypted_message))
    # encrypt_message = encrypt_message(message, passphrase, True)
    result = decrypt_server_hex_message(encrypted_message, passphrase, True)
    # result = decrypt_hex_message(encrypted_message, passphrase, True)
    # result = decrypt_encoded_message(encrypted_message, passphrase)
    # print("encrypted message", encrypt_message)
    print("decrypted message", result)
