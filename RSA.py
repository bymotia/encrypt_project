import os
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
RESET = "\033[0m"


class RSAEncryption:
    def __init__(self):
        self.private_key, self.public_key = self.generate_rsa_key_pair()

    def save_keys(self, public_key_file, private_key_file):
        with open(public_key_file, "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        with open(private_key_file, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    @staticmethod
    def load_keys(public_key_file, private_key_file):
        with open(public_key_file, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        with open(private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        return private_key, public_key

    @staticmethod
    def generate_rsa_key_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def _encrypt_aes_gcm(self, plaintext):
        # Pad the plaintext to be at least 16 bytes
        padding_size = max(16 - len(plaintext), 0)
        plaintext += b'\x00' * padding_size

        aes_key = os.urandom(32)  # 32 bytes = 256 bits
        aes_nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(aes_nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        print(GREEN + "Encrypted" + RESET)

        return aes_key, aes_nonce, padding_size.to_bytes(2, byteorder='big') + ciphertext + encryptor.tag

    def _decrypt_aes_gcm(self, aes_key, aes_nonce, ciphertext_with_tag):
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(aes_nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        padding_size_bytes, ciphertext, tag = ciphertext_with_tag[:2], ciphertext_with_tag[2:-16], ciphertext_with_tag[-16:]

        padding_size = int.from_bytes(padding_size_bytes, byteorder='big')
        plaintext = decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)

        # Remove padding from the decrypted data
        return plaintext[:-padding_size]
    def encrypt_file(self, input_file):
        with open(input_file, "rb") as f:
            plaintext = f.read()

        aes_key, aes_nonce, ciphertext_with_tag = self._encrypt_aes_gcm(plaintext)
        encrypted_aes_key = self.public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted_data = aes_nonce + encrypted_aes_key + ciphertext_with_tag
        with open(input_file, "wb") as f:
            f.write(encrypted_data)

    def decrypt_file(self, input_file):
        with open(input_file, "rb") as f:
            encrypted_data = f.read()

        aes_nonce, encrypted_aes_key, ciphertext_with_tag = encrypted_data[:12], encrypted_data[12:268], encrypted_data[
                                                                                                         268:]
        aes_key = self.private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print(RED + "Decrypted" + RESET)
        plaintext = self._decrypt_aes_gcm(aes_key, aes_nonce, ciphertext_with_tag)
        with open(input_file, "wb") as f:
            f.write(plaintext)


def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file using RSA.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="The operation mode: 'encrypt' or 'decrypt'.")
    parser.add_argument("input_file", help="The input file to be processed.")
    parser.add_argument("--public_key", help="Public key file", default="public_key.pem")
    parser.add_argument("--private_key", help="Private key file", default="private_key.pem")
    args = parser.parse_args()

    rsa_encryption = RSAEncryption()

    if args.mode == "encrypt":
        rsa_encryption.encrypt_file(args.input_file)
        rsa_encryption.save_keys(args.public_key, args.private_key)
    elif args.mode == "decrypt":
        rsa_encryption.private_key, rsa_encryption.public_key = RSAEncryption.load_keys(args.public_key, args.private_key)
        rsa_encryption.decrypt_file(args.input_file)


if __name__ == "__main__":
    main()

