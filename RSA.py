import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class RSAEncryption:
    def __init__(self):
        self.private_key, self.public_key = self.generate_rsa_key_pair()

    def __init__(self):
        self.private_key, self.public_key = self.generate_rsa_key_pair()

    @staticmethod
    def generate_rsa_key_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_file(self, input_file):
        with open(input_file, "rb") as f:
            plaintext = f.read()
        ciphertext = self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open(input_file, "wb") as f:
            f.write(ciphertext)

    def decrypt_file(self, input_file):
        with open(input_file, "rb") as f:
            ciphertext = f.read()
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open(input_file, "wb") as f:
            f.write(plaintext)

    @staticmethod
    def generate_rsa_key_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_file(self, input_file):
        with open(input_file, "rb") as f:
            plaintext = f.read()
        ciphertext = self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open(input_file, "wb") as f:
            f.write(ciphertext)

    def decrypt_file(self, input_file):
        with open(input_file, "rb") as f:
            ciphertext = f.read()
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open(input_file, "wb") as f:
            f.write(plaintext)
def main():
    parser = argparse.ArgumentParser(description="Encrypt and decrypt a file using RSA.")
    parser.add_argument("input_file", help="The input file to be encrypted.")
    parser.add_argument("--public_key", help="Public key file", default="public_key.pem")
    parser.add_argument("--private_key", help="Private key file", default="private_key.pem")
    args = parser.parse_args()

    rsa_encryption = RSAEncryption()

    # Encrypt a file
    rsa_encryption.encrypt_file(args.input_file)
    rsa_encryption.save_keys(args.public_key, args.private_key)

if __name__ == "__main__":
    main()