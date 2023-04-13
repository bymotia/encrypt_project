import argparse
import os
from rsa_encryption import RSAEncryption

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file using RSA.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="The operation mode: 'encrypt' or 'decrypt'.")
    parser.add_argument("input_file", help="The input file to be processed.")
    parser.add_argument("--public_key", help="Public key file", default="public_key.pem")
    parser.add_argument("--private_key", help="Private key file", default="private_key.pem")
    args = parser.parse_args()

    keys_folder = "keys"
    if not os.path.exists(keys_folder):
        os.makedirs(keys_folder)

    public_key_path = os.path.join(keys_folder, args.public_key)
    private_key_path = os.path.join(keys_folder, args.private_key)

    if args.mode == "encrypt":
        if not os.path.exists(public_key_path) or not os.path.exists(private_key_path):
            private_key, public_key = RSAEncryption.generate_rsa_key_pair()
            RSAEncryption.save_keys(public_key_path, private_key_path, private_key, public_key)
        else:
            private_key, public_key = RSAEncryption.load_keys(public_key_path, private_key_path)

        rsa_encryption = RSAEncryption(private_key, public_key)
        rsa_encryption.encrypt_file(args.input_file)
    elif args.mode == "decrypt":
        private_key, public_key = RSAEncryption.load_keys(public_key_path, private_key_path)
        rsa_encryption = RSAEncryption(private_key, public_key)
        rsa_encryption.decrypt_file(args.input_file)

if __name__ == "__main__":
    main()
