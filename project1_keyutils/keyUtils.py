import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

class KeyUtils():
    def __init__(self):
        pass

    def generate_rsa_key_pair(self):
        key = RSA.generate(2048)
        return key

    def write_rsa_keys_to_file(self, key):
        private_key = key.export_key()
        file_out = open("private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open("receiver.pem", "wb")
        file_out.write(public_key)
        file_out.close()

    def read_rsa_private_key_from_file(self, file_path):
        encoded_key = open(file_path, "rb").read()
        key = RSA.import_key(encoded_key)
        return key

    def read_rsa_public_key_from_file(self, file_path):
        encoded_key = open(file_path, "rb").read()
        key = RSA.import_key(encoded_key)
        return key

    def encrypt_rsa(self, public_key, message):
        cipher_rsa = PKCS1_OAEP.new(public_key)
        enc_data = cipher_rsa.encrypt(message)
        return enc_data

    def decrypt_rsa(self, private_key, encrypted_message):
        cipher_rsa = PKCS1_OAEP.new(private_key)
        data = cipher_rsa.decrypt(encrypted_message)
        return data