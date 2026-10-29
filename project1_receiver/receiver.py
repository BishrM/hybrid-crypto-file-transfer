import socket
import sys
import threading
import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from project1_keyutils import keyUtils

class ThreadedReceiver(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def run(self):
        self.sock.listen(5)
        print("\n" + "="*50)
        print("     HYBRID CRYPTOGRAPHY RECEIVER (RSA + AES)")
        print("="*50)
        print(f"[+] Server initialized on {self.host}:{self.port}")
        print("[+] Listening for incoming file transfers...\n")
        
        while True:
            client, address = self.sock.accept()
            print(f"\n[+] [NETWORK] Connection accepted from {address}")
            client.settimeout(60)
            threading.Thread(target=self.listenToClient, args=(client, address)).start()

    def listenToClient(self, client, address):
        size = 1024
        try:
            # Generate session RSA Keypair
            ku = keyUtils.KeyUtils()
            rsa_key = ku.generate_rsa_key_pair()
            pub_key = rsa_key.publickey().export_key()
            
            # Step 1: Send Public Key
            client.send(pub_key)
            print("[+] [RSA] Sent 2048-bit RSA Public Key to Sender.")

            # Step 2: Receive and decrypt AES key
            enc_aes_key = client.recv(256)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            aes_key = cipher_rsa.decrypt(enc_aes_key)
            print("[+] [RSA] Decrypted 128-bit AES key using Receiver's RSA Private Key.")

            # Step 3: Receive payload
            start_time = time.time()
            file_data = b""
            while True:
                data = client.recv(size)
                if not data:
                    break
                file_data += data

            if file_data:
                nonce = file_data[:16]
                tag = file_data[16:32]
                ciphertext = file_data[32:]

                # Step 4: Decrypt payload using AES
                cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                decrypted_file = cipher_aes.decrypt_and_verify(ciphertext, tag)
                dec_time = (time.time() - start_time) * 1000

                output_path = "decrypted_received_file"
                with open(output_path, "wb") as f:
                    f.write(decrypted_file)

                print(f"[+] [AES] File payload decrypted successfully in {dec_time:.2f} ms.")
                print(f"[+] File Size : {len(decrypted_file) / 1024:.2f} KB")
                print(f"[+] Saved As  : '{output_path}'")
                print("="*50)

        except Exception as e:
            print(f"[-] Transfer Error: {e}")
        finally:
            client.close()

if __name__ == "__main__":
    receiver = ThreadedReceiver("127.0.0.1", 8080)
    receiver.start()
    receiver.join()  # keep main thread alive; Python 3.12+ refuses new threads at interpreter shutdown