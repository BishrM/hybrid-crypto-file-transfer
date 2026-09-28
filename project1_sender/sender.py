import socket
import os
import time
from tkinter import Tk, filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

def select_file_via_gui():
    """Modification 1: GUI File Picker using Tkinter"""
    root = Tk()
    root.withdraw() # Hide the main root window
    root.attributes('-topmost', True) # Bring file dialog to front
    file_path = filedialog.askopenfilename(
        title="Select File to Encrypt & Send",
        filetypes=[("All Files", "*.*"), ("Text Files", "*.txt"), ("PDF Files", "*.pdf")]
    )
    root.destroy()
    return file_path

def send_file(host, port, file_path):
    if not file_path or not os.path.exists(file_path):
        print("[-] Error: No file selected or file does not exist!")
        return

    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)

    print("\n" + "="*50)
    print("      HYBRID CRYPTOGRAPHY SENDER (RSA + AES)")
    print("="*50)
    print(f"[+] Selected File : {file_name}")
    print(f"[+] File Size     : {file_size / 1024:.2f} KB")
    print(f"[+] Timestamp     : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*50)

    # Connect to Receiver
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print("[+] [NETWORK] Connected to Receiver at {}:{}".format(host, port))

    # Step 1: Receive Receiver's RSA Public Key
    pub_key_data = client.recv(2048)
    receiver_pub_key = RSA.import_key(pub_key_data)
    print("[+] [RSA] Received 2048-bit RSA Public Key from Receiver.")

    # Step 2: Generate random 128-bit AES Key
    aes_key = get_random_bytes(16)
    print("[+] [AES] Generated fresh random 128-bit AES symmetric key.")

    # Step 3: Encrypt AES Key using Receiver's RSA Public Key
    cipher_rsa = PKCS1_OAEP.new(receiver_pub_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    client.send(enc_aes_key)
    print("[+] [RSA] Encrypted AES key with RSA Public Key and sent to Receiver.")

    # Step 4: Encrypt file content using AES-EAX
    start_time = time.time()
    with open(file_path, "rb") as f:
        file_data = f.read()

    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
    enc_time = (time.time() - start_time) * 1000

    print(f"[+] [AES] File encrypted successfully in {enc_time:.2f} ms.")

    # Send payload: nonce (16b) + tag (16b) + ciphertext
    payload = cipher_aes.nonce + tag + ciphertext
    client.sendall(payload)
    print("[+] [NETWORK] Encrypted file payload transmitted successfully!")
    print("="*50 + "\n")
    client.close()

if __name__ == "__main__":
    print("[*] Opening File Selector window...")
    chosen_file = select_file_via_gui()
    if chosen_file:
        send_file("127.0.0.1", 8080, chosen_file)
    else:
        print("[-] File selection cancelled.")