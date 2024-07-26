from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os

def encrypt(key, plaintext):
    try:
        iv = os.urandom(8)  # Generate a random IV (Initialization Vector)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_data = pad(plaintext.encode(), DES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return iv + ciphertext
    except Exception as e:
        print(f"Error during encryption: {e}")
        return None

def decrypt(key, ciphertext):
    try:
        iv = ciphertext[:8]
        ciphertext = ciphertext[8:]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), DES.block_size)
        return decrypted_data.decode()
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

def des_menu():
    while True:
        choice = input("Choose operation for DES (encrypt/decrypt/quit): ").strip().lower()
        if choice == "quit":
            break
        key = input("Enter DES key (8 bytes): ").encode()
        if len(key) != 8:
            print("Invalid key length! Key must be 8 bytes long.")
            continue
        if choice == "encrypt":
            plaintext = input("Enter plaintext for DES encryption: ")
            ciphertext = encrypt(key, plaintext)
            if ciphertext:
                print("Encrypted:", b64encode(ciphertext).decode())
        elif choice == "decrypt":
            encrypted_text = b64decode(input("Enter ciphertext for DES decryption: "))
            decrypted_text = decrypt(key, encrypted_text)
            if decrypted_text:
                print("Decrypted:", decrypted_text)
        else:
            print("Invalid choice")

