from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os

def encrypt(key, plaintext):
    try:
        iv = os.urandom(16)  # Generate a random IV (Initialization Vector)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return iv + ciphertext
    except Exception as e:
        print(f"Error during encryption: {e}")
        return None

def decrypt(key, ciphertext):
    try:
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_data.decode()
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

def aes_menu():
    while True:
        choice = input("Choose operation for AES (encrypt/decrypt/quit): ").strip().lower()
        if choice == "quit":
            break
        key = input("Enter AES key (16/24/32 bytes): ").encode()
        if len(key) not in [16, 24, 32]:
            print("Invalid key length! Key must be 16, 24, or 32 bytes long.")
            continue
        if choice == "encrypt":
            plaintext = input("Enter plaintext for AES encryption: ")
            ciphertext = encrypt(key, plaintext)
            if ciphertext:
                print("Encrypted:", b64encode(ciphertext).decode())
        elif choice == "decrypt":
            encrypted_text = b64decode(input("Enter ciphertext for AES decryption: "))
            decrypted_text = decrypt(key, encrypted_text)
            if decrypted_text:
                print("Decrypted:", decrypted_text)
        else:
            print("Invalid choice")
