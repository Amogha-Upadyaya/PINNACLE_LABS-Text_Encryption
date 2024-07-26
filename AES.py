from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os

def encrypt(key, plaintext):
    iv = os.urandom(16)  # Generate a random IV (Initialization Vector)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext

def decrypt(key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode()

if __name__ == "__main__":
    key = input("Enter AES key (16/24/32 bytes): ").encode()
    plaintext = input("Enter plaintext for AES encryption: ")
    
    ciphertext = encrypt(key, plaintext)
    print("Encrypted:", b64encode(ciphertext).decode())
    
    encrypted_text = b64decode(input("Enter ciphertext for AES decryption: "))
    decrypted_text = decrypt(key, encrypted_text)
    print("Decrypted:", decrypted_text)
