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

# Example usage:
if __name__ == "__main__":
    key = b'Sixteen byte key'  # AES key must be either 16, 24, or 32 bytes long
    plaintext = "Hello, AES encryption and decryption!"
    
    ciphertext = encrypt(key, plaintext)
    print("Encrypted:", b64encode(ciphertext).decode())
    
    decrypted_text = decrypt(key, ciphertext)
    print("Decrypted:", decrypted_text)
