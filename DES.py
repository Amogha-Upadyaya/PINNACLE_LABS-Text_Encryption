from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os

def encrypt(key, plaintext):
    iv = os.urandom(8)  # Generate a random IV (Initialization Vector)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext

def decrypt(key, ciphertext):
    iv = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted_data.decode()

# Example usage:
if __name__ == "__main__":
    key = b'8bytekey'  # DES key must be exactly 8 bytes long
    plaintext = "Hello, DES encryption and decryption!"
    
    ciphertext = encrypt(key, plaintext)
    print("Encrypted:", b64encode(ciphertext).decode())
    
    decrypted_text = decrypt(key, ciphertext)
    print("Decrypted:", decrypted_text)
