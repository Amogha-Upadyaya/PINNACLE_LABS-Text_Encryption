# main.py

from AES import encrypt as aes_encrypt, decrypt as aes_decrypt
from DES import encrypt as des_encrypt, decrypt as des_decrypt
from RSA import generate_keys, encrypt as rsa_encrypt, decrypt as rsa_decrypt
from base64 import b64encode, b64decode

def main():
    # AES encryption and decryption
    aes_key = b'Sixteen byte key'
    aes_plaintext = "Hello, AES encryption and decryption!"
    
    aes_ciphertext = aes_encrypt(aes_key, aes_plaintext)
    print("AES Encrypted:", b64encode(aes_ciphertext).decode())
    
    aes_decrypted_text = aes_decrypt(aes_key, aes_ciphertext)
    print("AES Decrypted:", aes_decrypted_text)
    
    print()
    
    # DES encryption and decryption
    des_key = b'8bytekey'
    des_plaintext = "Hello, DES encryption and decryption!"
    
    des_ciphertext = des_encrypt(des_key, des_plaintext)
    print("DES Encrypted:", b64encode(des_ciphertext).decode())
    
    des_decrypted_text = des_decrypt(des_key, des_ciphertext)
    print("DES Decrypted:", des_decrypted_text)
    
    print()
    
    # RSA encryption and decryption
    private_key, public_key = generate_keys()
    
    rsa_plaintext = "Hello, RSA encryption and decryption!"
    print("RSA Plaintext:", rsa_plaintext)
    
    rsa_ciphertext = rsa_encrypt(public_key, rsa_plaintext)
    print("RSA Encrypted:", rsa_ciphertext)
    
    rsa_decrypted_text = rsa_decrypt(private_key, rsa_ciphertext)
    print("RSA Decrypted:", rsa_decrypted_text)

if __name__ == "__main__":
    main()
