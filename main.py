from AES import encrypt as aes_encrypt, decrypt as aes_decrypt
from DES import encrypt as des_encrypt, decrypt as des_decrypt
from RSA import generate_keys, encrypt as rsa_encrypt, decrypt as rsa_decrypt
from base64 import b64encode, b64decode

def main():
    # AES encryption and decryption
    aes_key = input("Enter AES key (16/24/32 bytes): ").encode()
    aes_plaintext = input("Enter plaintext for AES encryption: ")
    
    aes_ciphertext = aes_encrypt(aes_key, aes_plaintext)
    print("AES Encrypted:", b64encode(aes_ciphertext).decode())
    
    aes_encrypted_text = b64decode(input("Enter ciphertext for AES decryption: "))
    aes_decrypted_text = aes_decrypt(aes_key, aes_encrypted_text)
    print("AES Decrypted:", aes_decrypted_text)
    
    print()
    
    # DES encryption and decryption
    des_key = input("Enter DES key (8 bytes): ").encode()
    des_plaintext = input("Enter plaintext for DES encryption: ")
    
    des_ciphertext = des_encrypt(des_key, des_plaintext)
    print("DES Encrypted:", b64encode(des_ciphertext).decode())
    
    des_encrypted_text = b64decode(input("Enter ciphertext for DES decryption: "))
    des_decrypted_text = des_decrypt(des_key, des_encrypted_text)
    print("DES Decrypted:", des_decrypted_text)
    
    print()
    
    # RSA encryption and decryption
    generate_keys_option = input("Generate new RSA keys? (yes/no): ").strip().lower()
    if generate_keys_option == "yes":
        private_key, public_key = generate_keys()
        print("Public Key:")
        print(public_key.decode())
        print("\nPrivate Key:")
        print(private_key.decode())
    else:
        private_key = input("Enter your RSA private key: ").encode()
        public_key = input("Enter your RSA public key: ").encode()
    
    rsa_plaintext = input("Enter plaintext for RSA encryption: ")
    rsa_ciphertext = rsa_encrypt(public_key, rsa_plaintext)
    print("RSA Encrypted:", rsa_ciphertext)
    
    rsa_encrypted_text = input("Enter ciphertext for RSA decryption: ")
    rsa_decrypted_text = rsa_decrypt(private_key, rsa_encrypted_text)
    print("RSA Decrypted:", rsa_decrypted_text)

if __name__ == "__main__":
    main()
