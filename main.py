from AES import aes_menu
from DES import des_menu
from RSA import rsa_menu

def main_menu():
    while True:
        algorithm = input("\nChoose algorithm (AES/DES/RSA/quit): ").strip().upper()
        if algorithm == "QUIT":
            break
        elif algorithm == "AES":
            aes_menu()
        elif algorithm == "DES":
            des_menu()
        elif algorithm == "RSA":
            rsa_menu()
        else:
            print("Invalid algorithm")

if __name__ == "__main__":
    main_menu()
