from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def aes_encrypt(plaintext, key):
    # Generowanie wektora inicjalizacyjnego (IV) dla trybu ECB
    # W trybie ECB, IV jest nieużywany, ale AES wymaga podania losowego IV, nawet w tym trybie.
    iv = os.urandom(16)  # AES blok ma 16 bajtów

    # Tworzenie obiektu Cipher
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    # Dodawanie paddingu (AES wymaga bloków o rozmiarze 16 bajtów)
    padder = padding.PKCS7(128).padder()  # 128 to długość bloku w bitach
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Szyfrowanie danych
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext, iv

def aes_decrypt(ciphertext, key):
    # Tworzenie obiektu Cipher
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    # Deszyfrowanie danych
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Usuwanie paddingu
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode()

def main():
    # Klucz AES (musimy go ustawić na 16, 24 lub 32 bajty - 128, 192 lub 256 bitów)
    key = os.urandom(16)  # Losowy klucz 16-bajtowy (128-bitowy AES)

    # Wprowadzenie tekstu przez użytkownika
    plaintext = input("Enter your string to encrypt:")

    print("\nOriginal Text: ", plaintext)

    # Szyfrowanie
    ciphertext, iv = aes_encrypt(plaintext, key)
    print("\n-- Encryption --\n", ciphertext.hex())

    # Deszyfrowanie
    decrypted_text = aes_decrypt(ciphertext, key)
    print("\n-- Decryption --\n", decrypted_text)

if __name__ == "__main__":
    main()
