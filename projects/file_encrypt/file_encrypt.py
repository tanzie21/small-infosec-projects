from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import argparse
import os

def encrypt_file(input_file, output_file, key):

    with open(input_file, 'rb') as f:
        plaintext = f.read()


    if not key:
        key = get_random_bytes(16)


    cipher = AES.new(key, AES.MODE_CBC)


    padded_plaintext = pad(plaintext, AES.block_size)


    ciphertext = cipher.encrypt(padded_plaintext)


    with open(output_file, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)

    print("Encryption complete. Encrypted file saved as", output_file)
    print("Encryption key:", key.hex())

def decrypt_file(input_file, output_file, key):

    with open(input_file, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()


    cipher = AES.new(key, AES.MODE_CBC, iv)


    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    
    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print("Decryption complete. Decrypted file saved as", output_file)

def main():
    parser = argparse.ArgumentParser(description='File Encryption Tool')
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Action to perform (encrypt or decrypt)')
    parser.add_argument('input_file', type=str, help='Input file path')
    parser.add_argument('output_file', type=str, help='Output file path')
    parser.add_argument('--key', type=str, help='Encryption key (required for decryption)')

    args = parser.parse_args()

    if args.action == 'encrypt':
        encrypt_file(args.input_file, args.output_file, args.key)
    elif args.action == 'decrypt':
        if not args.key:
            print("Error: Encryption key is required for decryption.")
            return
        decrypt_file(args.input_file, args.output_file, bytes.fromhex(args.key))

if __name__ == "__main__":
    main()