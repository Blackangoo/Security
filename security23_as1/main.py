import argparse
from src import asymmetric, symmetric, rsa, salt, pbkdf

# Load a constant salt value used for key derivation
cst_salt = salt.get_salt()

def encrypt_symmetric(args):
    """
    Encrypts or decrypts a file using symmetric key encryption (ECB, CBC, or GCM modes).

    Args:
        args (argparse.Namespace): Parsed command-line arguments.
    """
    if args.operation == 'encrypt':
        key = pbkdf.derive_key_from_password(args.passphrase, cst_salt)
        with open(args.input, 'rb') as file:
            plaintext = file.read()

        if args.mode == 'ecb':
            ciphertext = symmetric.encrypt_ecb(plaintext, key)
            with open(args.output, 'wb') as file:
                file.write(ciphertext)
        elif args.mode == 'cbc':
            iv, ciphertext = symmetric.encrypt_cbc(plaintext, key)
            with open(args.output, 'wb') as file:
                file.write(iv)
                file.write(ciphertext)
        elif args.mode == 'gcm':
            tag, ciphertext = symmetric.encrypt_gcm(plaintext, key, salt.get_nonce())
            with open(args.output, 'wb') as file:
                file.write(tag)
                file.write(ciphertext)
        print("The file was encrypted and saved in", args.output)

    else:
        decrypt_symmetric(args)

def decrypt_symmetric(args):
    """
    Decrypts an encrypted file using symmetric key encryption.

    Args:
        args (argparse.Namespace): Parsed command-line arguments.
    """
    key = pbkdf.derive_key_from_password(args.passphrase, cst_salt)

    if args.mode == 'ecb':
        with open(args.input, 'rb') as file:
            ciphertext = file.read()
        plaintext = symmetric.decrypt_ecb(ciphertext, key)
    elif args.mode == 'cbc':
        with open(args.input, 'rb') as file:
            iv = file.read(16)
            ciphertext = file.read()
        plaintext = symmetric.decrypt_cbc(ciphertext, key, iv)
    elif args.mode == 'gcm':
        with open(args.input, 'rb') as file:
            tag = file.read(16)
            ciphertext = file.read()
        plaintext = symmetric.decrypt_gcm(ciphertext, key, salt.get_nonce(), tag)

    with open(args.output, 'wb') as file:
        file.write(plaintext)

    print("The file was decrypted and saved in", args.output)

def encrypt_asymmetric(args):
    """
    Encrypts a file using asymmetric key encryption.

    Args:
        args (argparse.Namespace): Parsed command-line arguments.
    """
    asymmetric.asymmetric_encryption(args.public_key, args.input, args.output)
    print("The file was encrypted and saved in", args.output)

def decrypt_asymmetric(args):
    """
    Decrypts an encrypted file using asymmetric key encryption.

    Args:
        args (argparse.Namespace): Parsed command-line arguments.
    """
    asymmetric.asymmetric_decryption(args.private_key, args.input, args.output)
    print("The file was decrypted and saved in", args.output)


if __name__ == '__main__':

    #create the top level parser
    parser = argparse.ArgumentParser(description='Assignment 1 - Files encryption')
    subparsers = parser.add_subparsers(required=True, title='Commands', description='Valid Commands', help='type python3 command --help for additional infos')

    #create the parser for the symmetric command
    parser_symmetric = subparsers.add_parser('symmetric')
    parser_symmetric.add_argument('--mode', choices=['ecb', 'cbc', 'gcm'], required=True, help='Encryption mode (ecb, cbc, gcm)')
    parser_symmetric.add_argument('--input', required=True, help='Path/NameOfFile you want to encrypt')
    parser_symmetric.add_argument('--output', required=True, help='Path/NameOfFile you want to decrypt')
    parser_symmetric.add_argument('--operation', choices=['encrypt', 'decrypt'], required=True, help='Operation (encrypt, decrypt)')
    parser_symmetric.add_argument('--passphrase', required=True, help='Passphrase to encrypt and decrypt')
    parser_symmetric.set_defaults(func = encrypt_symmetric)

    #create the parser for the asymmetric encryption command
    parser_asymmetric_encryption = subparsers.add_parser('asymmetric-encryption')
    parser_asymmetric_encryption.add_argument('--public_key', required=True, help='Path/NameOfFile where the public key of the reciever is')
    parser_asymmetric_encryption.add_argument('--input', required=True, help='Path/NameOfFile you want to encrypt')
    parser_asymmetric_encryption.add_argument('--output', required=True, help='Path/NameOfFile of the encrypted file')
    parser_asymmetric_encryption.set_defaults(func = encrypt_asymmetric)

    #create the parser for the asymmetric decryption command
    parser_asymmetric_decryption = subparsers.add_parser('asymmetric-decryption')
    parser_asymmetric_decryption.add_argument('--private_key', required=True, help='Path/NameOfFile where the private key of the reciever is')
    parser_asymmetric_decryption.add_argument('--input', required=True, help='Path/NameOfFile you want to decrypt')
    parser_asymmetric_decryption.add_argument('--output', required=True, help='Path/NameOfFile of the decrypted file ')
    parser_asymmetric_decryption.set_defaults(func = decrypt_asymmetric)

    args = parser.parse_args()
    args.func(args)