from Crypto.Random import get_random_bytes
from src import symmetric

def convert_key(key):
    """
    Converts a key string in the format '(a, b)' into a tuple of integers (a, b).

    Args:
        key (str): The key string in the format '(a, b)'.

    Returns:
        tuple: A tuple containing two integers a and b extracted from the string.
    """
    # Remove parentheses and spaces from the 'key' parameter
    key = key.strip('()').replace(' ', '')
    # Split the string into two parts using ',' as the separator
    a_str, b_str = key.split(',')
    a = int(a_str)
    b = int(b_str)
    return a, b

def encrypt_rsa(plaintext, public_key_file):
    """
    Encrypts the plaintext using textbook RSA.

    Args:
        plaintext (bytes): The plaintext to be encrypted.
        public_key_file (str): The path to the public key file.

    Returns:
        bytes: The ciphertext resulting from the RSA encryption.
    """
    # Open and read the public key from the provided file
    with open(public_key_file, "r") as public:
        public_key_str = public.read()
        public_key = convert_key(public_key_str)

    # Extract the public key components (e, n)
    e, n = public_key

    # Convert the plaintext into an integer
    plaintext_int = int.from_bytes(plaintext, byteorder='big')

    # Encrypt the plaintext using RSA encryption
    ciphertext_int = pow(plaintext_int, e, n)

    # Convert the ciphertext back to bytes
    ciphertext = ciphertext_int.to_bytes((ciphertext_int.bit_length() + 7) // 8, byteorder='big')

    return ciphertext

def decrypt_rsa(ciphertext, private_key_file):
    """
    Decrypts the ciphertext using textbook RSA.

    Args:
        ciphertext (bytes): The ciphertext to be decrypted.
        private_key_file (str): The path to the private key file.

    Returns:
        bytes: The plaintext resulting from the RSA decryption.
    """
    # Open and read the public key from the provided file
    with open(private_key_file, "r") as private:
        private_key_str = private.read()
        private_key =  convert_key(private_key_str)

    # Extract the private key components (d, n)
    d, n = private_key

    # Convert the ciphertext into an integer
    ciphertext_int = int.from_bytes(ciphertext, byteorder='big')

    # Decrypt the ciphertext using RSA decryption
    plaintext_int = pow(ciphertext_int, d, n)

    # Convert the plaintext back to bytes
    plaintext = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, byteorder='big')

    return plaintext

def asymmetric_encryption(public_key_file, input_file, output_file):
    """
    Encrypts the body of the given file with a symmetric key and encrypts this key with RSA.
    
    Args:
        public_key_file (str): The path to the recipient's public key file.
        input_file (str): The path to the input file to be encrypted.
        output_file (str): The path to the output file where the encrypted data will be saved.
    """
    # Generate a random symmetric key and nonce
    symmetric_key = get_random_bytes(16)
    nonce = get_random_bytes(12)

    # Read the plaintext data from the input file
    with open(input_file, 'rb') as file:
        plaintext = file.read()

    # Encrypt the plaintext using symmetric encryption
    tag, ciphertext = symmetric.encrypt_gcm(plaintext, symmetric_key, nonce)

    # Encrypt the symmetric key with the recipient's public key
    encrypted_symmetric_key = encrypt_rsa(symmetric_key, public_key_file)

    # Write the tag, nonce, encrypted symmetric key, and ciphertext to the output file
    with open(output_file, 'wb') as file:
        file.write(tag)
        file.write(nonce)
        file.write(encrypted_symmetric_key)
        file.write(ciphertext)

def asymmetric_decryption(private_key_file, input_file, output_file):
    """
    Decrypts the symmetric key with the RSA key and decrypts the body of the given file.
    
    Args:
        private_key_file (str): The path to the recipient's private key file.
        input_file (str): The path to the input file to be decrypted.
        output_file (str): The path to the output file where the decrypted data will be saved.
    """
    # Read tag, nonce, encrypted symmetric key, and ciphertext from the input file
    with open(input_file, 'rb') as file:
        tag = file.read(16)
        nonce = file.read(12)
        encrypted_symmetric_key = file.read(375) # 375 * 8 = 3000
        ciphertext = file.read()
    
    # Decrypt the symmetric key with the recipient's private key
    symmetric_key = decrypt_rsa(encrypted_symmetric_key, private_key_file)

    # Decrypt the ciphertext using symmetric encryption
    plaintext = symmetric.decrypt_gcm(ciphertext, symmetric_key, nonce, tag)

    # Write the plaintext data to the output file
    with open(output_file, 'wb') as file:
        file.write(plaintext)
