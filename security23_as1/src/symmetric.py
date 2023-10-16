from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt_ecb(data, key):
    """
    Encrypts data using the Electronic Codebook (ECB) mode of AES encryption.

    Args:
        data (bytes): The data to be encrypted.
        key (bytes): The cryptographic key used for encryption.

    Returns:
        bytes: The ciphertext resulting from the AES-ECB encryption.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    cipher_text = cipher.encrypt(padded_data)
    return cipher_text

def decrypt_ecb(ciphertext, key):
    """
    Decrypts data using the Electronic Codebook (ECB) mode of AES encryption.

    Args:
        ciphertext (bytes): The data to be decrypted.
        key (bytes): The cryptographic key used for encryption.

    Returns:
        bytes: The plaintext resulting from the AES-ECB decryption.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, AES.block_size)

def encrypt_cbc(data, key):
    """
    Encrypts data using the Ciphertext Block Chaining (CBC) mode of AES encryption.

    Args:
        data (bytes): The data to be encrypted.
        key (bytes): The cryptographic key used for encryption.

    Returns:
        tuple: A tuple containing the Initialization Vector iv (bytes), The ciphertext resulting from the AES-ECB encryption (bytes).
    """
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(data, AES.block_size)
    cipher_text = cipher.encrypt(padded_data)
    return (iv, cipher_text)

def decrypt_cbc(ciphertext, key, iv):
    """
    Decrypts data using the Ciphertext Block Chaining (CBC) mode of AES encryption.

    Args:
        ciphertext (bytes): The data to be decrypted.
        key (bytes): The cryptographic key used for encryption.
        iv (bytes): The Initialization Vector used for encryption.

    Returns:
        bytes: The cplaintext resulting from the AES-ECB decryption.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, AES.block_size)

def encrypt_gcm(data, key, nonce):
    """
    Encrypts data using the Galois/Counter Mode (GCM) of AES encryption.

    Args:
        data (bytes): The data to be encrypted.
        key (bytes): The cryptographic key used for encryption.
        nonce (bytes): The nonce for the encryption.

    Returns:
        tuple: A tuple containing the ciphertext (bytes) and the authentication tag (bytes).
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher_text, tag = cipher.encrypt_and_digest(data)
    return (tag, cipher_text)

def decrypt_gcm(data, key, nonce, tag):
    """
    Decrypts data encrypted using the Galois/Counter Mode (GCM) of AES encryption.

    Args:
        ciphertext (bytes): The data to be decrypted.
        key (bytes): The cryptographic key used for decryption.
        nonce (bytes): The nonce used during encryption.
        tag (bytes): The authentication tag received during encryption.

    Returns:
        bytes: The plaintext resulting from the AES-GCM decryption, or raises an exception if the data is not authentic.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(data, tag)
    return (decrypted_data)
