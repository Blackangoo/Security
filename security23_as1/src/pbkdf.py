from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

def derive_key_from_password(password, salt):
    """
    Derives a cryptographic key from a password using PBKDF2 (Password-Based Key Derivation Function).

    Args:
        password (str or bytes): The secret password from which to generate the key.
        salt (str or bytes): A random or unique string or bytes to enhance protection against dictionary attacks.

    Returns:
        bytes: A derived key with a length of 16 bytes
    """
    keys = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA512)
    key = keys[:16]  # La clé générée de 32 octets (256 bits)
    return key
