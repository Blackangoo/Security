from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

def derive_key_from_password(password, salt):
    keys = PBKDF2(password, salt, 64, count=1000000, hmac_hash_module=SHA512)
    key = keys[:16]  # La clé générée de 32 octets (256 bits)
    return key
