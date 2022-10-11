from authlib.jose import Key
from cryptography.hazmat.primitives import serialization


def get_public_key_as_pem(key: Key):
    return key.as_pem()


def get_private_key_as_pem(key: Key):
    private_key = key.get_private_key()
    private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PrivateFormat.PKCS8,
                                                  encryption_algorithm=serialization.NoEncryption())
    return private_key_bytes
