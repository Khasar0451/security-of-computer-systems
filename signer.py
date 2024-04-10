import hashlib
import cryptography.hazmat
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def generate_rsa():
    return cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )


def encrypt_key(key, pin):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(pin.encode())
    )


def decrypt_key(key, pin):
    return serialization.load_pem_private_key(
        key,
        password=pin.encode()
    )


def sign_data(data, private_key):
    return private_key.sign(data.encode(), padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
    ), hashes.SHA256())


def verify_signature(data, private_key, signature):
    try:
        private_key.verify(signature, data, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def create_keys(path, file_name, pin):
    private_key = generate_rsa()
    with open(path + file_name + ".pem", 'w') as f:
        f.write(private_key.public_bytes())
    with open(path + file_name + "priv.pem", 'w') as f:
        f.write(encrypt_key(private_key, pin))


def load_private_key_from_file(filename, pin):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=pin
        )
    return private_key
