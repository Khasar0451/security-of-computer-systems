import cryptography.hazmat
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def generate_rsa():
    return cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )


def sign_data(data, private_key):
    return private_key.sign(data.encode(), padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
    ), hashes.SHA256())


def verify_signature(data, public_key, signature):
    try:
        public_key.verify(signature, data.encode(), padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def save_keys(path, file_name, private_key, pin):
    with open(path + "/" + file_name + ".pem", 'wb') as f:
        f.write(private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(path + "/" + file_name + "priv.pem", 'wb') as f:
        f.write(private_key.private_bytes(serialization.Encoding.PEM,
                                          format=serialization.PrivateFormat.TraditionalOpenSSL,
                                          encryption_algorithm=serialization.
                                          BestAvailableEncryption(password=pin.encode())))

def load_private_key_from_file(url, pin):
    with open(url, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=pin.encode()
        )
    return private_key


def load_public_key_from_file(url):
    with open(url, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def encrypt_data(data, public_key):
    return public_key.encrypt(data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

def decrypt_data(data : bytes, private_key):
    return private_key.decrypt(data, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
