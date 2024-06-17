import datetime
import hashlib
import cryptography.hazmat
import xmlsig
from endesive import plain
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import xml.etree.ElementTree as ET
import os


def create_xml(path_with_file_name):
    root = ET.Element('root')
    size = ET.SubElement(root, "size")
    size.text = os.stat(path_with_file_name).st_size

    extension = ET.SubElement(root,"extension")
    _, extension.text = os.path.splitext(path_with_file_name)

    date_of_modification = ET.SubElement(root,"date_of_modification")
    date_of_modification.text = os.path.getmtime(path_with_file_name) #m in getmtime as modified

    user_name = ET.SubElement(root,"user_name")
    user_name.text = "User A"

    encrypted_hash = ET.SubElement(root, "encrypted_hash")
    encrypted_hash.text = "TutajHash"

    signature_timestamp = ET.SubElement(root, "signature_timestamp")
    signature_timestamp.text = datetime.datetime.now()

    tree = ET.ElementTree(root)
    tree.write('a.xml')

create_xml("R:\.Programowanie\info.txt")

def generate_rsa():
    return cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )


def encrypt_key(key, pin):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password=pin.encode())
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
    with open(path + "/" + file_name + ".pem", 'wb') as f:
        f.write(private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(path + "/" + file_name + "priv.pem", 'wb') as f:
        f.write(encrypt_key(private_key, pin))


def load_private_key_from_file(url, pin):
    with open(url, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=(pin)
        )
    return private_key