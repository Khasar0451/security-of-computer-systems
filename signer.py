import base64
import datetime
import hashlib
import cryptography.hazmat
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import xml.etree.ElementTree as ET
import os
import time


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


def decrypt_data(data: bytes, private_key):
    return private_key.decrypt(data, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))


def verify_signature(data: bytes, public_key, signature: bytes):  # data - signed file, signature - hash from xml
    try:
        public_key.verify(signature, data, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def create_xml(path_with_file_name, private_key):
    root = ET.Element('root')
    size = ET.SubElement(root, "size")
    size.text = str(os.stat(path_with_file_name).st_size)

    extension = ET.SubElement(root, "extension")
    _, extension.text = os.path.splitext(path_with_file_name)
    path_without = "/".join(path_with_file_name.split('/')[:-1])
    date_of_modification = ET.SubElement(root, "date_of_modification")
    date_of_modification.text = time.ctime(os.path.getmtime(path_with_file_name))  # m in getmtime as modified

    user_name = ET.SubElement(root, "user_name")
    user_name.text = "User A"

    encrypted_hash = ET.SubElement(root, "encrypted_hash")
    with open(path_with_file_name, "rb") as file:
        hash_bytes = sign_data(file.read(), private_key)
        string_hash_bytes = base64.b64encode(hash_bytes).decode("utf-8")
        encrypted_hash.text = string_hash_bytes

    signature_timestamp = ET.SubElement(root, "signature_timestamp")
    signature_timestamp.text = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

    tree = ET.ElementTree(root)
    tree.write(path_without + '/signature.xml')
    pass
    return hash_bytes


def verify_xml(path_xml, public_key, path_file):
    tree = ET.parse(path_xml)
    root = tree.getroot()
    read_hash = root.find('encrypted_hash').text
    hash = base64.b64decode(read_hash.encode('utf-8'))
    with open(path_file, "rb") as file:
        return verify_signature(file.read(), public_key, hash)


def generate_rsa():
    return cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )


def sign_data(data, private_key):
    return private_key.sign(data, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
    ), hashes.SHA256())


def save_keys(path, file_name, private_key, pin):
    with open(path + "/" + file_name + ".pem", 'wb') as f:
        f.write(private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(path + "/" + file_name + "priv.pem", 'wb') as f:
        f.write(private_key.private_bytes(serialization.Encoding.PEM,
                                          format=serialization.PrivateFormat.TraditionalOpenSSL,
                                          encryption_algorithm=serialization.
                                          BestAvailableEncryption(password=pin.encode())))
