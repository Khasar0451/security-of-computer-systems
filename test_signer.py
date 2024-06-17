import pytest, os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from signer import encrypt_key, decrypt_key, generate_rsa, create_keys, load_private_key_from_file, \
    load_public_key_from_file


def test_encrypt_decrypt_key():
    key = generate_rsa()
    pin = "123"

    encrypted_key = encrypt_key(key, pin)
    decrypted_key = decrypt_key(encrypted_key, pin)

    with pytest.raises(ValueError) as exc_info:
        decrypt_key(encrypted_key, "1")
    assert str(exc_info.value) == "Bad decrypt. Incorrect password?"

    assert (decrypted_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.PKCS8,
                                        encryption_algorithm=serialization.NoEncryption()) ==
            key.private_bytes(encoding=serialization.Encoding.PEM,
                              format=serialization.PrivateFormat.PKCS8,
                              encryption_algorithm=serialization.NoEncryption())
            )


def test_save_load_keys():
    path = "/tmp"
    key_file_name = "key"
    private_key_path = path + "/" + key_file_name + "priv.pem"
    public_key_path = path + "/" + key_file_name + ".pem"
    pin = "1"
    create_keys(path=path, file_name=key_file_name, pin=pin)

    lorem_string = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed in commodo diam. Mauris placerat sem "
                    "id")
    " nibh sagittis sodales. Nulla varius sollicitudin ornare. Aenean sed efficitur ex. Proin fermentum"
    " lorem sem, vitae mollis lorem auctor at. Nullam mollis diam vulputate, volutpat leo vitae,"
    " consequat nibh. Sed in enim enim. "

    public_key = load_public_key_from_file(public_key_path)
    private_key = load_private_key_from_file(url=private_key_path, pin=pin)

    encrypted_string = public_key.encrypt(lorem_string.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

    assert lorem_string.encode() == private_key.decrypt(encrypted_string, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

    os.remove(private_key_path)
    os.remove(public_key_path)


