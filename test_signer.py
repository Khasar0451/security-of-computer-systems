import pytest, os

from cryptography.hazmat.primitives import serialization

from signer import encrypt_key, decrypt_key, generate_rsa, create_keys, load_private_key_from_file


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
    file_url = "/tmp/file.cpp"
    key_file_name = "key"
    pin = "123"
    create_keys(path="/tmp", file_name=key_file_name, pin=pin)

    with open(file_url, 'w') as f:
        f.write(" Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed in commodo diam. Mauris placerat sem id"
                " nibh sagittis sodales. Nulla varius sollicitudin ornare. Aenean sed efficitur ex. Proin fermentum"
                " lorem sem, vitae mollis lorem auctor at. Nullam mollis diam vulputate, volutpat leo vitae,"
                " consequat nibh. Sed in enim enim. ")

    private_key = load_private_key_from_file(url=file_url, pin=pin)

    assert os.path.exists(key_file_name + "/" + key_file_name + ".pem")
    assert os.path.exists(key_file_name + "/" + key_file_name + "priv.pem")

    os.remove(file_url)
    os.remove(key_file_name + "/" + key_file_name + ".pem")
    os.remove(key_file_name + "/" + key_file_name + "priv.pem")
