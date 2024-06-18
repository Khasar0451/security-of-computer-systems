import pytest, os


from signer import *


def test_save_load_keys():
    path = "/tmp"
    key_file_name = "key"
    private_key_path = path + "/" + key_file_name + "priv.pem"
    public_key_path = path + "/" + key_file_name + ".pem"
    pin = "1"
    private_key = generate_rsa()
    save_keys(path=path, file_name=key_file_name,private_key=private_key , pin=pin)

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


def test_sign_verify():
    key = generate_rsa()
    lorem_string = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed in commodo diam. Mauris placerat sem "
                    "id")
    " nibh sagittis sodales. Nulla varius sollicitudin ornare. Aenean sed efficitur ex. Proin fermentum"
    " lorem sem, vitae mollis lorem auctor at. Nullam mollis diam vulputate, volutpat leo vitae,"
    " consequat nibh. Sed in enim enim. "

    signature = sign_data(lorem_string.encode(), key)
    assert verify_signature(lorem_string.encode(), key.public_key(), signature)


def test_encrypt_decrypt():
    key = generate_rsa()
    lorem_string = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed in commodo diam. Mauris placerat sem "
                    "id")
    " nibh sagittis sodales. Nulla varius sollicitudin ornare. Aenean sed efficitur ex. Proin fermentum"
    " lorem sem, vitae mollis lorem auctor at. Nullam mollis diam vulputate, volutpat leo vitae,"
    " consequat nibh. Sed in enim enim. "
    encrypted = encrypt_data(lorem_string.encode(), key.public_key())

    decrypted = decrypt_data(encrypted, key)

    assert decrypted == lorem_string.encode()



def test_xml_verify():
    file = "/tmp/file.cpp"
    xml = "/tmp/signature.xml"
    with open(file, "w") as f:
        f.write("abc")

    key = generate_rsa()

    hash = create_xml(file, key)
    with open(file,"rb") as f:
        assert verify_signature(f.read(), key.public_key(), hash)

    assert verify_xml(xml, key.public_key(), file)

    os.remove(file)
    os.remove(xml)

