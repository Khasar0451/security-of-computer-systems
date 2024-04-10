import pytest

from cryptography.hazmat.primitives import serialization

from signer import encrypt_key, decrypt_key, generate_rsa


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
