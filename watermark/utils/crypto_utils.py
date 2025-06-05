# watermark/utils/crypto_utils.py

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """
    Chiffre les octets `data` en AES-CBC avec la clé `key` (32 octets).
    Retourne iv + ciphertext (bytes).
    """
    # 1) Génération d’un IV de 16 octets
    iv = os.urandom(16)

    # 2) Padding PKCS7 pour que la longueur du buffer soit multiple de 16
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # 3) Création du cipher AES-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # 4) Chiffrement
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # 5) On concatène IV || ciphertext pour le renvoyer
    return iv + ciphertext


def decrypt_bytes(iv_and_cipher: bytes, key: bytes) -> bytes:
    """
    Déchiffre le buffer `iv_and_cipher` (qui contient IV + ciphertext),
    et retourne les octets d’origine (sans padding).
    """
    # 1) Séparer IV (16 octets) et ciphertext
    iv = iv_and_cipher[:16]
    ciphertext = iv_and_cipher[16:]

    # 2) Recréation du cipher AES-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    # 3) Déchiffrement du ciphertext -> padded_data
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # 4) Suppression du padding PKCS7
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data
