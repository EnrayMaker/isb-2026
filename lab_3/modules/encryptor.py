# -*- coding: utf-8 -*-
import os
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from modules.logger import app_logger as log

def run_encryption(source_path: str, priv_key_path: str, enc_sym_key_path: str, output_path: str):
    """
    Encryption
    1. Decrypt symmetric key with Private Key.
    2. Pad data using ANSIX923 (block size 64 bits for CAST5).
    3. Encrypt data with CAST5 in CBC mode.
    """
    try:
        with open(priv_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        with open(enc_sym_key_path, "rb") as f:
            enc_sym_key_data = f.read()
        
        sym_key = private_key.decrypt(
            enc_sym_key_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(source_path, "rb") as f:
            data = f.read()

        padder = sym_padding.ANSIX923(64).padder()
        padded_data = padder.update(data) + padder.finalize()

        iv = os.urandom(8)
        cipher = Cipher(algorithms.CAST5(sym_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        c_text = encryptor.update(padded_data) + encryptor.finalize()

        with open(output_path, "wb") as f:
            f.write(iv + c_text)

        log.info(f"File encrypted successfully: {output_path}")
    except Exception as e:
        log.error(f"Encryption error: {e}")
