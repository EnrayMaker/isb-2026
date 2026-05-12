# -*- coding: utf-8 -*-
import os
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from modules.logger import app_logger as log
from modules.file_manager import read_file, write_file, load_private_key

def run_encryption(source_path: str, priv_key_path: str, enc_sym_key_path: str, output_path: str):
    """
    Scenario 2: Encryption
    """
    try:
        # Use centralized file management
        private_key = load_private_key(priv_key_path)
        enc_sym_key_data = read_file(enc_sym_key_path)
        data = read_file(source_path)

        # 2.1 Decrypt symmetric key
        sym_key = private_key.decrypt(
            enc_sym_key_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 2.2 Padding and CAST5 Encryption
        padder = sym_padding.ANSIX923(64).padder()
        padded_data = padder.update(data) + padder.finalize()

        iv = os.urandom(8)
        cipher = Cipher(algorithms.CAST5(sym_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        c_text = encryptor.update(padded_data) + encryptor.finalize()

        # Save result
        write_file(output_path, iv + c_text)
        log.info(f"File encrypted successfully: {output_path}")

    except Exception as e:
        log.error(f"Encryption error: {e}")
