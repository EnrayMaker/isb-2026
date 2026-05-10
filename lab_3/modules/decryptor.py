# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from modules.logger import app_logger as log

def run_decryption(enc_file_path: str, priv_key_path: str, enc_sym_key_path: str, output_path: str):
    """
    Decryption
    1. Decrypt symmetric key with Private Key.
    2. Decrypt ciphertext with CAST5.
    3. Remove ANSIX923 padding.
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

        with open(enc_file_path, "rb") as f:
            raw_data = f.read()
            iv = raw_data[:8]
            c_text = raw_data[8:]

        cipher = Cipher(algorithms.CAST5(sym_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        dc_text = decryptor.update(c_text) + decryptor.finalize()

        unpadder = sym_padding.ANSIX923(64).unpadder()
        unpadded_data = unpadder.update(dc_text) + unpadder.finalize()

        with open(output_path, "wb") as f:
            f.write(unpadded_data)

        log.info(f"File decrypted successfully: {output_path}")
    except Exception as e:
        log.error(f"Decryption error: {e}")
