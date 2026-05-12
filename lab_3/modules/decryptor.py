# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from modules.logger import app_logger as log
from modules.file_manager import read_file, write_file, load_private_key

def run_decryption(enc_file_path: str, priv_key_path: str, enc_sym_key_path: str, output_path: str):
    """
    Scenario 3: Data Decryption.
    Performs hybrid decryption: recovers the session key via RSA private key, 
    decrypts the ciphertext using CAST5, and removes the ANSIX923 padding.
    Args:
        enc_file_path (str): Path to the encrypted data file.
        priv_key_path (str): Path to the RSA private key.
        enc_sym_key_path (str): Path to the encrypted CAST5 key.
        output_path (str): Path to save the restored plaintext file.    
    """
    try:
        private_key = load_private_key(priv_key_path)
        enc_sym_key_data = read_file(enc_sym_key_path)
        raw_data = read_file(enc_file_path)

        sym_key = private_key.decrypt(
            enc_sym_key_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        iv = raw_data[:8]
        c_text = raw_data[8:]

        cipher = Cipher(algorithms.CAST5(sym_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        dc_text = decryptor.update(c_text) + decryptor.finalize()

        unpadder = sym_padding.ANSIX923(64).unpadder()
        unpadded_data = unpadder.update(dc_text) + unpadder.finalize()

        write_file(output_path, unpadded_data)
        log.info(f"File decrypted successfully: {output_path}")

    except Exception as e:
        log.error(f"Decryption error: {e}")
