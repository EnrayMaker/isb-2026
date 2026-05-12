# -*- coding: utf-8 -*-
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from modules.logger import app_logger as log
from modules.file_manager import write_file

def run_gen_keys(sym_key_path: str, pub_key_path: str, priv_key_path: str, key_size_bits: int):
    """
    Key Generation
    """
    try:
        sym_key = os.urandom(key_size_bits // 8)
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        write_file(priv_key_path, private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
        write_file(pub_key_path, public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        enc_sym_key = public_key.encrypt(
            sym_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        write_file(sym_key_path, enc_sym_key)

        log.info("Keys successfully generated and serialized.")
    except Exception as e:
        log.error(f"Generation error: {e}")
