# -*- coding: utf-8 -*-
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from modules.logger import app_logger as log

def run_gen_keys(sym_key_path: str, pub_key_path: str, priv_key_path: str, key_size_bits: int):
    """
    Generates a hybrid key system.
    1. Generates a CAST5 symmetric key.
    2. Generates an RSA key pair.
    3. Serializes RSA keys to PEM files.
    4. Encrypts the CAST5 key with the RSA Public Key and saves it.
    """
    try:
        sym_key = os.urandom(key_size_bits // 8)
        log.info(f"Symmetric key (CAST5) generated. Size: {key_size_bits} bits.")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        log.info("Asymmetric RSA-2048 key pair generated.")

        with open(priv_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        log.info(f"Public key successfully serialized to: {pub_key_path}")

        with open(pub_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        log.info(f"Private key successfully serialized to: {priv_key_path}")

        encrypted_sym_key = public_key.encrypt(
            sym_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        with open(sym_key_path, "wb") as f:
            f.write(encrypted_sym_key)
        log.info(f"Encrypted symmetric key saved to: {sym_key_path}")

        log.info(f"Keys successfully generated and saved")
    except Exception as e:
        log.error(f"Error in key generation: {e}")
