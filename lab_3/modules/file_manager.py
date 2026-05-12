# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives import serialization
from modules.logger import app_logger as log

def read_file(file_path: str) -> bytes:
    """Read raw binary data from a file."""
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        log.error(f"File not found: {file_path}")
        raise
    except Exception as e:
        log.error(f"Error reading {file_path}: {e}")
        raise

def write_file(file_path: str, data: bytes):
    """Write binary data to a file."""
    try:
        with open(file_path, 'wb') as f:
            f.write(data)
    except Exception as e:
        log.error(f"Error writing to {file_path}: {e}")
        raise

def load_private_key(path: str):
    """Load and deserialize RSA private key from PEM."""
    data = read_file(path)
    return serialization.load_pem_private_key(data, password=None)

def load_public_key(path: str):
    """Load and deserialize RSA public key from PEM."""
    data = read_file(path)
    return serialization.load_pem_public_key(data)
