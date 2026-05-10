# -*- coding: utf-8 -*-
import os
from dotenv import load_dotenv

load_dotenv()

def get_settings():
    """Return settings from .env"""
    return {
        "sym_key": os.getenv("SYM_KEY_PATH", "sym_key.enc"),
        "pub_key": os.getenv("PUB_KEY_PATH", "public_key.pem"),
        "priv_key": os.getenv("PRIV_KEY_PATH", "private_key.pem"),
        "source": os.getenv("SOURCE_FILE", "input.txt"),
        "encrypted": os.getenv("ENCRYPTED_FILE", "output.enc"),
        "decrypted": os.getenv("DECRYPTED_FILE", "output.txt"),
        "key_size": int(os.getenv("CAST5_KEY_SIZE", 128))
    }
