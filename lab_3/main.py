# -*- coding: utf-8 -*-
"""
Name: CryptographyTask
Version: 0.1
Date: 10.05.2026
"""

import modules.logger as logger
import modules.env_parser as env_parser
import modules.generator as generator
import modules.encryptor as encryptor
import modules.decryptor as decryptor

log = logger.app_logger


if __name__ == '__main__':   
    log.info("App start")
    cfg = env_parser.get_settings()
    
    while True:
        print("\n--- Hybrid System Menu ---")
        print("\n1. Key Gen | 2. Encrypt | 3. Decrypt | 0. Exit")
        choice = input(">_< ")

        match choice:
            case '1':
                generator.run_gen_keys(
                    cfg['sym_key'], cfg['pub_key'], cfg['priv_key'], cfg['key_size']
                )
            case '2':
                encryptor.run_encryption(
                    cfg['source'], cfg['priv_key'], cfg['sym_key'], cfg['encrypted']
                )
            case '3':
                decryptor.run_decryption(
                    cfg['encrypted'], cfg['priv_key'], cfg['sym_key'], cfg['decrypted']
                )
            case '0':
                log.info("Shutting down...")
                break
            case _:
                print("Wrong arg")
