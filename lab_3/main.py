# -*- coding: utf-8 -*-
"""
Name: CryptographyTask
Version: 0.1
Date: 10.05.2026
"""

import os
import modules.logger as logger
import modules.env_parser as env_parser
import cryptography

log = logger.app_logger

if __name__ == '__main__':   
    log.info("App start")
    cfg = env_parser.get_settings()
    
    while True:
        print("\n1. Key Gen | 2. Encrypt | 3. Decrypt | 0. Exit")
        choise = input(">_< ")
        if choise == '1': pass
        elif choise == '2': pass
        elif choise == '3': pass
        elif choise == '0': break
        else:
            print("Wrong arg")
