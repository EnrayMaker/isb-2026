# -*- coding: utf-8 -*-
"""
Name: CryptographyTask
Version: 0.1
Date: 10.05.2026
"""

import modules.logger as logger
from dotenv import load_dotenv
import os
import cryptography


if __name__ == '__main__':
    log = logger.app_logger
    log.info("App start")
    load_dotenv()
