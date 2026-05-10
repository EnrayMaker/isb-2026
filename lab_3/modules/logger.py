# -*- coding: utf-8 -*-
import logging
import sys

def setup_logger(name: str = "CryptographyTask", level: str = "INFO") -> logging.Logger:
    """
    Setup logger for CryptographyTask
    Args:
        name: Task logger
        level: (DEBUG, INFO, WARNING, ERROR)
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))

    formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger

app_logger = setup_logger()
