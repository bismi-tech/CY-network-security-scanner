# src/utils/logger.py
import logging
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class ScanLogger:
    def __init__(self):
        self.logger = logging.getLogger('SecurityScanner')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        fh = logging.FileHandler(f'scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        fh.setLevel(logging.INFO)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatting
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def info(self, message):
        self.logger.info(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

    def warning(self, message):
        self.logger.warning(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")

    def error(self, message):
        self.logger.error(f"{Fore.RED}{message}{Style.RESET_ALL}")