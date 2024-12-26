# src/utils/validator.py
import ipaddress
import re

class InputValidator:
    @staticmethod
    def validate_ip(ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_port_range(port_range: str) -> bool:
        pattern = r'^\d+(-\d+)?$'
        if not re.match(pattern, port_range):
            return False
        
        parts = port_range.split('-')
        start_port = int(parts[0])
        end_port = int(parts[-1])
        
        return 0 <= start_port <= end_port <= 65535