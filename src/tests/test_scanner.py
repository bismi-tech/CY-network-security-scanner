# src/tests/test_scanner.py
import pytest
from src.utils.validator import InputValidator
from src.scanner import SecurityScanner

def test_ip_validator():
    validator = InputValidator()
    assert validator.validate_ip("192.168.1.1") == True
    assert validator.validate_ip("256.256.256.256") == False
    assert validator.validate_ip("invalid_ip") == False

def test_port_range_validator():
    validator = InputValidator()
    assert validator.validate_port_range("1-100") == True
    assert validator.validate_port_range("80") == True
    assert validator.validate_port_range("0-65536") == False
    assert validator.validate_port_range("invalid") == False

def test_scanner_initialization():
    scanner = SecurityScanner()
    assert scanner is not None