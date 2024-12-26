# src/scanner.py
import nmap
from scapy.all import *
from utils.validator import InputValidator
from utils.logger import ScanLogger

class SecurityScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.logger = ScanLogger()
        self.validator = InputValidator()

    def scan_ports(self, target_ip: str, port_range: str = "1-1024") -> dict:
        """
        Scan specified ports on target IP address
        """
        if not self.validator.validate_ip(target_ip):
            self.logger.error(f"Invalid IP address: {target_ip}")
            return {}

        if not self.validator.validate_port_range(port_range):
            self.logger.error(f"Invalid port range: {port_range}")
            return {}

        try:
            self.logger.info(f"Starting scan on {target_ip} for ports {port_range}")
            self.scanner.scan(target_ip, port_range)
            
            results = {}
            for host in self.scanner.all_hosts():
                results[host] = {}
                for proto in self.scanner[host].all_protocols():
                    ports = self.scanner[host][proto].keys()
                    for port in ports:
                        state = self.scanner[host][proto][port]['state']
                        service = self.scanner[host][proto][port]['name']
                        results[host][port] = {
                            'state': state,
                            'service': service
                        }
            
            return results

        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            return {}

    def detect_os(self, target_ip: str) -> str:
        """
        Attempt to detect OS of target system
        """
        try:
            self.scanner.scan(target_ip, arguments="-O")
            if 'osmatch' in self.scanner[target_ip]:
                return self.scanner[target_ip]['osmatch'][0]['name']
        except Exception as e:
            self.logger.error(f"OS detection failed: {str(e)}")
        return "Unknown"

def main():
    scanner = SecurityScanner()
    target = input("Enter target IP address: ")
    ports = input("Enter port range (e.g., 1-100): ")
    
    results = scanner.scan_ports(target, ports)
    
    for host, ports in results.items():
        print(f"\nResults for {host}:")
        os_guess = scanner.detect_os(host)
        print(f"Detected OS: {os_guess}")
        
        for port, info in ports.items():
            print(f"Port {port}: {info['state']} ({info['service']})")

if __name__ == "__main__":
    main()