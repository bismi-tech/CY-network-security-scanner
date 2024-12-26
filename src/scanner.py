# src/scanner.py
import nmap3
import json
from datetime import datetime
from utils.validator import InputValidator
from utils.logger import ScanLogger

class SecurityScanner:
    def __init__(self):
        self.scanner = nmap3.Nmap()
        self.logger = ScanLogger()
        self.validator = InputValidator()

    def scan_ports(self, target_ip: str, port_range: str = "1-1024") -> dict:
        if not self.validator.validate_ip(target_ip):
            self.logger.error(f"Invalid IP address: {target_ip}")
            return {}

        try:
            self.logger.info(f"Starting scan on {target_ip}")
            # Basic scan without requiring root privileges
            scan_arguments = " ".join([
                "-sV",                     # Version detection
                "-sT",                     # TCP connect scan (doesn't require root)
                "-Pn",                     # Skip host discovery
                "--script safe"            # Only run safe scripts
            ])
            
            results = self.scanner.nmap_version_detection(target_ip, args=scan_arguments)
            return self.process_scan_results(results)

        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            return {}

    def process_scan_results(self, results: dict) -> dict:
        processed_results = {}
        
        for host in results:
            if host not in ['runtime', 'stats', 'task_results']:
                processed_results[host] = {
                    'ports': {},
                    'services': []
                }
                
                if 'ports' in results[host]:
                    for port_info in results[host]['ports']:
                        port = port_info['portid']
                        service_info = port_info.get('service', {})
                        
                        processed_results[host]['ports'][port] = {
                            'state': port_info.get('state', 'unknown'),
                            'service': service_info.get('name', 'unknown'),
                            'version': service_info.get('version', ''),
                            'product': service_info.get('product', '')
                        }
                        
                        if service_info.get('name'):
                            processed_results[host]['services'].append(service_info.get('name'))

        return processed_results

    def generate_reports(self, results: dict, target_ip: str):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        base_filename = f"scan_report_{timestamp}"
        
        return {
            'json': self.generate_json_report(results, base_filename),
            'txt': self.generate_text_report(results, base_filename)
        }

    def generate_json_report(self, results: dict, base_filename: str) -> str:
        filename = f"{base_filename}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        return filename

    def generate_text_report(self, results: dict, base_filename: str) -> str:
        filename = f"{base_filename}.txt"
        
        with open(filename, 'w') as f:
            f.write("Security Scan Report\n")
            f.write("===================\n\n")
            
            for host, data in results.items():
                f.write(f"Host: {host}\n")
                f.write("-" * 50 + "\n\n")
                
                f.write("Open Ports and Services:\n")
                f.write("------------------------\n")
                for port, info in data['ports'].items():
                    f.write(f"Port {port}:\n")
                    f.write(f"  State: {info['state']}\n")
                    f.write(f"  Service: {info['service']}\n")
                    if info['version']:
                        f.write(f"  Version: {info['version']}\n")
                    if info['product']:
                        f.write(f"  Product: {info['product']}\n")
                    f.write("\n")
                
                if data['services']:
                    f.write("\nDetected Services:\n")
                    f.write("-----------------\n")
                    for service in set(data['services']):
                        f.write(f"- {service}\n")
                
                f.write("\n" + "="*50 + "\n\n")
        
        return filename

def main():
    scanner = SecurityScanner()
    target = input("Enter target IP address: ")
    ports = input("Enter port range (e.g., 1-100): ")
    
    print("\nStarting security scan...")
    results = scanner.scan_ports(target, ports)
    
    # Generate reports
    report_files = scanner.generate_reports(results, target)
    
    print("\nScan complete! Reports generated:")
    print(f"JSON Report: {report_files['json']}")
    print(f"Text Report: {report_files['txt']}")
    
    # Print summary to console
    for host, data in results.items():
        print(f"\nResults for {host}:")
        print("-" * 50)
        
        for port, info in data['ports'].items():
            state = info['state'].upper()
            service = info['service']
            version = f" ({info['version']})" if info['version'] else ""
            product = f" - {info['product']}" if info['product'] else ""
            
            print(f"Port {port}: {state} - {service}{version}{product}")

if __name__ == "__main__":
    main()