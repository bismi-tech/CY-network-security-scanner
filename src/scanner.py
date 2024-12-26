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
            self.logger.info(f"Starting vulnerability scan on {target_ip}")
            # Enhanced scanning with vulnerability detection
            scan_arguments = " ".join([
                "-sV",                      # Version detection
                "-sT",                      # TCP connect scan
                "-Pn",                      # Skip host discovery
                "--script",                 # Enable script scanning
                "vuln,auth,default,version" # Vulnerability scripts
            ])
            
            results = self.scanner.nmap_version_detection(target_ip, args=scan_arguments)
            return self.process_scan_results(results)

        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            return {}

    def check_vulnerabilities(self, service: str, version: str) -> list:
        """Check for known vulnerabilities in services"""
        vulnerabilities = []
        
        # Common vulnerability checks
        if service == 'http' and version:
            if version.startswith('2.'):
                vulnerabilities.append({
                    'severity': 'MEDIUM',
                    'description': f'Apache {version} might be outdated and vulnerable to attacks'
                })
        
        elif service == 'ssh':
            if version and version.startswith('1.'):
                vulnerabilities.append({
                    'severity': 'HIGH',
                    'description': 'SSHv1 is cryptographically broken'
                })
        
        elif service == 'ftp':
            vulnerabilities.append({
                'severity': 'WARNING',
                'description': 'FTP transfers data in cleartext'
            })
        
        return vulnerabilities

    def process_scan_results(self, results: dict) -> dict:
        processed_results = {}
        
        for host in results:
            if host not in ['runtime', 'stats', 'task_results']:
                processed_results[host] = {
                    'ports': {},
                    'services': [],
                    'vulnerabilities': []
                }
                
                if 'ports' in results[host]:
                    for port_info in results[host]['ports']:
                        port = port_info['portid']
                        service_info = port_info.get('service', {})
                        
                        # Enhanced service information
                        service_name = service_info.get('name', 'unknown')
                        version = service_info.get('version', '')
                        
                        # Check for vulnerabilities
                        vulns = self.check_vulnerabilities(service_name, version)
                        
                        processed_results[host]['ports'][port] = {
                            'state': port_info.get('state', 'unknown'),
                            'service': service_name,
                            'version': version,
                            'product': service_info.get('product', ''),
                            'vulnerabilities': vulns
                        }
                        
                        if vulns:
                            processed_results[host]['vulnerabilities'].extend(vulns)
                        
                        if service_name:
                            processed_results[host]['services'].append(service_name)

        return processed_results

    def generate_vulnerability_report(self, results: dict, base_filename: str) -> str:
        filename = f"reports/{base_filename}_vulnerabilities.txt"
        
        with open(filename, 'w') as f:
            f.write("Vulnerability Scan Report\n")
            f.write("=======================\n\n")
            
            for host, data in results.items():
                f.write(f"Host: {host}\n")
                f.write("-" * 50 + "\n\n")
                
                if data['vulnerabilities']:
                    f.write("Found Vulnerabilities:\n")
                    f.write("---------------------\n")
                    for vuln in data['vulnerabilities']:
                        f.write(f"Severity: {vuln['severity']}\n")
                        f.write(f"Description: {vuln['description']}\n\n")
                
                f.write("Service Details:\n")
                f.write("---------------\n")
                for port, info in data['ports'].items():
                    f.write(f"Port {port}:\n")
                    f.write(f"  Service: {info['service']}\n")
                    f.write(f"  Version: {info['version']}\n")
                    if info['vulnerabilities']:
                        f.write("  Vulnerabilities:\n")
                        for vuln in info['vulnerabilities']:
                            f.write(f"    - [{vuln['severity']}] {vuln['description']}\n")
                    f.write("\n")
                
                f.write("\n" + "="*50 + "\n\n")
        
        return filename

    def generate_reports(self, results: dict, target_ip: str):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        base_filename = f"scan_report_{timestamp}"
        
        return {
            'json': self.generate_json_report(results, base_filename),
            'txt': self.generate_text_report(results, base_filename),
            'vuln': self.generate_vulnerability_report(results, base_filename)
        }

    def generate_json_report(self, results: dict, base_filename: str) -> str:
        filename = f"reports/{base_filename}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        return filename

    def generate_text_report(self, results: dict, base_filename: str) -> str:
        filename = f"reports/{base_filename}.txt"
        
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
                    if info['vulnerabilities']:
                        f.write("  Vulnerabilities Found:\n")
                        for vuln in info['vulnerabilities']:
                            f.write(f"    - {vuln['description']}\n")
                    f.write("\n")
                
                f.write("\n" + "="*50 + "\n\n")
        
        return filename

def main():
    scanner = SecurityScanner()
    target = input("Enter target IP address: ")
    ports = input("Enter port range (e.g., 1-100): ")
    
    print("\nStarting vulnerability scan...")
    results = scanner.scan_ports(target, ports)
    
    # Generate reports
    report_files = scanner.generate_reports(results, target)
    
    print("\nScan complete! Reports generated:")
    print(f"JSON Report: {report_files['json']}")
    print(f"Text Report: {report_files['txt']}")
    print(f"Vulnerability Report: {report_files['vuln']}")
    
    # Print summary to console
    for host, data in results.items():
        print(f"\nResults for {host}:")
        print("-" * 50)
        
        if data['vulnerabilities']:
            print("\nVulnerabilities Found:")
            for vuln in data['vulnerabilities']:
                print(f"- [{vuln['severity']}] {vuln['description']}")
        
        print("\nPort Details:")
        for port, info in data['ports'].items():
            state = info['state'].upper()
            service = info['service']
            version = f" ({info['version']})" if info['version'] else ""
            product = f" - {info['product']}" if info['product'] else ""
            
            print(f"Port {port}: {state} - {service}{version}{product}")
            if info['vulnerabilities']:
                for vuln in info['vulnerabilities']:
                    print(f"  ! {vuln['severity']}: {vuln['description']}")

if __name__ == "__main__":
    main()