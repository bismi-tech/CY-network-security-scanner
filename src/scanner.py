# src/scanner.py
import nmap3
import json
from datetime import datetime
import os
from utils.validator import InputValidator
from utils.logger import ScanLogger

class SecurityScanner:
    def __init__(self):
        self.scanner = nmap3.Nmap()
        self.logger = ScanLogger()
        self.validator = InputValidator()
        self.security_checks = {
            'ssh': self.analyze_ssh_security,
            'http': self.analyze_http_security,
            'https': self.analyze_https_security,
            'ftp': self.analyze_ftp_security,
            'mysql': self.analyze_database_security,
            'postgresql': self.analyze_database_security,
            'telnet': self.analyze_telnet_security
        }

    def analyze_ssh_security(self, version: str) -> dict:
        analysis = {
            'risk_level': 'LOW',
            'findings': [],
            'recommendations': []
        }
        
        if not version:
            analysis['risk_level'] = 'MEDIUM'
            analysis['findings'].append('SSH version information not available')
            analysis['recommendations'].append('Enable version detection for better analysis')
            return analysis

        if version.startswith('1'):
            analysis['risk_level'] = 'HIGH'
            analysis['findings'].append('SSHv1 is cryptographically broken')
            analysis['recommendations'].append('Upgrade to SSHv2')
        
        if version.startswith('2'):
            analysis['findings'].append('Using SSHv2')
            analysis['recommendations'].append('Ensure strong ciphers are configured')
            analysis['recommendations'].append('Use key-based authentication')

        return analysis

    def analyze_http_security(self, version: str) -> dict:
        analysis = {
            'risk_level': 'MEDIUM',
            'findings': ['HTTP traffic is unencrypted'],
            'recommendations': ['Consider implementing HTTPS']
        }
        
        if version:
            if 'apache' in version.lower():
                analysis['findings'].append(f'Apache version {version} detected')
                analysis['recommendations'].append('Keep Apache updated with security patches')
            elif 'nginx' in version.lower():
                analysis['findings'].append(f'Nginx version {version} detected')
                analysis['recommendations'].append('Keep Nginx updated with security patches')

        return analysis

    def analyze_https_security(self, version: str) -> dict:
        return {
            'risk_level': 'LOW',
            'findings': ['HTTPS is implemented'],
            'recommendations': [
                'Ensure TLS 1.2 or higher is used',
                'Configure secure cipher suites',
                'Implement HSTS'
            ]
        }

    def analyze_ftp_security(self, version: str) -> dict:
        return {
            'risk_level': 'HIGH',
            'findings': ['FTP transfers data in cleartext'],
            'recommendations': [
                'Consider using SFTP instead',
                'Implement strong authentication',
                'Restrict FTP access to specific IPs'
            ]
        }

    def analyze_database_security(self, version: str) -> dict:
        return {
            'risk_level': 'HIGH',
            'findings': ['Database port exposed'],
            'recommendations': [
                'Restrict database access to specific IPs',
                'Use strong authentication',
                'Implement encryption',
                'Regular security patches'
            ]
        }

    def analyze_telnet_security(self, version: str) -> dict:
        return {
            'risk_level': 'CRITICAL',
            'findings': ['Telnet is insecure and transfers data in cleartext'],
            'recommendations': [
                'Disable Telnet immediately',
                'Use SSH instead',
                'Implement encrypted communications'
            ]
        }

    def analyze_port_security(self, port: int) -> dict:
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            5432: 'PostgreSQL'
        }
        
        analysis = {
            'risk_level': 'LOW',
            'findings': [],
            'recommendations': []
        }
        
        if port in common_ports:
            analysis['findings'].append(f'Common service port ({common_ports[port]})')
            analysis['recommendations'].append('Ensure this service is required')
            analysis['recommendations'].append('Implement access controls')
        
        if port < 1024:
            analysis['findings'].append('System port (0-1023)')
        else:
            analysis['findings'].append('User port (1024+)')
            
        return analysis

    def scan_ports(self, target_ip: str, port_range: str = "1-1024") -> dict:
        if not self.validator.validate_ip(target_ip):
            self.logger.error(f"Invalid IP address: {target_ip}")
            return {}

        try:
            self.logger.info(f"Starting security analysis on {target_ip}")
            scan_arguments = " ".join([
                "-sV",                     # Version detection
                "-sT",                     # TCP connect scan
                "-Pn",                     # Skip host discovery
                "--script",                # Enable scripts
                "auth,default,version"     # Script selection
            ])
            
            results = self.scanner.nmap_version_detection(target_ip, args=scan_arguments)
            return self.process_scan_results(results)

        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            return {}

    def process_scan_results(self, results: dict) -> dict:
        processed_results = {
            'scan_summary': {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'total_ports': 0,
                'open_ports': 0,
                'risk_levels': {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0
                }
            },
            'hosts': {}
        }
        
        for host in results:
            if host not in ['runtime', 'stats', 'task_results']:
                processed_results['hosts'][host] = {
                    'ports': {},
                    'services': [],
                    'security_analysis': {
                        'overall_risk': 'LOW',
                        'findings': [],
                        'recommendations': []
                    }
                }
                
                if 'ports' in results[host]:
                    for port_info in results[host]['ports']:
                        port = port_info['portid']
                        service_info = port_info.get('service', {})
                        
                        # Analyze port security
                        port_analysis = self.analyze_port_security(int(port))
                        
                        # Analyze service security
                        service_name = service_info.get('name', 'unknown')
                        version = service_info.get('version', '')
                        
                        service_analysis = self.security_checks.get(service_name, lambda x: {
                            'risk_level': 'MEDIUM',
                            'findings': ['Unknown service'],
                            'recommendations': ['Verify service necessity']
                        })(version)
                        
                        # Combine analyses
                        combined_analysis = {
                            'risk_level': service_analysis['risk_level'],
                            'findings': port_analysis['findings'] + service_analysis['findings'],
                            'recommendations': port_analysis['recommendations'] + service_analysis['recommendations']
                        }
                        
                        processed_results['hosts'][host]['ports'][port] = {
                            'state': port_info.get('state', 'unknown'),
                            'service': service_name,
                            'version': version,
                            'product': service_info.get('product', ''),
                            'security_analysis': combined_analysis
                        }
                        
                        # Update risk level counters
                        processed_results['scan_summary']['risk_levels'][combined_analysis['risk_level']] += 1
                        
                        # Update overall statistics
                        processed_results['scan_summary']['total_ports'] += 1
                        if port_info.get('state') == 'open':
                            processed_results['scan_summary']['open_ports'] += 1
                        
                        # Collect findings and recommendations
                        processed_results['hosts'][host]['security_analysis']['findings'].extend(combined_analysis['findings'])
                        processed_results['hosts'][host]['security_analysis']['recommendations'].extend(combined_analysis['recommendations'])
                
                # Determine overall risk level for host
                if processed_results['scan_summary']['risk_levels']['CRITICAL'] > 0:
                    processed_results['hosts'][host]['security_analysis']['overall_risk'] = 'CRITICAL'
                elif processed_results['scan_summary']['risk_levels']['HIGH'] > 0:
                    processed_results['hosts'][host]['security_analysis']['overall_risk'] = 'HIGH'
                elif processed_results['scan_summary']['risk_levels']['MEDIUM'] > 0:
                    processed_results['hosts'][host]['security_analysis']['overall_risk'] = 'MEDIUM'

        return processed_results

    def generate_security_report(self, results: dict, base_filename: str) -> str:
        filename = f"reports/{base_filename}_security_analysis.txt"
        
        with open(filename, 'w') as f:
            f.write("Security Analysis Report\n")
            f.write("=======================\n\n")
            
            # Write summary
            f.write("Scan Summary\n")
            f.write("------------\n")
            f.write(f"Scan Time: {results['scan_summary']['timestamp']}\n")
            f.write(f"Total Ports: {results['scan_summary']['total_ports']}\n")
            f.write(f"Open Ports: {results['scan_summary']['open_ports']}\n\n")
            
            f.write("Risk Level Distribution\n")
            f.write("----------------------\n")
            for level, count in results['scan_summary']['risk_levels'].items():
                f.write(f"{level}: {count}\n")
            f.write("\n")
            
            # Write host details
            for host, data in results['hosts'].items():
                f.write(f"Host: {host}\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Overall Risk Level: {data['security_analysis']['overall_risk']}\n\n")
                
                f.write("Port Analysis\n")
                f.write("-------------\n")
                for port, info in data['ports'].items():
                    f.write(f"\nPort {port} ({info['service']}):\n")
                    f.write(f"State: {info['state']}\n")
                    f.write(f"Risk Level: {info['security_analysis']['risk_level']}\n")
                    
                    f.write("Findings:\n")
                    for finding in info['security_analysis']['findings']:
                        f.write(f"- {finding}\n")
                    
                    f.write("Recommendations:\n")
                    for rec in info['security_analysis']['recommendations']:
                        f.write(f"- {rec}\n")
                
                f.write("\nOverall Security Findings:\n")
                f.write("-----------------------\n")
                for finding in set(data['security_analysis']['findings']):
                    f.write(f"- {finding}\n")
                
                f.write("\nSecurity Recommendations:\n")
                f.write("------------------------\n")
                for rec in set(data['security_analysis']['recommendations']):
                    f.write(f"- {rec}\n")
                
                f.write("\n" + "="*50 + "\n\n")
        
        return filename

    def generate_reports(self, results: dict, target_ip: str):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        base_filename = f"scan_report_{timestamp}"
        
        # Create reports directory if it doesn't exist
        os.makedirs('reports', exist_ok=True)
        
        return {
            'security': self.generate_security_report(results, base_filename),
            'json': self.generate_json_report(results, base_filename),
            'txt': self.generate_text_report(results, base_filename)
        }

    def generate_json_report(self, results: dict, base_filename: str) -> str:
        filename = f"reports/{base_filename}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        return filename

    def generate_text_report(self, results: dict, base_filename: str) -> str:
        filename = f"reports/{base_filename}.txt"
        
        with open(filename, 'w') as f:
            f.write("Port Scan Report\n")
            f.write("===============\n\n")
            
            for host, data in results['hosts'].items():
                f.write(f"Host: {host}\n")
                f.write("-" * 50 + "\n\n")
                
                for port, info in data['ports'].items():
                    f.write(f"Port {port}:\n")
                    f.write(f"  State: {info['state']}\n")
                    f.write(f"  Service: {info['service']}\n")
                    if info['version']:
                        f.write(f"  Version: {info['version']}\n")
                    if info['product']:
                        f.write(f"  Product: {info['product']}\n")
                    f.write("\n")
        
        return filename

def main():
    scanner = SecurityScanner()
    target = input("Enter target IP address: ")
    ports = input("Enter port range (e.g., 1-100): ")
    
    print("\nStarting security analysis...")
    results = scanner.scan_ports(target, ports)
    
    # Generate reports
    report_files = scanner.generate_reports(results, target)
    
    print("\nScan complete! Reports generated:")
    print(f"Security Analysis: {report_files['security']}")
    print(f"JSON Report: {report_files['json']}")
    print(f"Text Report: {report_files['txt']}")
    
    # Print summary to console
    print("\nSecurity Analysis Summary:")
    print(f"Total Ports: {results['scan_summary']['total_ports']}")
    print(f"Open Ports: {results['scan_summary']['open_ports']}")
    print("\nRisk Level Distribution:")
    for level, count in results['scan_summary']['risk_levels'].items():
        print(f"{level}: {count}")
    
    for host, data in results['hosts'].items():
        print(f"\nResults for {host}:")
        print(f"Overall Risk Level: {data['security_analysis']['overall_risk']}")
        print("-" * 50)
        
        for port, info in data['ports'].items():
            state = info['state'].upper()
            service = info['service']
            version = f" ({info['version']})" if info['version'] else ""
            risk = info['security_analysis']['risk_level']
            
            print(f"\nPort {port}: {state} - {service}{version}")
            print(f"Risk Level: {risk}")
            if info['security_analysis']['findings']:
                print("Findings:")
                for finding in info['security_analysis']['findings']:
                    print(f"- {finding}")

if __name__ == "__main__":
    main()