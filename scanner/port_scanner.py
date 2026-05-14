import socket
import json
from datetime import datetime
from threading import Thread
import ipaddress

class PortScanner:
    
    # Portas comuns
    COMMON_PORTS = {
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
    }
    
    def __init__(self, timeout=2):
        self.timeout = timeout
        self.results = {
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'scan_start': None,
            'scan_end': None,
        }
    
    @staticmethod
    def validate_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def get_hostname(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    def scan_port(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return 'open'
            else:
                return 'closed'
        except socket.timeout:
            return 'filtered'
        except Exception as e:
            return 'error'
    
    def scan_common_ports(self, host):
        if not self.validate_ip(host):
            return {
                'status': 'error',
                'message': 'IP inválido'
            }
        
        self.results['scan_start'] = datetime.utcnow().isoformat()
        self.results['target_host'] = host
        self.results['hostname'] = self.get_hostname(host)
        
        for port in sorted(self.COMMON_PORTS.keys()):
            status = self.scan_port(host, port)
            
            port_info = {
                'port': port,
                'service': self.COMMON_PORTS[port],
                'status': status
            }
            
            if status == 'open':
                self.results['open_ports'].append(port_info)
            elif status == 'closed':
                self.results['closed_ports'].append(port_info)
            else:
                self.results['filtered_ports'].append(port_info)
        
        self.results['scan_end'] = datetime.utcnow().isoformat()
        return {
            'status': 'success',
            'results': self.results
        }
    
    def scan_port_range(self, host, start_port, end_port):
        if not self.validate_ip(host):
            return {
                'status': 'error',
                'message': 'IP inválido'
            }
        
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            return {
                'status': 'error',
                'message': 'Range de portas inválido'
            }
        
        self.results['scan_start'] = datetime.utcnow().isoformat()
        self.results['target_host'] = host
        self.results['hostname'] = self.get_hostname(host)
        
        for port in range(start_port, end_port + 1):
            status = self.scan_port(host, port)
            
            port_info = {
                'port': port,
                'status': status
            }
            
            if status == 'open':
                self.results['open_ports'].append(port_info)
            elif status == 'closed':
                self.results['closed_ports'].append(port_info)
            else:
                self.results['filtered_ports'].append(port_info)
        
        self.results['scan_end'] = datetime.utcnow().isoformat()
        return {
            'status': 'success',
            'results': self.results
        }
    
    def get_results_json(self):
        return json.dumps(self.results, indent=2, default=str)
