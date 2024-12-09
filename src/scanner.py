import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Optional

class ActiveScanner:
    """Active Scanner implementation with service detection and banner grabbing"""
    
    COMMON_PORTS = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        110: "POP3",
        143: "IMAP",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Proxy"
    }

    def __init__(self, target_ip: str, timeout: float = 0.5):
        self.target_ip = target_ip
        self.timeout = timeout
        self.open_ports: Dict[int, Dict] = {}

    def scan_port(self, port: int) -> Optional[Dict]:
        """
        Scan a single port and attempt service detection
        """
        try:
            # Initial connection check
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:  # Port is open
                    # Create new connection for banner grabbing
                    service_info = {
                        'service': self.COMMON_PORTS.get(port, "Unknown"),
                        'banner': self.grab_banner(port)
                    }
                    print(f"[+] Port {port} is open ({service_info['service']})")
                    return service_info
                return None
                
        except socket.error as e:
            print(f"[!] Error scanning port {port}: {str(e)}")
            return None

    def grab_banner(self, port: int) -> str:
        """
        Attempt to grab service banner from the specified port
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.target_ip, port))
                
                # Prepare custom requests for different services
                if port == 80 or port == 8080:
                    sock.send(f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n".encode())
                elif port == 443:
                    return "HTTPS Enabled"  # Simple HTTPS detection
                
                # Try to receive banner
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    return banner[:100]  # Limit banner length
                except socket.timeout:
                    return f"{self.COMMON_PORTS.get(port, 'Unknown')} - No banner"
                
        except (socket.error, UnicodeDecodeError):
            return "No banner available"

    def scan_range(self, start_port: int = 1, end_port: int = 1024, max_workers: int = 100):
        """
        Scan a range of ports using multiple threads
        """
        print(f"\n[*] Starting active scan on {self.target_ip}")
        print(f"[*] Scanning ports {start_port}-{end_port}")
        print(f"[*] Timeout set to {self.timeout} seconds")
        start_time = time.time()

        try:
            # Test connection to target
            socket.gethostbyname(self.target_ip)
        except socket.gaierror:
            print(f"[!] Could not resolve host: {self.target_ip}")
            return

        ports_to_scan = range(start_port, end_port + 1)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port 
                            for port in ports_to_scan}
            
            completed = 0
            total_ports = len(ports_to_scan)
            
            for future in as_completed(future_to_port):
                completed += 1
                if completed % 100 == 0:  # Progress update every 100 ports
                    print(f"[*] Progress: {completed}/{total_ports} ports scanned "
                          f"({(completed/total_ports*100):.1f}%)")
                
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        self.open_ports[port] = result
                except Exception as e:
                    print(f"[!] Unexpected error scanning port {port}: {str(e)}")

        scan_time = time.time() - start_time
        self._print_results(scan_time)

    def _print_results(self, scan_time: float):
        """Print scan results in a formatted way"""
        print("\n============ SCAN RESULTS ============")
        print(f"Target IP: {self.target_ip}")
        print(f"Scan Duration: {scan_time:.2f} seconds")
        print(f"Open Ports: {len(self.open_ports)}")
        
        if self.open_ports:
            print("\nPORT\tSTATE\tSERVICE\tBANNER")
            print("-" * 60)
            for port, info in sorted(self.open_ports.items()):
                banner = info['banner'][:50] + "..." if len(info['banner']) > 50 else info['banner']
                print(f"{port}\topen\t{info['service']}\t{banner}")
        else:
            print("\nNo open ports found.")
            print("\nPossible reasons:")
            print("1. Host is not accessible")
            print("2. Firewall is blocking the scan")
            print("3. No services running on scanned ports")
        print("====================================")

def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <ip>")
        print("Example: python scanner.py 192.168.1.1")
        sys.exit(1)

    target_ip = sys.argv[1]
    scanner = ActiveScanner(target_ip)
    
    try:
        scanner.scan_range(1, 1024)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()