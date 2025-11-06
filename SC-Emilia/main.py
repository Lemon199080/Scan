"""
Improved Proxy Checker v2.0
Checks proxy connectivity and validates against Cloudflare
"""
import socket
import ssl
import json
import re
import concurrent.futures
from typing import Dict, Optional, List, Tuple
from pathlib import Path
from dataclasses import dataclass
import logging

# Configuration
IP_RESOLVER = "speed.cloudflare.com"
PATH_RESOLVER = "/meta"
PROXY_FILE = "Data/proxy.txt"
OUTPUT_FILE = "Data/alive.txt"
MAX_WORKERS = 20
TIMEOUT = 5
RETRY_ATTEMPTS = 2

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_checker.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class ProxyInfo:
    """Data class for proxy information"""
    ip: str
    port: str
    country: str
    org: str

    def __str__(self) -> str:
        return f"{self.ip},{self.port},{self.country},{self.org}"


class ProxyChecker:
    """Main class for checking proxy connectivity"""
    
    def __init__(self, timeout: int = TIMEOUT, retry_attempts: int = RETRY_ATTEMPTS):
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.active_proxies: List[ProxyInfo] = []
        self.stats = {
            'total': 0,
            'alive': 0,
            'dead': 0,
            'errors': 0
        }

    def check_connection(self, host: str, path: str, proxy: Optional[Dict[str, str]] = None) -> Dict:
        """
        Establish SSL connection and retrieve JSON response
        
        Args:
            host: Target hostname
            path: Request path
            proxy: Optional proxy dict with 'ip' and 'port'
            
        Returns:
            JSON response as dict, or empty dict on error
        """
        payload = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n"
        )
        
        ip = proxy.get("ip", host) if proxy else host
        port = int(proxy.get("port", 443)) if proxy else 443
        conn = None
        
        for attempt in range(self.retry_attempts):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                
                conn = socket.create_connection((ip, port), timeout=self.timeout)
                conn = ctx.wrap_socket(conn, server_hostname=host)
                conn.sendall(payload.encode())
                
                resp = b""
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    resp += data
                
                resp_str = resp.decode("utf-8", errors="ignore")
                
                # Parse HTTP response
                if "\r\n\r\n" not in resp_str:
                    logger.warning(f"Invalid HTTP response from {ip}:{port}")
                    continue
                    
                headers, body = resp_str.split("\r\n\r\n", 1)
                
                # Check status code
                if "200 OK" not in headers.split("\r\n")[0]:
                    logger.warning(f"Non-200 response from {ip}:{port}")
                    continue
                
                return json.loads(body)
                
            except json.JSONDecodeError as e:
                logger.debug(f"JSON parse error from {ip}:{port} (attempt {attempt + 1}): {e}")
            except (socket.timeout, socket.error) as e:
                logger.debug(f"Connection error to {ip}:{port} (attempt {attempt + 1}): {e}")
            except ssl.SSLError as e:
                logger.debug(f"SSL error with {ip}:{port} (attempt {attempt + 1}): {e}")
            except Exception as e:
                logger.error(f"Unexpected error with {ip}:{port}: {e}")
                break
            finally:
                if conn:
                    try:
                        conn.close()
                    except:
                        pass
        
        return {}

    @staticmethod
    def clean_org_name(org_name: Optional[str]) -> str:
        """Remove unwanted characters from organization name"""
        if not org_name:
            return "Unknown"
        # Keep alphanumeric, spaces, and common punctuation
        cleaned = re.sub(r'[^a-zA-Z0-9\s\-\.]', '', org_name)
        return cleaned.strip() or "Unknown"

    def parse_proxy_line(self, line: str) -> Optional[ProxyInfo]:
        """Parse a proxy line into ProxyInfo object"""
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        
        parts = line.split(',')
        if len(parts) != 4:
            logger.warning(f"Invalid proxy format: {line}. Expected: ip,port,country,org")
            return None
        
        ip, port, country, org = [p.strip() for p in parts]
        
        # Validate IP format
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            logger.warning(f"Invalid IP address: {ip}")
            return None
        
        # Validate port
        try:
            port_int = int(port)
            if not (1 <= port_int <= 65535):
                raise ValueError
        except ValueError:
            logger.warning(f"Invalid port: {port}")
            return None
        
        return ProxyInfo(ip=ip, port=port, country=country, org=org)

    def test_proxy(self, proxy_info: ProxyInfo) -> bool:
        """
        Test if proxy is working by comparing IPs
        
        Returns:
            True if proxy is alive, False otherwise
        """
        self.stats['total'] += 1
        
        try:
            proxy_data = {"ip": proxy_info.ip, "port": proxy_info.port}
            
            # Get original IP and proxy IP
            original_resp = self.check_connection(IP_RESOLVER, PATH_RESOLVER)
            proxy_resp = self.check_connection(IP_RESOLVER, PATH_RESOLVER, proxy_data)
            
            if not original_resp or not proxy_resp:
                logger.debug(f"Empty response for {proxy_info.ip}:{proxy_info.port}")
                self.stats['dead'] += 1
                return False
            
            original_ip = original_resp.get("clientIp")
            proxy_ip = proxy_resp.get("clientIp")
            
            if not original_ip or not proxy_ip:
                logger.debug(f"Missing clientIp for {proxy_info.ip}:{proxy_info.port}")
                self.stats['dead'] += 1
                return False
            
            # Proxy is working if IPs are different
            if original_ip != proxy_ip:
                # Update org name from actual response
                org_from_response = self.clean_org_name(proxy_resp.get("asOrganization"))
                proxy_info.org = org_from_response
                
                logger.info(f"✓ ALIVE: {proxy_info}")
                self.active_proxies.append(proxy_info)
                self.stats['alive'] += 1
                return True
            else:
                logger.info(f"✗ DEAD: {proxy_info.ip}:{proxy_info.port} (IP not changed)")
                self.stats['dead'] += 1
                return False
                
        except Exception as e:
            logger.error(f"Error testing proxy {proxy_info.ip}:{proxy_info.port}: {e}")
            self.stats['errors'] += 1
            return False

    def process_proxy_file(self, input_file: str, output_file: str):
        """Process all proxies from input file and save results"""
        
        # Ensure directories exist
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        # Clear output file
        Path(output_file).write_text("")
        logger.info(f"Cleared output file: {output_file}")
        
        # Read proxy list
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except FileNotFoundError:
            logger.error(f"File not found: {input_file}")
            return
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return
        
        # Parse proxies
        proxies = []
        for line in lines:
            proxy = self.parse_proxy_line(line)
            if proxy:
                proxies.append(proxy)
        
        if not proxies:
            logger.warning("No valid proxies found in input file")
            return
        
        logger.info(f"Starting check for {len(proxies)} proxies with {MAX_WORKERS} workers...")
        
        # Process proxies concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(self.test_proxy, proxy): proxy for proxy in proxies}
            
            # Wait for all to complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    proxy = futures[future]
                    logger.error(f"Exception for {proxy.ip}:{proxy.port}: {e}")
        
        # Save results
        if self.active_proxies:
            with open(output_file, 'w', encoding='utf-8') as f:
                for proxy in self.active_proxies:
                    f.write(str(proxy) + '\n')
            logger.info(f"Saved {len(self.active_proxies)} active proxies to {output_file}")
        else:
            logger.warning("No active proxies found")
        
        # Print statistics
        logger.info("=" * 50)
        logger.info("SCAN COMPLETE - Statistics:")
        logger.info(f"Total Proxies: {self.stats['total']}")
        logger.info(f"Alive: {self.stats['alive']} ({self.stats['alive']/max(1, self.stats['total'])*100:.1f}%)")
        logger.info(f"Dead: {self.stats['dead']} ({self.stats['dead']/max(1, self.stats['total'])*100:.1f}%)")
        logger.info(f"Errors: {self.stats['errors']}")
        logger.info("=" * 50)


def main():
    """Main entry point"""
    checker = ProxyChecker(timeout=TIMEOUT, retry_attempts=RETRY_ATTEMPTS)
    checker.process_proxy_file(PROXY_FILE, OUTPUT_FILE)


if __name__ == "__main__":
    main()
