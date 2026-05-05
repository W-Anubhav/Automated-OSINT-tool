import nmap
import os
from dotenv import load_dotenv

load_dotenv()

class PortScanner:
    def __init__(self):
        # On Windows, Nmap path might need to be explicitly set in the environment PATH
        nmap_bin_path = os.getenv("NMAP_PATH")
        if nmap_bin_path and os.path.exists(nmap_bin_path):
            nmap_dir = os.path.dirname(nmap_bin_path)
            if nmap_dir not in os.environ["PATH"]:
                os.environ["PATH"] += os.pathsep + nmap_dir
        
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("[-] Error: Nmap not found. Please ensure NMAP_PATH is correct in .env")
            raise

    def scan_target(self, target, arguments="-sV -T4"):
        """
        Performs a lightweight Nmap scan on the target.
        -sV: Service/Version detection
        -T4: Faster execution
        """
        try:
            print(f"Starting scan on {target}...")
            self.nm.scan(target, arguments=arguments)
            
            scan_results = []
            for host in self.nm.all_hosts():
                host_data = {
                    "host": host,
                    "hostname": self.nm[host].hostname(),
                    "status": self.nm[host].state(),
                    "protocols": []
                }
                
                for proto in self.nm[host].all_protocols():
                    proto_data = {"protocol": proto, "ports": []}
                    lport = self.nm[host][proto].keys()
                    for port in sorted(lport):
                        port_info = self.nm[host][proto][port]
                        proto_data["ports"].append({
                            "port": port,
                            "state": port_info['state'],
                            "service": port_info['name'],
                            "product": port_info.get('product', ''),
                            "version": port_info.get('version', '')
                        })
                    host_data["protocols"].append(proto_data)
                scan_results.append(host_data)
            return scan_results
        except Exception as e:
            return {"error": str(e)}
