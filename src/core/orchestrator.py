from src.osint.hunter_client import HunterClient
from src.osint.dns_resolver import DNSResolver
from src.scanner.nmap_scanner import PortScanner
from src.core.graph_manager import GraphManager
from src.osint.breach_client import BreachClient

class ThreatIntelOrchestrator:
    def __init__(self):
        self.hunter = HunterClient()
        self.dns = DNSResolver()
        self.scanner = PortScanner()
        self.graph = GraphManager()
        self.breach = BreachClient()

    def run_recon(self, input_target):
        """
        Full workflow: Passive OSINT -> Graph -> Active Scan -> Graph
        """
        # Clean the input target (strip http/https and trailing slashes)
        target_domain = input_target.replace("https://", "").replace("http://", "").split("/")[0]
        
        results = {"target": target_domain, "osint": {}, "scans": []}
        
        # 1. Passive OSINT
        print(f"[*] Running Passive OSINT for {target_domain}...")
        self.graph.add_target_node(target_domain)
        
        # DNS Resolution
        dns_data = self.dns.get_records(target_domain)
        results["osint"]["dns"] = dns_data
        self.graph.add_osint_data(target_domain, dns_data)
        
        # Hunter.io Search
        hunter_data = self.hunter.domain_search(target_domain)
        results["osint"]["hunter"] = hunter_data
        self.graph.add_osint_data(target_domain, hunter_data)
        
        # 2. Breach Check (for discovered emails)
        results["osint"]["breaches"] = {}
        emails = [e.get("value") for e in hunter_data.get("data", {}).get("emails", [])]
        for email in emails[:5]: # Limit to first 5 for performance/rate limits
            print(f"[*] Checking breaches for {email}...")
            breach_data = self.breach.check_email_breaches(email)
            results["osint"]["breaches"][email] = breach_data
            self.graph.add_breach_data(email, breach_data)

        # 3. Active Recon (based on discovered IPs)
        ips = dns_data.get("A", [])
        for ip in ips:
            print(f"[*] Starting active scan on discovered IP: {ip}")
            scan_data = self.scanner.scan_target(ip)
            results["scans"].append({"ip": ip, "results": scan_data})
            self.graph.add_scan_results(ip, scan_data)
            
        return results, self.graph.generate_interactive_graph()
