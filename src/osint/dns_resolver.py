import dns.resolver

class DNSResolver:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()

    def get_records(self, domain):
        results = {
            "A": [],
            "MX": [],
            "TXT": [],
            "NS": []
        }
        
        for record_type in results.keys():
            try:
                answers = self.resolver.resolve(domain, record_type)
                for rdata in answers:
                    results[record_type].append(str(rdata))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                continue
            except Exception as e:
                print(f"Error resolving {record_type}: {e}")
                
        return results

    def get_subdomains(self, domain):
        # In a real tool, we'd use a wordlist or a dedicated API.
        # For this demo, we'll return common ones or just the A records found.
        return self.get_records(domain).get("A", [])
