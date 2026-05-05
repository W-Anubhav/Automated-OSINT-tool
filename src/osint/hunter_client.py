import requests
import os
from dotenv import load_dotenv

load_dotenv()

class HunterClient:
    def __init__(self):
        self.api_key = os.getenv("HUNTER_API_KEY")
        self.base_url = "https://api.hunter.io/v2"

    def domain_search(self, domain):
        if not self.api_key:
            return {"error": "Hunter API Key not found"}
        
        endpoint = f"{self.base_url}/domain-search"
        params = {
            "domain": domain,
            "api_key": self.api_key
        }
        
        try:
            response = requests.get(endpoint, params=params)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def email_finder(self, domain, first_name, last_name):
        endpoint = f"{self.base_url}/email-finder"
        params = {
            "domain": domain,
            "first_name": first_name,
            "last_name": last_name,
            "api_key": self.api_key
        }
        try:
            response = requests.get(endpoint, params=params)
            return response.json()
        except Exception as e:
            return {"error": str(e)}
