import requests
import os
from dotenv import load_dotenv

load_dotenv()

class BreachClient:
    def __init__(self):
        self.api_key = os.getenv("BREACH_DIRECTORY_API_KEY")
        self.host = "breachdirectory.p.rapidapi.com"
        self.base_url = f"https://{self.host}/"

    def check_email_breaches(self, email):
        if not self.api_key:
            return {"error": "BreachDirectory API Key not found"}
        
        headers = {
            "x-rapidapi-host": self.host,
            "x-rapidapi-key": self.api_key
        }
        
        # params: func=auto, query=<email>
        params = {
            "func": "auto",
            "term": email
        }
        
        try:
            response = requests.get(self.base_url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}
