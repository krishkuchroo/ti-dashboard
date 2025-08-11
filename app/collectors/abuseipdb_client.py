import os, requests
from dotenv import load_dotenv
load_dotenv()
KEY = os.getenv("ABUSEIPDB_API_KEY")

def ip_report(ip: str):
    r = requests.get("https://api.abuseipdb.com/api/v2/check",
                     headers={"Key": KEY, "Accept": "application/json"},
                     params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=20)
    return r.json() if r.status_code == 200 else None
