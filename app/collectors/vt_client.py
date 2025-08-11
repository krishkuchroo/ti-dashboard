import os, requests
from dotenv import load_dotenv
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
HEADERS = {"x-apikey": VT_API_KEY}

def ip_report(ip: str):
    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                     headers=HEADERS, timeout=20)
    return r.json() if r.status_code == 200 else None
