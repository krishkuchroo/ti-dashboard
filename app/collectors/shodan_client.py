import os, requests
from dotenv import load_dotenv
load_dotenv()
KEY = os.getenv("SHODAN_API_KEY")

def ip_report(ip: str):
    r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={KEY}", timeout=20)
    return r.json() if r.status_code == 200 else None
