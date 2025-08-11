import os, requests
from dotenv import load_dotenv
load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")
HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}

def recent_iocs(limit=50):
    """Pull recent subscribed pulses and flatten to indicators.
    NOTE: Free-tier returns user's subscribed pulses; you can also call /indicators endpoint.
    """
    r = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed",
                     headers=HEADERS, timeout=30)
    if r.status_code != 200:
        return []
    data = r.json()
    out = []
    for pulse in data.get("results", [])[:10]:
        for ind in pulse.get("indicators", []):
            out.append({
                "indicator": ind.get("indicator"),
                "type": ind.get("type"),  # IPv4, domain, URL, FileHash-*
                "tags": pulse.get("tags", []),
            })
            if len(out) >= limit:
                return out
    return out
