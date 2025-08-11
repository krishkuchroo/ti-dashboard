import os, requests
from dotenv import load_dotenv
load_dotenv()
KEY = os.getenv("SHODAN_API_KEY")
def search_ips(query=None, limit=None):
    if not KEY: return []
    if query is None: query = os.getenv("SHODAN_SEARCH_QUERY", "port:23 country:US")
    if limit is None:
        try: limit = int(os.getenv("SHODAN_SEARCH_LIMIT", "25"))
        except ValueError: limit = 25
    out, page = [], 1
    while len(out) < limit:
        r = requests.get("https://api.shodan.io/shodan/host/search",
                         params={"key": KEY, "query": query, "page": page}, timeout=25)
        if r.status_code != 200: break
        data = r.json()
        for m in data.get("matches", []):
            ip = m.get("ip_str")
            if ip and ip not in out:
                out.append(ip)
                if len(out) >= limit: break
        if page * 100 >= data.get("total", 0): break
        page += 1
    return out
