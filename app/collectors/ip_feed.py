import requests
FEEDS = [
  "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
  "https://blocklist.greensnow.co/greensnow.txt"
]
def fetch_ips(limit=25):
    ips = []
    for url in FEEDS:
        try:
            r = requests.get(url, timeout=25)
            if r.status_code != 200: continue
            for line in r.text.splitlines():
                s = line.strip()
                if not s or s.startswith(("#",";")): continue
                cand = s.split()[0]
                if cand.count(".")==3 and all(p.isdigit() and 0<=int(p)<=255 for p in cand.split(".")):
                    if cand not in ips:
                        ips.append(cand)
                        if len(ips) >= limit: return ips
        except Exception:
            pass
    return ips
