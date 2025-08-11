import re
from sqlalchemy import text
from app.db import SessionLocal
from app.scheduler import ensure_sources, upsert, normalize_enrich_ip
from app.collectors import ip_feed, vt_client, shodan_client, abuseipdb_client

def _clean(o):
    if isinstance(o, dict): return {k:_clean(v) for k,v in o.items()}
    if isinstance(o, list): return [_clean(x) for x in o]
    if isinstance(o, str):  return re.sub(r'[\ud800-\udfff]', '', o)
    return o

def _safe_norm(ip, vendor, raw):
    n = normalize_enrich_ip(ip, vendor, raw)
    if n.get("extra") is not None:
        n["extra"] = _clean(n["extra"])
    return n

def main(seed_limit=40, enrich_limit=40):
    db = SessionLocal()
    ensure_sources(db)
    src = {name:sid for sid,name in db.execute(text("SELECT id,name FROM sources"))}
    def sid(name):
        if name in src: return src[name]
        i = db.execute(text("INSERT INTO sources(name) VALUES (:n) RETURNING id"),{"n":name}).scalar()
        src[name]=i; return i
    s_ip=sid("ip_feed"); s_man=sid("manual"); s_vt=sid("virustotal"); s_sh=sid("shodan"); s_ab=sid("abuseipdb")

    # your IP (Bay Ridge)
    upsert(db, s_man,_cat > scripts/seed_demo.py <<'PY'
import re
from sqlalchemy import text
from app.db import SessionLocal
from app.scheduler import ensure_sources, upsert, normalize_enrich_ip
from app.collectors import ip_feed, vt_client, shodan_client, abuseipdb_client

def _clean(o):
    if isinstance(o, dict): return {k:_clean(v) for k,v in o.items()}
    if isinstance(o, list): return [_clean(x) for x in o]
    if isinstance(o, str):  return re.sub(r'[\ud800-\udfff]', '', o)
    return o

def _safe_norm(ip, vendor, raw):
    n = normalize_enrich_ip(ip, vendor, raw)
    if n.get("extra") is not None:
        n["extra"] = _clean(n["extra"])
    return n

def main(seed_limit=40, enrich_limit=40):
    db = SessionLocal()
    ensure_sources(db)
    src = {name:sid for sid,name in db.execute(text("SELECT id,name FROM sources"))}
    def sid(name):
        if name in src: return src[name]
        i = db.execute(text("INSERT INTO sources(name) VALUES (:n) RETURNING id"),{"n":name}).scalar()
        src[name]=i; return i
    s_ip=sid("ip_feed"); s_man=sid("manual"); s_vt=sid("virustotal"); s_sh=sid("shodan"); s_ab=sid("abuseipdb")

    # your IP (Bay Ridge)
    upsert(db, s_man, {
        "indicator":"192.168.1.173","type":"ip","reputation_score":95,
        "categories":["lab","demo"],
        "geo":{"lat":40.6299,"lon":-74.0231,"label":"home-7807-3rd-ave"},
        "extra":{"note":"user-added"}
    })

    # seed feeds
    for ip in ip_feed.fetch_ips(limit=seed_limit):
        upsert(db, s_ip, {"indicator":ip,"type":"ip","reputation_score":70,
                          "categories":["ip_feed"],"geo":None,"extra":{"seed":True}})
    db.commit()

    # enrich latest distinct IPs
    rows = db.execute(text("""
        SELECT indicator, MAX(last_seen) AS last_seen
        FROM indicators WHERE type='ip'
        GROUP BY indicator ORDER BY last_seen DESC
        LIMIT :lim
    """), {"lim": enrich_limit}).fetchall()
    for ip in [r[0] for r in rows]:
        upsert(db, s_vt, _safe_norm(ip,"virustotal", vt_client.ip_report(ip)))
        upsert(db, s_sh, _safe_norm(ip,"shodan",     shodan_client.ip_report(ip)))
        upsert(db, s_ab, _safe_norm(ip,"abuseipdb",  abuseipdb_client.ip_report(ip)))
    db.commit()
    db.close()

if __name__ == "__main__":
    main()
