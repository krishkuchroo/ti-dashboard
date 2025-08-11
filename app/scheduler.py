from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select, text
from datetime import datetime
import os

from .db import SessionLocal
from .models import Indicator, Source, IocType
from .collectors import otx_client, vt_client, shodan_client, abuseipdb_client, shodan_search


def ensure_sources(db):
    for name in ("otx", "virustotal", "shodan", "abuseipdb", "shodan_search"):
        db.execute(text("INSERT INTO sources(name) VALUES (:n) ON CONFLICT DO NOTHING"), {"n": name})
    db.commit()


def upsert(db, src_id, i):
    existing = db.execute(
        select(Indicator).where(
            Indicator.indicator == i["indicator"],
            Indicator.type == IocType(i["type"]),
            Indicator.source_id == src_id
        )
    ).scalar_one_or_none()
    if existing:
        existing.last_seen = datetime.utcnow()
        if i.get("reputation_score") is not None:
            existing.reputation_score = i["reputation_score"]
        if i.get("categories"):
            existing.categories = list(set((existing.categories or []) + i["categories"]))
        if i.get("geo"):
            existing.geo = i["geo"]
        if i.get("extra"):
            existing.extra = i["extra"]
    else:
        db.add(Indicator(**i, source_id=src_id))


def normalize_otx(i):
    tmap = {"IPv4": "ip", "domain": "domain", "URL": "url", "FileHash-SHA256": "hash", "FileHash-MD5": "hash"}
    t = tmap.get(i["type"])
    if not t:
        return None
    return {
        "indicator": i["indicator"],
        "type": t,
        "reputation_score": 60,
        "categories": i.get("tags") or None,
        "geo": None,
        "extra": {"otx_type": i["type"]},
    }


def normalize_enrich_ip(ip, vendor, raw):
    score, cats, geo = None, None, None
    if vendor == "virustotal" and raw:
        stats = (raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}))
        positives = (stats.get("malicious", 0) + stats.get("suspicious", 0))
        score = min(100, positives * 10)
    if vendor == "shodan" and raw:
        geo = {"country": raw.get("country_code"),
               "city": raw.get("city"),
               "lat": raw.get("latitude"),
               "lon": raw.get("longitude")}
    if vendor == "abuseipdb" and raw:
        d = raw.get("data", {})
        score = d.get("abuseConfidenceScore")
        geo = {"country": d.get("countryCode")}
    return {"indicator": ip, "type": "ip", "reputation_score": score, "categories": cats, "geo": geo, "extra": raw}


def pull_cycle():
    db = SessionLocal()
    ensure_sources(db)
    src_ids = {name: sid for sid, name in db.execute(text("SELECT id, name FROM sources"))}

    # 1) OTX pulses → indicators
    for raw in otx_client.recent_iocs(limit=50):
        n = normalize_otx(raw)
        if n:
            upsert(db, src_ids["otx"], n)
    db.commit()

    # 1b) Seed extra IPs from Shodan Search (so the map fills in)
    query = os.getenv("SHODAN_SEARCH_QUERY", "port:23 country:US")
    limit = int(os.getenv("SHODAN_SEARCH_LIMIT", "25"))
    for ip in shodan_search.search_ips(query=query, limit=limit):
        upsert(db, src_ids["shodan_search"], {
            "indicator": ip,
            "type": "ip",
            "reputation_score": 50,
            "categories": ["shodan_search"],
            "geo": None,
            "extra": {"query": query},
        })
    db.commit()

    # 2) Enrich a small set of IPs
    ips = [r[0] for r in db.execute(text("SELECT DISTINCT indicator FROM indicators WHERE type='ip' LIMIT 20"))]
    for ip in ips:
        vt = vt_client.ip_report(ip);         upsert(db, src_ids["virustotal"], normalize_enrich_ip(ip, "virustotal", vt))
        sh = shodan_client.ip_report(ip);     upsert(db, src_ids["shodan"],     normalize_enrich_ip(ip, "shodan", sh))
        ab = abuseipdb_client.ip_report(ip);  upsert(db, src_ids["abuseipdb"],  normalize_enrich_ip(ip, "abuseipdb", ab))
    db.commit()
    db.close()


def start_scheduler():
    sched = BackgroundScheduler(timezone="UTC")
    sched.add_job(pull_cycle, "interval", minutes=15, id="ioc-pull")
    sched.start()
