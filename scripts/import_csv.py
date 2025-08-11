import sys, csv, os
from dotenv import load_dotenv
from sqlalchemy import text, create_engine

if len(sys.argv) < 2:
    print("Usage: python3 scripts/import_csv.py <path_to_csv>")
    raise SystemExit(1)

load_dotenv()
engine = create_engine(os.getenv("DB_URL"))

SRC = "maltego"
with engine.begin() as conn:
    conn.execute(text("INSERT INTO sources(name) VALUES (:n) ON CONFLICT DO NOTHING"), {"n": SRC})
    src_id = conn.execute(text("SELECT id FROM sources WHERE name=:n"), {"n": SRC}).scalar()

    with open(sys.argv[1], newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            ind = row.get("indicator") or row.get("value") or row.get("Entity")
            t   = (row.get("type") or row.get("kind") or "").lower()
            if not ind:
                continue
            if t in ("ipv4","ip"): t = "ip"
            elif t in ("domain","dnsname"): t = "domain"
            elif t in ("url","uri"): t = "url"
            else: t = "hash" if "hash" in t else None
            if not t:
                continue
            conn.execute(text("""
              INSERT INTO indicators(indicator,type,source_id)
              VALUES (:i,:t,:s)
              ON CONFLICT (indicator,type,source_id) DO UPDATE
              SET last_seen=now()
            """), {"i": ind, "t": t, "s": src_id})
print("Imported.")
