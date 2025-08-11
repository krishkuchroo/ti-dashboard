# Threat Intelligence Dashboard (OSINT + Real-Time Feeds)

FastAPI + PostgreSQL + Grafana dashboard that aggregates IOCs from OTX, VirusTotal, Shodan, AbuseIPDB, and public IP feeds. Normalizes/enriches (reputation + geo) and visualizes trends, top risky IPs, and a geomap.

![Dashboard](docs/images/dashboard-overview.png)

## What this repo shows
- OSINT collectors (OTX/VT/Shodan/AbuseIPDB + feeds)
- Postgres schema with JSONB for `geo`/`extra`
- Enrichment pipeline + scheduler
- FastAPI endpoints
- Grafana dashboard (JSON in `grafana/dashboards/ti_basic.json`)

## Quickstart (macOS)
```bash
brew services start postgresql@16
createdb ti_db && psql -d ti_db -c "CREATE USER ti_user WITH PASSWORD 'ti_pass'; GRANT ALL PRIVILEGES ON DATABASE ti_db TO ti_user;"
pip3 install -r requirements.txt --user
cp .env.example .env   # add your API keys (do NOT commit .env)
uvicorn app.main:app --host 0.0.0.0 --port 8000

# .env template (no secrets)
cat > .env.example <<'EOF'
SHODAN_API_KEY=
VT_API_KEY=
OTX_API_KEY=
ABUSEIPDB_API_KEY=

DB_URL=postgresql+psycopg2://ti_user:ti_pass@localhost:5432/ti_db
APP_SECRET=change-me

SHODAN_SEARCH_QUERY='port:80 country:US'
SHODAN_SEARCH_LIMIT=50
SCHED_INTERVAL_MIN=5
