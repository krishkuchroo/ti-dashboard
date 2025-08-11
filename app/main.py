from fastapi import FastAPI, Depends
from sqlalchemy import select, desc, text
from sqlalchemy.orm import Session
from .db import Base, engine, SessionLocal
from .models import Indicator
from .scheduler import start_scheduler

Base.metadata.create_all(bind=engine)
app = FastAPI(title="TI Dashboard API")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

@app.on_event("startup")
def _startup():
    start_scheduler()

@app.get("/health")
def health(): return {"ok": True}

@app.get("/indicators")
def indicators(limit: int=100, db: Session=Depends(get_db)):
    rows = db.execute(select(Indicator).order_by(desc(Indicator.last_seen)).limit(limit)).scalars().all()
    return [ {
        "indicator": r.indicator, "type": r.type.value,
        "score": r.reputation_score, "cats": r.categories,
        "last_seen": r.last_seen, "geo": r.geo
    } for r in rows ]

@app.get("/stats/top")
def top_stats(db: Session=Depends(get_db)):
    rows = db.execute(text("""
        SELECT indicator, COUNT(*) c, MAX(COALESCE(reputation_score,0)) m
        FROM indicators WHERE type='ip'
        GROUP BY indicator ORDER BY c DESC, m DESC LIMIT 20
    """)).fetchall()
    return [{"ip": r[0], "count": r[1], "max_score": r[2]} for r in rows]

@app.get("/search")
def search(q: str, db: Session=Depends(get_db)):
    rows = db.execute(text("""
        SELECT indicator,type,reputation_score
        FROM indicators
        WHERE indicator ILIKE :q
        LIMIT 200
    """), {"q": f"%{q}%"}).fetchall()
    return [{"indicator": r[0], "type": str(r[1]), "score": r[2]} for r in rows]
