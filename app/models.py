from sqlalchemy import Column, Integer, BigInteger, Text, JSON, ForeignKey, ARRAY, TIMESTAMP, func
from sqlalchemy.dialects.postgresql import ENUM as PGEnum
from .db import Base
import enum

class IocType(str, enum.Enum):
    ip = "ip"; domain = "domain"; url = "url"; hash = "hash"

class Source(Base):
    __tablename__ = "sources"
    id = Column(Integer, primary_key=True)
    name = Column(Text, unique=True, nullable=False)

class Indicator(Base):
    __tablename__ = "indicators"
    id = Column(BigInteger, primary_key=True)
    indicator = Column(Text, nullable=False)
    type = Column(PGEnum(IocType, name="ioc_type"), nullable=False)
    reputation_score = Column(Integer)
    categories = Column(ARRAY(Text))
    first_seen = Column(TIMESTAMP(timezone=True), server_default=func.now())
    last_seen = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())
    geo = Column(JSON)
    extra = Column(JSON)
    source_id = Column(Integer, ForeignKey("sources.id"))
