from sqlalchemy import Column, Integer, String, DateTime, Text

from src.db import Base


class CVERecord(Base):
    __tablename__ = 'cve_records'

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, nullable=False)
    published_date = Column(DateTime, nullable=False)
    last_modified_date = Column(DateTime, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    problem_types = Column(Text, nullable=True)
