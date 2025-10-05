import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
import datetime


DATABASE_URL = "sqlite:///./dlp_offenses.db" 

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# table definition buat offense
class Offense(Base):
    __tablename__ = "offenses"
    id = Column(Integer, primary_key=True, index=True)
    user_principal_name = Column(String, index=True)
    incident_title = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

# Fungsi untuk membuat tabel di database jika belum ada
def create_db_and_tables():
    Base.metadata.create_all(bind=engine)

# Fungsi untuk mencatat pelanggaran baru ke database
def log_offense(db, user_upn: str, title: str):
    db_offense = Offense(user_principal_name=user_upn, incident_title=title)
    db.add(db_offense)
    db.commit()
    db.refresh(db_offense)
    print(f"Berhasil mencatat pelanggaran untuk {user_upn}")
    return db_offense

# Fungsi untuk menghitung berapa kali seorang user telah melanggar
def get_offense_count(db, user_upn: str):
    count = db.query(Offense).filter(Offense.user_principal_name == user_upn).count()
    print(f"User {user_upn} memiliki {count} pelanggaran sebelumnya.")
    return count