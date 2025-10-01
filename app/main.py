from fastapi import FastAPI, Request, HTTPException, Depends
from sqlalchemy.orm import Session
import json

from .services import SentinelIncidentParser, asdict
from . import database

# Membuat tabel database saat aplikasi pertama kali dijalankan
database.create_db_and_tables()

app = FastAPI(title="Adaptive DLP Remediation Engine")

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- ENDPOINT KHUSUS UNTUK PENGUJIAN LOGIKA ---
@app.get("/test-logic")
def test_database_logic(db: Session = Depends(get_db)):
    """
    Endpoint ini akan menguji parser DAN database.
    Dia akan mem-parsing insiden, lalu mencatatnya sebagai pelanggaran.
    """
    try:
        with open('sentinel_payload.json', 'r') as f:
            sample_data = json.load(f)

        parsed_incident = SentinelIncidentParser.parse_incident(sample_data)
        user_upn = parsed_incident.user_principal_name

        print("--- Menguji Logika Database ---")

        # Cek jumlah pelanggaran SEBELUM mencatat yang baru
        count_before = database.get_offense_count(db, user_upn)

        # Catat pelanggaran yang baru
        database.log_offense(db, user_upn, parsed_incident.title)

        # Cek jumlah pelanggaran SETELAH mencatat yang baru
        count_after = database.get_offense_count(db, user_upn)

        return {
            "status": "success", 
            "message": "Logika database berhasil diuji! Cek terminal.",
            "user": user_upn,
            "offenses_before": count_before,
            "offenses_after": count_after,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/remediate")
async def process_sentinel_incident(request: Request):
    return {"status": "received"}

@app.get("/")
def read_root():
    return {"status": "OK"}