from fastapi import FastAPI, Request, HTTPException, Depends
from sqlalchemy.orm import Session
import json

# Impor dari file-file yang sudah kita buat
from .services import SentinelIncidentParser, asdict
from . import database, graph_client # Tambahkan graph_client

# Inisialisasi dari .env file (hanya untuk lokal)
from dotenv import load_dotenv
load_dotenv()

database.create_db_and_tables()
app = FastAPI(title="Adaptive DLP Remediation Engine")

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- ENDPOINT PENGUJIAN LOGIKA ---
@app.get("/test-logic")
async def test_full_logic(db: Session = Depends(get_db)): # Tambahkan 'async'
    """
    Endpoint ini akan menguji parser, database, DAN koneksi ke Graph API.
    """
    try:
        with open('sentinel_payload.json', 'r') as f:
            sample_data = json.load(f)

        parsed_incident = SentinelIncidentParser.parse_incident(sample_data)
        user_upn = parsed_incident.user_principal_name

        if not user_upn:
            raise HTTPException(status_code=400, detail="User UPN tidak ditemukan di payload.")

        print("--- Menguji Logika Pengambilan Konteks ---")

        # 1. Mengambil detail user dari Graph API
        user_details = await graph_client.get_user_details(user_upn)
        print("--- Detail User dari Graph API ---")
        print(user_details)
        print("---------------------------------")

        # 2. Cek riwayat pelanggaran dari database
        count_before = database.get_offense_count(db, user_upn)
        database.log_offense(db, user_upn, parsed_incident.title)
        count_after = database.get_offense_count(db, user_upn)

        return {
            "status": "success", 
            "message": "Pengambilan konteks berhasil! Cek terminal.",
            "user_details_from_graph": user_details,
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