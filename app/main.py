from fastapi import FastAPI
# 'BaseModel' digunakan untuk mendefinisikan struktur data
from pydantic import BaseModel

# --- DEKLARASI STRUKTUR DATA ---
# Kita memberitahu API kita untuk mengharapkan data JSON dengan format seperti ini
# dari Logic App. Kamu bisa menambahkan field lain nanti.
class IncidentPayload(BaseModel):
    incident_title: str
    user_principal_name: str
    severity: str

# Inisialisasi aplikasi
app = FastAPI(title="DLP Remediation Engine")

# --- ENDPOINT BARU KITA ---
# @app.post artinya endpoint ini menerima request dengan metode POST
@app.post("/remediate")
def remediate_incident(payload: IncidentPayload):
    """
    Endpoint ini akan menerima data insiden dari Logic App.
    Untuk saat ini, kita hanya akan mencetak datanya ke terminal.
    """
    print("--- Menerima Insiden Baru ---")
    print(f"Judul Insiden: {payload.incident_title}")
    print(f"User Terlibat: {payload.user_principal_name}")
    print(f"Severity: {payload.severity}")
    print("--------------------------")
    
    # Nanti, logika remediasi (block user, dll.) akan ada di sini.
    
    return {"status": "success", "message": "Incident received and logged."}

# Endpoint lama untuk health check
@app.get("/")
def read_root():
    return {"status": "OK", "message": "API is running!"}