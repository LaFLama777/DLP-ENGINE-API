from fastapi import FastAPI
from pydantic import BaseModel


class IncidentPayload(BaseModel):
    incident_title: str
    user_principal_name: str
    severity: str

app = FastAPI(title="DLP Remediation Engine")

@app.post("/remediate")
def remediate_incident(payload: IncidentPayload):
    """
    Endpoint ini akan menerima data insiden dari Logic App.
    """
    print("--- Menerima Insiden Baru ---")
    print(f"Judul Insiden: {payload.incident_title}")
    print(f"User Terlibat: {payload.user_principal_name}")
    print(f"Severity: {payload.severity}")
    print("--------------------------")
    return {"status": "success", "message": "Incident received and logged."}

@app.get("/")
def read_root():
    return {"status": "OK", "message": "API is running!"}