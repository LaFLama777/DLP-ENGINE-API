from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, Request, HTTPException, Depends
from sqlalchemy.orm import Session
import json
from datetime import datetime

# meng impor file yang sudah dibuat
from .services import SentinelIncidentParser, TeamsNotificationService, asdict
from . import database, graph_client
from .decision_engine import (
    AdvancedDecisionEngine,
    IncidentContext,
    UserContext,
    FileContext,
    OffenseHistory,
)

from dotenv import load_dotenv
load_dotenv()

database.create_db_and_tables()
app = FastAPI(title="Adaptive DLP Remediation Engine")

engine = AdvancedDecisionEngine(enable_logging=True)
# graph_client_instance = graph_client.get_graph_client()
# teams_service = TeamsNotificationService(graph_client_instance)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Endpoint Utama untuk di integrasi ---
@app.post("/remediate")
async def process_sentinel_incident(request: Request, db: Session = Depends(get_db)):
    try:
        incident_data = await request.json()
        
        # 1. PARSE: Mengubah data mentah dari Sentinel menjadi objek yang terstruktur
        parsed_incident = SentinelIncidentParser.parse_incident(incident_data)
        user_upn = parsed_incident.user_principal_name
        
        if not user_upn:
            raise HTTPException(status_code=400, detail="User UPN tidak ditemukan di payload insiden.")

        # 2. GATHER CONTEXT: Kumpulkan semua informasi yang dibutuhkan oleh Decision Engine
        
        # 2a. Konteks Insiden
        incident_context = IncidentContext(
            incident_id=parsed_incident.incident_id,
            incident_severity=parsed_incident.severity,
            incident_type="Data Exfiltration",
            destination="External", 
            timestamp=datetime.fromisoformat(parsed_incident.created_time.replace("Z", "+00:00")),
            source_ip="N/A", 
            user_agent="N/A"
        )

        # 2b. Konteks User dari Graph API
        user_details_from_graph = await graph_client.get_user_details(user_upn)
        user_context = UserContext(
            user_id=user_upn, 
            department=user_details_from_graph.get("department", "Unknown"),
            role=user_details_from_graph.get("jobTitle", "Unknown"),
            job_title=user_details_from_graph.get("jobTitle", "Unknown"),
        )
        
        # 2c. Konteks File (Placeholder)
        file_context = FileContext(
            file_name=parsed_incident.file_name or "N/A",
            file_size_mb=10, 
            sensitivity_label="Confidential", 
            file_type=parsed_incident.file_name.split('.')[-1] if parsed_incident.file_name else "N/A",
            classification_tags=[], 
        )

        # 2d. Riwayat Pelanggaran dari Database
        offense_history = OffenseHistory(
            total_offenses=database.get_offense_count(db, user_upn),
            offenses_last_30_days=0, 
            offenses_last_90_days=0, 
            last_offense_date=None, 
            previous_risk_levels=[],
            completed_training=False
        )

        # 3. ASSESS RISK: Panggil "otak" decision engine
        assessment = engine.assess_risk(
            incident=incident_context,
            user=user_context,
            file=file_context,
            history=offense_history
        )
        
        # 4. LOG & NOTIFY: Kirim notifikasi dan catat pelanggaran
        print("Mengirim notifikasi ke Teams...")
        # await teams_service.send_remediation_notification(assessment)
        
        # MenCatat pelanggaran baru ke database
        database.log_offense(db, user_upn, parsed_incident.title)
        
        # 5. ACT: Lakukan aksi remediasi (masih placeholder)
        print(f"Aksi yang direkomendasikan: {assessment.remediation_action.value}")

        return asdict(assessment) 

    except Exception as e:
        print(f"Terjadi error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
def read_root():
    return {"status": "OK"}