import os
import sys
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Body
from sqlalchemy.orm import Session
try:
       sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  
except Exception as e:
       raise ImportError(f"Error menambahkan path: {e}")
from database import create_db_and_tables, SessionLocal, log_offense, get_offense_count, Offense
from graph_client import get_user_details, perform_hard_block  # Import Graph client functions
from app.decision_engine import AdvancedDecisionEngine, IncidentContext, UserContext, FileContext, OffenseHistory  # Import decision engine components
from pydantic import BaseModel  # For any custom models if needed


load_dotenv()

create_db_and_tables()

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def remediate_endpoint(incident_payload: dict = Body(..., description="Full Sentinel incident JSON payload"), db: Session = Depends(get_db)):
    try:
        # Step 1: Parse the Sentinel incident payload
        parsed_incident = SentinelIncidentParser.parse(incident_payload)  # Assuming this returns an object with attributes like user_upn, incident_title, severity, file_sensitivity
        
        user_upn = parsed_incident.user_upn  # Extract user UPN from parsed incident
        incident_title = parsed_incident.incident_title  # Extract incident title
        severity = parsed_incident.severity  # e.g., 'High'
        file_sensitivity = parsed_incident.file_sensitivity  # e.g., 'Confidential'
        
        # Step 2: Get the user's offense history from the database
        offense_count = await get_offense_count(db, user_upn)
        
        # Step 3: Get the user's details from Graph API
        user_details = await get_user_details(user_upn)  # Returns a dict with details like {'displayName': ..., 'department': ..., 'jobTitle': ...}
        
        # Step 4: Construct the context objects
        incident_ctx = IncidentContext(severity=severity)
        user_ctx = UserContext(department=user_details.get('department', 'Unknown'))  # Use 'department' from user details
        file_ctx = FileContext(sensitivity_label=file_sensitivity)
        offense_hist = OffenseHistory(previous_offenses=offense_count)
        
        # Step 5: Use AdvancedDecisionEngine to get the RiskAssessment
        engine = AdvancedDecisionEngine()
        assessment = engine.assess_risk(incident_ctx, user_ctx, file_ctx, offense_hist)
        
        # Step 6: Based on the assessment, perform the remediation action
        if assessment.remediation_action == 'Hard Block':
            await perform_hard_block(user_upn)  # Call the hard block function
            # You can add more logic for other actions if needed, e.g., 'Soft Remediation'
        elif assessment.remediation_action == 'Soft Remediation':
            # Implement or call any soft remediation logic here (not specified, so just logging for now)
            print(f"Performing soft remediation for user: {user_upn}")
        else:
            print(f"No remediation action required for user: {user_upn}")
        
        # Step 7: Log the new offense to the database
        await log_offense(db, user_upn, incident_title)
        
        # Step 8: Return the RiskAssessment as JSON
        return assessment  # FastAPI will automatically serialize this as JSON
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing remediation: {str(e)}")

app.post("/remediate")(remediate_endpoint)  # Define the POST endpoint

# GET /incidents endpoint
async def get_incidents(db: Session = Depends(get_db)):
    try:
        offenses = db.query(Offense).all()  # Query all offenses from the database
        # Serialize the offenses to a list of dictionaries for JSON response
        return [{"id": offense.id, "user_principal_name": offense.user_principal_name, "incident_title": offense.incident_title, "timestamp": offense.timestamp.isoformat()} for offense in offenses]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching incidents: {str(e)}")

app.get("/incidents")(get_incidents)  # Define the GET endpoint

# Run the app if this file is executed directly
if __name__ == "__main__":
    import uvicorn
uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)