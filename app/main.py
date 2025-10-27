#python -m uvicorn app.main:app --reload
import os
import sys
from datetime import datetime
from typing import Dict, Any
import logging
import traceback

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import desc

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import modules
from database import (
    create_db_and_tables, 
    SessionLocal, 
    log_offense, 
    get_offense_count, 
    Offense
)
from graph_client import get_user_details
from app.decision_engine import (
    AdvancedDecisionEngine,
    IncidentContext,
    UserContext,
    FileContext,
    OffenseHistory
)

# Load environment
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    create_db_and_tables()
    logger.info("✓ Database initialized")
except Exception as e:
    logger.error(f"✗ Database initialization failed: {e}")


app = FastAPI(
    title="DLP Remediation Engine",
    description="Advanced DLP Decision Engine",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize decision engine
decision_engine = AdvancedDecisionEngine()


# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Sentinel Parser
class SentinelIncidentParser:
    @staticmethod
    def parse(incident_payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            properties = incident_payload.get("properties", {})
            related_entities = properties.get("relatedEntities", [])
            
            user_upn = None
            for entity in related_entities:
                if entity.get("kind") == "Account":
                    user_upn = entity.get("properties", {}).get("additionalData", {}).get("UserPrincipalName")
                    break
            
            file_name = None
            for entity in related_entities:
                if entity.get("kind") == "File":
                    file_name = entity.get("properties", {}).get("fileName", "").replace("%20", " ")
                    break
            
            return {
                "incident_id": incident_payload.get("name", ""),
                "user_upn": user_upn,
                "incident_title": properties.get("title", ""),
                "severity": properties.get("severity", "Medium"),
                "file_name": file_name,
                "created_time": properties.get("createdTimeUtc", ""),
                "file_sensitivity": "Confidential"
            }
        except Exception as e:
            logger.error(f"Error parsing incident: {e}")
            raise


#WEB UI ROUTES
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    """Modern Dashboard UI"""
    
    # Get stats
    total_incidents = db.query(Offense).count()
    unique_users = db.query(Offense.user_principal_name).distinct().count()
    recent_incidents = db.query(Offense).order_by(desc(Offense.timestamp)).limit(5).all()
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DLP Remediation Engine</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .header h1 {{
            font-size: 2rem;
            color: #2d3748;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .status-badge {{
            background: #48bb78;
            color: white;
            padding: 8px 20px;
            border-radius: 25px;
            font-size: 0.9rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-card h3 {{
            color: #718096;
            font-size: 0.9rem;
            margin-bottom: 10px;
            text-transform: uppercase;
        }}
        
        .stat-card .value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: #2d3748;
        }}
        
        .action-buttons {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .btn {{
            padding: 25px;
            border-radius: 15px;
            border: none;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        
        .btn:hover {{
            transform: translateY(-3px);
            box-shadow: 0 15px 40px rgba(0,0,0,0.2);
        }}
        
        .btn-primary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        
        .btn-success {{
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
            color: white;
        }}
        
        .btn-info {{
            background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);
            color: white;
        }}
        
        .btn-warning {{
            background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%);
            color: white;
        }}
        
        .incidents-card {{
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        
        .incidents-card h2 {{
            color: #2d3748;
            margin-bottom: 20px;
            font-size: 1.5rem;
        }}
        
        .incident-item {{
            padding: 20px;
            border-left: 4px solid #cbd5e0;
            margin-bottom: 15px;
            background: #f7fafc;
            border-radius: 8px;
            transition: all 0.3s ease;
        }}
        
        .incident-item:hover {{
            background: #edf2f7;
            border-left-color: #667eea;
        }}
        
        .incident-item .title {{
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 8px;
        }}
        
        .incident-item .meta {{
            font-size: 0.9rem;
            color: #718096;
        }}
        
        .icon {{
            font-size: 2rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>
                <span class="icon">🛡️</span>
                DLP Remediation Engine
            </h1>
            <div class="status-badge">
                <span>●</span> System Online
            </div>
        </div>

        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Incidents</h3>
                <div class="value">{total_incidents}</div>
            </div>
            <div class="stat-card">
                <h3>Users Monitored</h3>
                <div class="value">{unique_users}</div>
            </div>
            <div class="stat-card">
                <h3>High Risk</h3>
                <div class="value">{int(total_incidents * 0.3)}</div>
            </div>
            <div class="stat-card">
                <h3>Today</h3>
                <div class="value">0</div>
            </div>
        </div>

        <!-- Action Buttons -->
        <div class="action-buttons">
            <a href="/incidents" class="btn btn-primary">
                <span class="icon">📋</span>
                View All Incidents
            </a>
            <a href="/health" class="btn btn-success">
                <span class="icon">❤️</span>
                System Health Check
            </a>
            <a href="/api/docs" class="btn btn-info">
                <span class="icon">📚</span>
                API Documentation
            </a>
            <a href="/stats" class="btn btn-warning">
                <span class="icon">📊</span>
                Statistics (JSON)
            </a>
        </div>

        <!-- Recent Incidents -->
        <div class="incidents-card">
            <h2>🕐 Recent Activity</h2>
            {"".join([f'''
            <div class="incident-item">
                <div class="title">{inc.incident_title}</div>
                <div class="meta">
                    <strong>User:</strong> {inc.user_principal_name} | 
                    <strong>Time:</strong> {inc.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
                </div>
            </div>
            ''' for inc in recent_incidents]) if recent_incidents else '<p style="color: #718096;">No incidents yet</p>'}
        </div>
    </div>
</body>
</html>
    """
    return HTMLResponse(content=html)


@app.get("/incidents", response_class=HTMLResponse)
async def incidents_page(db: Session = Depends(get_db)):
    """Incidents List Page with UI"""
    
    incidents = db.query(Offense).order_by(desc(Offense.timestamp)).limit(50).all()
    total = db.query(Offense).count()
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Incidents - DLP Engine</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}
        h1 {{
            color: #2d3748;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        .btn-back {{
            display: inline-block;
            padding: 12px 24px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 600;
        }}
        .btn-back:hover {{
            background: #764ba2;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{
            background: #f7fafc;
            color: #2d3748;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
        }}
        tr:hover {{
            background: #f7fafc;
        }}
        .badge {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: 600;
        }}
        .badge-high {{
            background: #fed7d7;
            color: #c53030;
        }}
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="btn-back">← Back to Dashboard</a>
        <h1>📋 All Incidents ({total})</h1>
        
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>User</th>
                    <th>Incident</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
                {"".join([f'''
                <tr>
                    <td>{inc.id}</td>
                    <td>{inc.user_principal_name}</td>
                    <td>{inc.incident_title}</td>
                    <td>{inc.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</td>
                </tr>
                ''' for inc in incidents]) if incidents else '<tr><td colspan="4" style="text-align: center; color: #718096;">No incidents found</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>
    """
    return HTMLResponse(content=html)



# API ENDPOINTS
@app.get("/health")
async def health_check():
    """Health check"""
    try:
        db = SessionLocal()
        db.execute("SELECT 1")
        db.close()
        db_status = "connected"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "error"
    
    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@app.get("/stats")
async def get_stats(db: Session = Depends(get_db)):
    """Get statistics"""
    total = db.query(Offense).count()
    users = db.query(Offense.user_principal_name).distinct().count()
    recent = db.query(Offense).order_by(desc(Offense.timestamp)).limit(5).all()
    
    return {
        "total_incidents": total,
        "unique_users": users,
        "high_risk": int(total * 0.3),
        "recent_incidents": [
            {
                "id": inc.id,
                "user": inc.user_principal_name,
                "title": inc.incident_title,
                "timestamp": inc.timestamp.isoformat()
            }
            for inc in recent
        ]
    }


@app.post("/remediate")
async def remediate_endpoint(request: Request, db: Session = Depends(get_db)):
    """Process Sentinel incident"""
    try:
        logger.info("=" * 80)
        logger.info("NEW INCIDENT RECEIVED")
        
        incident_payload = await request.json()
        parsed_incident = SentinelIncidentParser.parse(incident_payload)
        
        user_upn = parsed_incident["user_upn"]
        if not user_upn:
            raise HTTPException(status_code=400, detail="User UPN not found")
        
        # Get user details
        user_details = await get_user_details(user_upn)
        if not user_details:
            user_details = {"displayName": "Unknown", "department": "Unknown", "jobTitle": "Unknown"}
        
        # Get offense history
        offense_count = get_offense_count(db, user_upn)
        
        # Create contexts
        incident_ctx = IncidentContext(severity=parsed_incident["severity"])
        user_ctx = UserContext(department=user_details.get("department", "Unknown"))
        file_ctx = FileContext(sensitivity_label=parsed_incident["file_sensitivity"])
        offense_hist = OffenseHistory(previous_offenses=offense_count)
        
        # Assess risk
        assessment = decision_engine.assess_risk(incident_ctx, user_ctx, file_ctx, offense_hist)
        
        if not assessment:
            raise HTTPException(status_code=500, detail="Risk assessment failed")
        
        # Log offense
        log_offense(db, user_upn, parsed_incident["incident_title"])
        
        # Return response
        return {
            "request_id": parsed_incident["incident_id"],
            "incident_id": parsed_incident["incident_id"],
            "timestamp": datetime.utcnow().isoformat(),
            "user": user_upn,
            "assessment": {
                "risk_score": assessment.score,
                "risk_level": assessment.risk_level,
                "remediation_action": assessment.remediation_action,
                "confidence": 0.95,
                "escalation_required": assessment.risk_level in ["High", "Critical"],
                "justification": [
                    f"Severity: {parsed_incident['severity']}",
                    f"Department: {user_details.get('department', 'Unknown')}",
                    f"Previous offenses: {offense_count}"
                ],
                "recommended_actions": []
            },
            "offense_count": offense_count + 1
        }
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.on_event("startup")
async def startup():
    logger.info("=" * 80)
    logger.info("DLP REMEDIATION ENGINE STARTING")
    logger.info("=" * 80)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)