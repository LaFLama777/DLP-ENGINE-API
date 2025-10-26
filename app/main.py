import os
import sys
from datetime import datetime
from typing import Dict, Any
import logging
import traceback
#python -m uvicorn app.main:app --reload
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import local modules
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
    OffenseHistory,
    RiskAssessment
)

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize database
try:
    create_db_and_tables()
    logger.info("✓ Database initialized successfully")
except Exception as e:
    logger.error(f"✗ Database initialization failed: {e}")

# Initialize FastAPI app
app = FastAPI(
    title="DLP Remediation Engine",
    description="Advanced DLP Decision Engine with Risk Assessment",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize decision engine
decision_engine = AdvancedDecisionEngine()


# ============================================================================
# DATABASE DEPENDENCY
# ============================================================================

def get_db():
    """Database session dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# SENTINEL INCIDENT PARSER
# ============================================================================

class SentinelIncidentParser:
    """Parser for Microsoft Sentinel incident payloads"""
    
    @staticmethod
    def parse(incident_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Sentinel incident payload
        
        Args:
            incident_payload: Raw Sentinel incident JSON
            
        Returns:
            Dict with parsed incident data
        """
        try:
            properties = incident_payload.get("properties", {})
            related_entities = properties.get("relatedEntities", [])
            
            # Extract user UPN
            user_upn = None
            for entity in related_entities:
                if entity.get("kind") == "Account":
                    user_upn = entity.get("properties", {}).get("additionalData", {}).get("UserPrincipalName")
                    break
            
            # Extract file info
            file_name = None
            file_directory = None
            for entity in related_entities:
                if entity.get("kind") == "File":
                    props = entity.get("properties", {})
                    file_name = props.get("fileName", "").replace("%20", " ")
                    file_directory = props.get("directory")
                    break
            
            # Extract application info
            app_name = None
            for entity in related_entities:
                if entity.get("kind") == "CloudApplication":
                    app_name = entity.get("properties", {}).get("appName")
                    break
            
            return {
                "incident_id": incident_payload.get("name", ""),
                "user_upn": user_upn,
                "incident_title": properties.get("title", ""),
                "severity": properties.get("severity", "Medium"),
                "status": properties.get("status", "New"),
                "file_name": file_name,
                "file_directory": file_directory,
                "application_name": app_name,
                "created_time": properties.get("createdTimeUtc", ""),
                "incident_url": properties.get("incidentUrl", ""),
                "file_sensitivity": "Confidential",  # Default, can be enhanced
                "raw_payload": incident_payload
            }
            
        except Exception as e:
            logger.error(f"Error parsing incident: {e}")
            raise


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint with basic info"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>DLP Remediation Engine</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            }
            .container {
                background: rgba(255, 255, 255, 0.1);
                padding: 30px;
                border-radius: 10px;
                backdrop-filter: blur(10px);
            }
            h1 { margin-top: 0; }
            .status { color: #48bb78; }
            a {
                color: #ffd700;
                text-decoration: none;
                font-weight: bold;
            }
            a:hover { text-decoration: underline; }
            .endpoint {
                background: rgba(0, 0, 0, 0.2);
                padding: 10px;
                margin: 10px 0;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ DLP Remediation Engine</h1>
            <p class="status">✅ System Online</p>
            <p>Version: 1.0.0</p>
            
            <h2>Available Endpoints:</h2>
            <div class="endpoint">
                <strong>GET</strong> <a href="/health">/health</a> - Health check
            </div>
            <div class="endpoint">
                <strong>GET</strong> <a href="/incidents">/incidents</a> - List all incidents
            </div>
            <div class="endpoint">
                <strong>POST</strong> /remediate - Process Sentinel incident
            </div>
            <div class="endpoint">
                <strong>GET</strong> <a href="/api/docs">/api/docs</a> - API Documentation
            </div>
            
            <p style="margin-top: 30px;">
                <small>Powered by FastAPI | Microsoft Graph API | Azure Sentinel</small>
            </p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        db_status = "connected"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = f"error"
    
    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@app.post("/remediate")
async def remediate_endpoint(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Main remediation endpoint - processes Sentinel incidents
    
    Expected payload: Microsoft Sentinel incident JSON
    """
    try:
        logger.info("=" * 80)
        logger.info("NEW INCIDENT RECEIVED")
        logger.info("=" * 80)
        
        # Get incident payload
        incident_payload = await request.json()
        logger.info(f"Payload received: {str(incident_payload)[:200]}...")
        
        # Step 1: Parse the Sentinel incident
        logger.info("Step 1: Parsing incident...")
        parsed_incident = SentinelIncidentParser.parse(incident_payload)
        
        user_upn = parsed_incident["user_upn"]
        if not user_upn:
            raise HTTPException(
                status_code=400,
                detail="User UPN not found in incident payload"
            )
        
        logger.info(f"✓ Incident parsed")
        logger.info(f"  User: {user_upn}")
        logger.info(f"  File: {parsed_incident['file_name']}")
        logger.info(f"  Severity: {parsed_incident['severity']}")
        
        # Step 2: Get user details from Graph API
        logger.info("\nStep 2: Fetching user details from Graph API...")
        user_details = await get_user_details(user_upn)
        if not user_details:
            user_details = {"displayName": "Unknown", "department": "Unknown", "jobTitle": "Unknown"}
            logger.warning("Could not fetch user details from Graph API, using defaults")
        else:
            logger.info(f"✓ User details fetched: {user_details.get('displayName')}")
        
        # Step 3: Get offense history from database
        logger.info("\nStep 3: Checking offense history...")
        offense_count = get_offense_count(db, user_upn)
        logger.info(f"✓ User has {offense_count} previous offenses")
        
        # Step 4: Create context objects for decision engine
        logger.info("\nStep 4: Preparing risk assessment...")
        incident_ctx = IncidentContext(
            severity=parsed_incident["severity"]
        )
        user_ctx = UserContext(
            department=user_details.get("department", "Unknown")
        )
        file_ctx = FileContext(
            sensitivity_label=parsed_incident["file_sensitivity"]
        )
        offense_hist = OffenseHistory(
            previous_offenses=offense_count
        )
        
        # Step 5: Perform risk assessment
        logger.info("\nStep 5: Running risk assessment...")
        assessment = decision_engine.assess_risk(
            incident_ctx,
            user_ctx,
            file_ctx,
            offense_hist
        )
        
        if not assessment:
            raise HTTPException(
                status_code=500,
                detail="Risk assessment failed"
            )
        
        logger.info("\n" + "=" * 80)
        logger.info("RISK ASSESSMENT COMPLETE")
        logger.info("=" * 80)
        logger.info(f"Risk Score: {assessment.score}/100")
        logger.info(f"Risk Level: {assessment.risk_level}")
        logger.info(f"Remediation: {assessment.remediation_action}")
        logger.info("=" * 80)
        
        # Step 6: Log the offense
        logger.info("\nStep 6: Logging offense to database...")
        log_offense(db, user_upn, parsed_incident["incident_title"])
        logger.info("✓ Offense logged")
        
        # Step 7: Prepare response
        response = {
            "request_id": parsed_incident["incident_id"],
            "incident_id": parsed_incident["incident_id"],
            "timestamp": datetime.utcnow().isoformat(),
            "user": user_upn,
            "user_details": user_details,
            "assessment": {
                "risk_score": assessment.score,
                "risk_level": assessment.risk_level,
                "remediation_action": assessment.remediation_action,
                "confidence": 0.95,  # Placeholder
                "escalation_required": assessment.risk_level in ["High", "Critical"],
                "justification": [
                    f"Severity: {parsed_incident['severity']}",
                    f"Department: {user_details.get('department', 'Unknown')}",
                    f"File sensitivity: {parsed_incident['file_sensitivity']}",
                    f"Previous offenses: {offense_count}"
                ],
                "recommended_actions": _get_recommended_actions(assessment)
            },
            "notifications_sent": [],
            "offense_count": offense_count + 1
        }
        
        logger.info("\n✓ Incident processing complete\n")
        return JSONResponse(content=response, status_code=200)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"\n✗ Error processing incident: {str(e)}")
        logger.error(traceback.format_exc())
        return JSONResponse(
            content={
                "error": str(e),
                "detail": "Internal server error",
                "timestamp": datetime.utcnow().isoformat()
            },
            status_code=500
        )


@app.get("/incidents")
async def get_incidents(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Get list of incidents from database"""
    try:
        # Query offenses with pagination
        offenses = db.query(Offense).order_by(
            Offense.timestamp.desc()
        ).limit(limit).offset(offset).all()
        
        total_count = db.query(Offense).count()
        
        incidents = [
            {
                "id": offense.id,
                "user_principal_name": offense.user_principal_name,
                "incident_title": offense.incident_title,
                "timestamp": offense.timestamp.isoformat()
            }
            for offense in offenses
        ]
        
        return {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "count": len(incidents),
            "incidents": incidents
        }
        
    except Exception as e:
        logger.error(f"Error fetching incidents: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching incidents: {str(e)}"
        )


@app.get("/stats")
async def get_statistics(db: Session = Depends(get_db)):
    """Get dashboard statistics"""
    try:
        total_incidents = db.query(Offense).count()
        
        # Get unique users
        unique_users = db.query(Offense.user_principal_name).distinct().count()
        
        # Get recent incidents
        recent = db.query(Offense).order_by(
            Offense.timestamp.desc()
        ).limit(5).all()
        
        return {
            "total_incidents": total_incidents,
            "unique_users": unique_users,
            "high_risk_incidents": int(total_incidents * 0.3),  # Estimate
            "incidents_today": 0,  # TODO: Calculate
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
    except Exception as e:
        logger.error(f"Error fetching statistics: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _get_recommended_actions(assessment: RiskAssessment) -> list:
    """Get recommended actions based on risk assessment"""
    actions = []
    
    if assessment.remediation_action == "Hard Block":
        actions = [
            "Immediately revoke user session",
            "Disable user account temporarily",
            "Notify Security Operations Center",
            "Initiate security investigation",
            "Contact user's manager"
        ]
    elif assessment.remediation_action == "Soft Remediation":
        actions = [
            "Restrict file sharing permissions",
            "Send warning to user",
            "Notify user's manager",
            "Log incident for review"
        ]
    else:  # Warn & Educate
        actions = [
            "Send policy reminder to user",
            "Assign security awareness training",
            "Log warning for tracking"
        ]
    
    return actions


# ============================================================================
# APPLICATION STARTUP
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Run on application startup"""
    logger.info("=" * 80)
    logger.info("DLP REMEDIATION ENGINE STARTING")
    logger.info("=" * 80)
    logger.info(f"Version: 1.0.0")
    logger.info(f"Environment: {os.getenv('ENVIRONMENT', 'production')}")
    logger.info(f"Database: Supabase (PostgreSQL)")
    logger.info("=" * 80)


@app.on_event("shutdown")
async def shutdown_event():
    """Run on application shutdown"""
    logger.info("DLP Remediation Engine shutting down...")


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Global exception: {str(exc)}")
    logger.error(traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "path": str(request.url)
        }
    )


# Run the app if executed directly (for local testing)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)