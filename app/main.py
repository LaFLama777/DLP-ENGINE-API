#python -m uvicorn app.main:app --reload
import os
import sys
import re
import traceback
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import (
    create_db_and_tables, 
    SessionLocal, 
    log_offense, 
    get_offense_count, 
    Offense
)
from graph_client import get_user_details, perform_hard_block
from app.decision_engine import (
    AdvancedDecisionEngine,
    IncidentContext,
    UserContext,
    FileContext,
    OffenseHistory
)

load_dotenv()

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
    description="Advanced DLP Decision Engine with Email Blocking & Compliance",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

decision_engine = AdvancedDecisionEngine()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Sensitive Data Detection
class SensitiveDataDetector:
    @staticmethod
    def detect_ktp(text: str) -> List[str]:
        """Detect 16-digit KTP numbers"""
        pattern = r'\b\d{16}\b'
        return re.findall(pattern, text)
    
    @staticmethod
    def detect_npwp(text: str) -> List[str]:
        """Detect NPWP with keyword and 15-16 digits"""
        pattern = r'npwp[:\s-]*(\d{15,16})'
        return re.findall(pattern, text, re.IGNORECASE)
    
    @staticmethod
    def detect_employee_id(text: str) -> List[str]:
        """Detect employee ID"""
        pattern = r'\b(EMP|KARY|NIP)[-\s]?\d{4,6}\b'
        return re.findall(pattern, text, re.IGNORECASE)
    
    @staticmethod
    def mask_sensitive_data(text: str) -> str:
        """Mask sensitive data in text"""
        text = re.sub(r'\b(\d{3})\d{10}(\d{3})\b', r'\1***********\2', text)
        text = re.sub(r'(npwp[:\s-]*)(\d{2})\d{11}(\d{2})', r'\1\2***********\3', text, flags=re.IGNORECASE)
        return text
    
    @staticmethod
    def check_sensitive_content(content: str) -> Dict[str, Any]:
        """Check if content contains sensitive data"""
        ktp_found = SensitiveDataDetector.detect_ktp(content)
        npwp_found = SensitiveDataDetector.detect_npwp(content)
        employee_id_found = SensitiveDataDetector.detect_employee_id(content)
        
        has_sensitive = bool(ktp_found or npwp_found or employee_id_found)
        
        violation_types = []
        if ktp_found:
            violation_types.append("KTP")
        if npwp_found:
            violation_types.append("NPWP")
        if employee_id_found:
            violation_types.append("Employee ID")
        
        return {
            "has_sensitive_data": has_sensitive,
            "ktp_count": len(ktp_found),
            "npwp_count": len(npwp_found),
            "employee_id_count": len(employee_id_found),
            "violation_types": violation_types,
            "violations": [
                {"type": "KTP", "count": len(ktp_found)},
                {"type": "NPWP", "count": len(npwp_found)},
                {"type": "Employee ID", "count": len(employee_id_found)}
            ]
        }

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

try:
    from email_notifications import send_violation_email, send_socialization_email, EmailNotificationService
    EMAIL_ENABLED = True
    logger.info("✓ Email notifications enabled")
except ImportError:
    EMAIL_ENABLED = False
    logger.warning("⚠️ Email notifications disabled (email_notifications.py not found)")

# Import UI routes
try:
    from app.ui_routes import router as ui_router
    app.include_router(ui_router)
    logger.info("✓ UI routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ UI routes not loaded: {e}")


@app.get("/health")
async def health_check():
    """Health check endpoint - JSON response"""
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
        "version": "2.0.0",
        "features": {
            "email_blocking": True,
            "teams_alerts": True,
            "sensitive_data_detection": True,
            "account_revocation": True,
            "email_notifications": EMAIL_ENABLED
        }
    }


@app.post("/check-email")
async def check_email(request: Request, db: Session = Depends(get_db)):
    """
    Check email content for sensitive data
    Logic App can call this first before sending
    """
    try:
        payload = await request.json()
        sender = payload.get("sender")
        content = payload.get("content", "")
        
        detection_result = SensitiveDataDetector.check_sensitive_content(content)
        
        if detection_result["has_sensitive_data"]:
            log_offense(db, sender, f"Email blocked - Sensitive data detected")
            violation_count = get_offense_count(db, sender)
            
            # Send email notification if enabled
            if EMAIL_ENABLED:
                try:
                    send_violation_email(
                        recipient=sender,
                        violation_types=detection_result["violation_types"],
                        violation_count=violation_count
                    )
                    logger.info(f"✓ Email notification sent to {sender}")
                except Exception as e:
                    logger.error(f"Failed to send email: {e}")
            
            return {
                "status": "blocked",
                "reason": "Sensitive data detected",
                "violations": detection_result["violations"],
                "violation_types": detection_result["violation_types"],
                "violation_count": violation_count,
                "masked_content": SensitiveDataDetector.mask_sensitive_data(content),
                "action_required": "revoke_signin" if violation_count >= 3 else "warning"
            }
        
        return {"status": "allowed", "message": "No sensitive data detected"}
        
    except Exception as e:
        logger.error(f"Email check error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.post("/remediate")
async def remediate_endpoint(request: Request, db: Session = Depends(get_db)):
    """
    Process Sentinel incident - Called by Logic App
    Logic App will handle Teams notification
    This API handles: detection, logging, email, account revocation
    """
    try:
        logger.info("=" * 80)
        logger.info("NEW INCIDENT RECEIVED FROM LOGIC APP")
        
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
        
        # Create contexts for decision engine
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
        
        # Calculate new offense count
        new_offense_count = offense_count + 1
        should_revoke = new_offense_count >= 3
        send_socialization_flag = new_offense_count in [3, 5]
        
        # Detect violation types (for Logic App)
        violation_types = ["Sensitive Data"]  # Default
        
        # Send email notification if enabled
        email_sent = False
        if EMAIL_ENABLED:
            try:
                send_violation_email(
                    recipient=user_upn,
                    violation_types=violation_types,
                    violation_count=new_offense_count
                )
                email_sent = True
                logger.info(f"✓ Email notification sent to {user_upn}")
            except Exception as e:
                logger.error(f"Failed to send email notification: {e}")
        
        # Send socialization email if threshold reached
        socialization_sent = False
        if EMAIL_ENABLED and send_socialization_flag:
            try:
                send_socialization_email(user_upn, new_offense_count)
                socialization_sent = True
                logger.info(f"✓ Socialization email sent to {user_upn}")
            except Exception as e:
                logger.error(f"Failed to send socialization email: {e}")
        
        # Revoke account if threshold reached
        account_revoked = False
        if should_revoke:
            try:
                await perform_hard_block(user_upn)
                account_revoked = True
                logger.info(f"✓ Account revoked for {user_upn}")
            except Exception as e:
                logger.error(f"Failed to revoke account: {e}")
        
        # Send admin alert if high risk
        admin_notified = False
        if EMAIL_ENABLED and new_offense_count >= 3:
            try:
                email_service = EmailNotificationService()
                email_service.send_admin_alert(
                    user=user_upn,
                    incident_title=parsed_incident["incident_title"],
                    violation_count=new_offense_count,
                    action_taken="Account Revoked" if account_revoked else "Warning Sent"
                )
                admin_notified = True
                logger.info(f"✓ Admin alert sent for {user_upn}")
            except Exception as e:
                logger.error(f"Failed to send admin alert: {e}")
        
        # Return response - Logic App will use this to post to Teams
        response = {
            "request_id": parsed_incident["incident_id"],
            "incident_id": parsed_incident["incident_id"],
            "timestamp": datetime.utcnow().isoformat(),
            "user": user_upn,
            "user_details": {
                "display_name": user_details.get("displayName", "Unknown"),
                "department": user_details.get("department", "Unknown"),
                "job_title": user_details.get("jobTitle", "Unknown")
            },
            "assessment": {
                "risk_score": assessment.score,
                "risk_level": assessment.risk_level,
                "remediation_action": assessment.remediation_action,
                "confidence": 0.95,
                "escalation_required": assessment.risk_level in ["High", "Critical"]
            },
            "offense_count": new_offense_count,
            "violation_types": violation_types,
            "actions_taken": {
                "email_blocked": True,
                "account_revoked": account_revoked,
                "email_notification_sent": email_sent,
                "socialization_sent": socialization_sent,
                "admin_notified": admin_notified,
                "teams_alert_sent": False  # Logic App handles this
            },
            "status": "processed",
            "message": f"Violation processed. User has {new_offense_count} total violations."
        }
        
        logger.info(f"✓ Incident processed for {user_upn}: {new_offense_count} violations")
        return response
        
    except Exception as e:
        logger.error(f"Error processing incident: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return JSONResponse(
            content={
                "error": str(e),
                "status": "failed",
                "timestamp": datetime.utcnow().isoformat()
            }, 
            status_code=500
        )


@app.on_event("startup")
async def startup():
    logger.info("=" * 80)
    logger.info("DLP REMEDIATION ENGINE v2.0 STARTING")
    logger.info("=" * 80)
    logger.info("Integration: Azure Logic App → API → Database/Email")
    logger.info("Teams Alerts: Handled by Logic App")
    logger.info(f"Email Notifications: {'Enabled' if EMAIL_ENABLED else 'Disabled'}")
    logger.info("=" * 80)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)