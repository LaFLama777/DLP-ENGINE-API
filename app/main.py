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
from fastapi import Header
from typing import Optional
import hashlib
import hmac

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
            # Handle Logic App wrapper structure
            actual_incident = incident_payload
            
            # Check if payload is wrapped (from Logic App)
            if "object" in incident_payload and "properties" not in incident_payload:
                logger.info("Detected Logic App wrapper - extracting incident object")
                actual_incident = incident_payload["object"]
            
            # Extract properties and related entities
            properties = actual_incident.get("properties", {})
            related_entities = properties.get("relatedEntities", [])
            
            logger.info(f"Processing incident with {len(related_entities)} related entities")
            
            # Extract user UPN
            user_upn = None
            for entity in related_entities:
                if entity.get("kind") == "Account":
                    entity_props = entity.get("properties", {})
                    additional_data = entity_props.get("additionalData", {})
                    
                    # Try to get UserPrincipalName from additionalData
                    user_upn = additional_data.get("UserPrincipalName")
                    
                    # Fallback: construct from accountName and upnSuffix if not found
                    if not user_upn:
                        account_name = additional_data.get("AccountName") or entity_props.get("accountName")
                        upn_suffix = entity_props.get("upnSuffix")
                        if account_name and upn_suffix:
                            user_upn = f"{account_name}@{upn_suffix}"
                            logger.info(f"Constructed UPN from components: {user_upn}")
                    
                    if user_upn:
                        logger.info(f"Found user UPN: {user_upn}")
                        break
            
            # Extract file name
            file_name = None
            for entity in related_entities:
                if entity.get("kind") == "File":
                    file_name = entity.get("properties", {}).get("fileName", "").replace("%20", " ")
                    if file_name:
                        logger.info(f"Found file name: {file_name}")
                    break
            
            # Log warning if user UPN not found
            if not user_upn:
                logger.warning("User UPN not found in incident payload!")
            
            return {
                "incident_id": actual_incident.get("name", ""),
                "user_upn": user_upn,
                "incident_title": properties.get("title", ""),
                "severity": properties.get("severity", "Medium"),
                "file_name": file_name,
                "created_time": properties.get("createdTimeUtc", ""),
                "file_sensitivity": "Confidential"
            }
        except Exception as e:
            logger.error(f"Error parsing incident: {e}")
            logger.error(f"Payload structure: {list(incident_payload.keys())}")
            raise

# ============================================================================
# EMAIL NOTIFICATION SETUP - IMPROVED ERROR HANDLING
# ============================================================================
EMAIL_ENABLED = False
GraphEmailNotificationService = None

try:
    # Try to import the Graph email service
    from email_notifications import (
        GraphEmailNotificationService,
        send_violation_email,
        send_socialization_email
    )
    EMAIL_ENABLED = True
    logger.info("✅ Graph Email notifications enabled")
except ImportError as e:
    logger.error(f"❌ Failed to import email_notifications: {e}")
    logger.error(f"   Make sure email_notifications.py exists in the root directory")
    logger.error(f"   Current directory: {os.getcwd()}")
    logger.error(f"   Files in directory: {os.listdir('.')}")
    EMAIL_ENABLED = False
except Exception as e:
    logger.error(f"❌ Unexpected error importing email notifications: {e}")
    logger.error(f"   Traceback: {traceback.format_exc()}")
    EMAIL_ENABLED = False

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
        db.execute(text("SELECT 1"))
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
            "email_notifications": EMAIL_ENABLED,
            "email_service": "Graph API" if EMAIL_ENABLED else "Disabled"
        }
    }


@app.post("/check-email")
async def check_email(request: Request, db: Session = Depends(get_db)):
    """Check email content for sensitive data"""
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
                    await send_violation_email(
                        recipient=sender,
                        violation_types=detection_result["violation_types"],
                        violation_count=violation_count,
                        blocked_content=content
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
    """Process Sentinel incident - Called by Logic App"""
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
        
        # Detect violation types
        violation_types = ["Sensitive Data"]
        
        # Send email notification if enabled
        email_sent = False
        if EMAIL_ENABLED and GraphEmailNotificationService:
            try:
                logger.info(f"📧 Attempting to send email notification to {user_upn}")
                
                email_service = GraphEmailNotificationService()
                result = await email_service.send_violation_notification(
                    recipient=user_upn,
                    violation_types=violation_types,
                    violation_count=new_offense_count,
                    blocked_content_summary=parsed_incident.get("incident_title"),
                    incident_title=parsed_incident["incident_title"],
                    file_name=parsed_incident.get("file_name")
                )
                
                if result:
                    email_sent = True
                    logger.info(f"✅ Email notification sent to {user_upn}")
                else:
                    logger.error(f"❌ Email notification failed for {user_upn}")
                    
            except Exception as e:
                logger.error(f"❌ Failed to send email notification: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
        else:
            logger.warning(f"⚠️ Email notifications disabled - skipping email to {user_upn}")
        
        # Send socialization email if threshold reached
        socialization_sent = False
        if EMAIL_ENABLED and send_socialization_flag and GraphEmailNotificationService:
            try:
                email_service = GraphEmailNotificationService()
                await email_service.send_socialization_invitation(user_upn, new_offense_count)
                socialization_sent = True
                logger.info(f"✓ Socialization email sent to {user_upn}")
            except Exception as e:
                logger.error(f"Failed to send socialization email: {e}")
        
        # Revoke account if threshold reached
        account_revoked = False
        if should_revoke:
            logger.info(f"🚨 CRITICAL: User has {new_offense_count} violations - triggering account revocation")
            try:
                revoke_result = await perform_hard_block(user_upn)
                if revoke_result:
                    account_revoked = True
                    logger.info(f"✅ Account successfully revoked for {user_upn}")
                else:
                    logger.error(f"❌ Account revocation returned False for {user_upn}")
            except Exception as e:
                logger.error(f"❌ Failed to revoke account for {user_upn}: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
        
        # Send admin alert if high risk
        admin_notified = False
        if EMAIL_ENABLED and new_offense_count >= 3 and GraphEmailNotificationService:
            try:
                email_service = GraphEmailNotificationService()
                await email_service.send_admin_alert(
                    user=user_upn,
                    incident_title=parsed_incident["incident_title"],
                    violation_count=new_offense_count,
                    action_taken="Account Revoked" if account_revoked else "Warning Sent",
                    violation_types=violation_types,
                    file_name=parsed_incident.get("file_name")
                )
                admin_notified = True
                logger.info(f"✓ Admin alert sent for {user_upn}")
            except Exception as e:
                logger.error(f"Failed to send admin alert: {e}")
        
        # Return response
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
                "teams_alert_sent": False
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
@app.get("/webhook/test")
async def test_webhook():
    """Test endpoint - verify webhook is accessible"""
    return {
        "status": "online",
        "service": "DLP Remediation Engine",
        "version": "2.0.0",
        "endpoints": {
            "eventgrid": "/webhook/eventgrid",
            "purview": "/webhook/purview",
            "test": "/webhook/test"
        },
        "timestamp": datetime.utcnow().isoformat(),
        "message": "Webhook service is ready"
    }


@app.post("/webhook/purview")
async def purview_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Microsoft Purview DLP Webhook
    Receives alerts directly from Purview DLP policies
    """
    try:
        payload = await request.json()
        logger.info("=" * 80)
        logger.info("📨 PURVIEW WEBHOOK RECEIVED")
        logger.info(f"Payload keys: {list(payload.keys())}")
        
        # Log full payload for debugging
        logger.info(f"Full payload: {payload}")
        
        # Purview DLP payload structure
        alert_data = payload.get("AlertData", {})
        
        # Extract user and incident info
        user_upn = alert_data.get("User") or payload.get("User")
        incident_title = alert_data.get("Title") or payload.get("Title", "DLP Policy Violation")
        severity = alert_data.get("Severity", "High")
        file_name = alert_data.get("FileName") or payload.get("FileName")
        
        logger.info(f"User: {user_upn}")
        logger.info(f"Incident: {incident_title}")
        
        if not user_upn:
            logger.error("❌ User UPN not found in Purview payload")
            return {"status": "error", "message": "User UPN required"}
        
        # Get user details
        user_details = await get_user_details(user_upn)
        if not user_details:
            user_details = {"displayName": "Unknown", "department": "Unknown", "jobTitle": "Unknown"}
        
        # Get offense history
        offense_count = get_offense_count(db, user_upn)
        
        # Create contexts for decision engine
        incident_ctx = IncidentContext(severity=severity)
        user_ctx = UserContext(department=user_details.get("department", "Unknown"))
        file_ctx = FileContext(sensitivity_label="Confidential")
        offense_hist = OffenseHistory(previous_offenses=offense_count)
        
        # Assess risk
        assessment = decision_engine.assess_risk(incident_ctx, user_ctx, file_ctx, offense_hist)
        
        # Log offense
        log_offense(db, user_upn, incident_title)
        new_offense_count = offense_count + 1
        
        # Determine actions
        should_revoke = new_offense_count >= 3
        violation_types = ["Sensitive Data", "DLP Policy Violation"]
        
        # Send email notification
        email_sent = False
        if EMAIL_ENABLED and GraphEmailNotificationService:
            try:
                logger.info(f"📧 Sending email to {user_upn}")
                email_service = GraphEmailNotificationService()
                result = await email_service.send_violation_notification(
                    recipient=user_upn,
                    violation_types=violation_types,
                    violation_count=new_offense_count,
                    blocked_content_summary=incident_title,
                    incident_title=incident_title,
                    file_name=file_name
                )
                email_sent = result
                logger.info(f"✅ Email sent: {email_sent}")
            except Exception as e:
                logger.error(f"❌ Email failed: {e}")
        
        # Revoke account if threshold reached
        account_revoked = False
        if should_revoke:
            try:
                logger.info(f"🚨 Revoking account for {user_upn}")
                revoke_result = await perform_hard_block(user_upn)
                account_revoked = revoke_result
                logger.info(f"✅ Account revoked: {account_revoked}")
            except Exception as e:
                logger.error(f"❌ Revocation failed: {e}")
        
        # Send admin alert
        admin_notified = False
        if EMAIL_ENABLED and new_offense_count >= 3 and GraphEmailNotificationService:
            try:
                email_service = GraphEmailNotificationService()
                await email_service.send_admin_alert(
                    user=user_upn,
                    incident_title=incident_title,
                    violation_count=new_offense_count,
                    action_taken="Account Revoked" if account_revoked else "Warning Sent",
                    violation_types=violation_types,
                    file_name=file_name
                )
                admin_notified = True
            except Exception as e:
                logger.error(f"Admin alert failed: {e}")
        
        response = {
            "status": "success",
            "incident_id": payload.get("CorrelationId", "unknown"),
            "user": user_upn,
            "offense_count": new_offense_count,
            "risk_score": assessment.score if assessment else 0,
            "risk_level": assessment.risk_level if assessment else "Unknown",
            "actions": {
                "email_sent": email_sent,
                "account_revoked": account_revoked,
                "admin_notified": admin_notified
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        logger.info(f"✅ Purview webhook processed: {response}")
        logger.info("=" * 80)
        
        return response
        
    except Exception as e:
        logger.error(f"❌ Purview webhook error: {e}")
        logger.error(traceback.format_exc())
        return JSONResponse(
            content={"error": str(e), "timestamp": datetime.utcnow().isoformat()},
            status_code=500
        )


@app.post("/webhook/eventgrid")
async def event_grid_webhook(
    request: Request,
    aeg_event_type: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    Azure Event Grid webhook
    Receives events from Sentinel via Event Grid
    """
    try:
        payload = await request.json()
        logger.info(f"📨 Event Grid webhook: {aeg_event_type}")
        
        # Handle subscription validation
        if aeg_event_type == "SubscriptionValidation":
            validation_code = payload[0]["data"]["validationCode"]
            logger.info(f"✅ Validation code: {validation_code}")
            return {"validationResponse": validation_code}
        
        # Process events
        results = []
        for event in payload:
            try:
                event_type = event.get("eventType", "")
                
                if "SecurityInsights" in event_type or "Incident" in event_type:
                    incident_data = event.get("data", {})
                    
                    # Parse and process (same as /remediate)
                    parsed_incident = SentinelIncidentParser.parse(incident_data)
                    user_upn = parsed_incident["user_upn"]
                    
                    if not user_upn:
                        continue
                    
                    # Get offense count
                    offense_count = get_offense_count(db, user_upn)
                    
                    # Log offense
                    log_offense(db, user_upn, parsed_incident["incident_title"])
                    new_offense_count = offense_count + 1
                    
                    # Send notification
                    email_sent = False
                    if EMAIL_ENABLED and GraphEmailNotificationService:
                        try:
                            email_service = GraphEmailNotificationService()
                            result = await email_service.send_violation_notification(
                                recipient=user_upn,
                                violation_types=["Sensitive Data"],
                                violation_count=new_offense_count,
                                incident_title=parsed_incident["incident_title"],
                                file_name=parsed_incident.get("file_name")
                            )
                            email_sent = result
                        except Exception as e:
                            logger.error(f"Email failed: {e}")
                    
                    results.append({
                        "incident_id": parsed_incident["incident_id"],
                        "user": user_upn,
                        "offense_count": new_offense_count,
                        "email_sent": email_sent
                    })
            
            except Exception as e:
                logger.error(f"Event processing error: {e}")
                results.append({"error": str(e)})
        
        return {"status": "success", "processed": len(results), "results": results}
        
    except Exception as e:
        logger.error(f"Event Grid webhook error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/webhook/status")
async def webhook_status():
    """Get webhook service status"""
    return {
        "service": "DLP Webhook Service",
        "status": "online",
        "endpoints": {
            "test": {
                "path": "/webhook/test",
                "method": "GET",
                "description": "Test endpoint connectivity"
            },
            "purview": {
                "path": "/webhook/purview",
                "method": "POST",
                "description": "Receive alerts from Microsoft Purview DLP"
            },
            "eventgrid": {
                "path": "/webhook/eventgrid",
                "method": "POST",
                "description": "Receive events from Azure Event Grid (Sentinel)"
            }
        },
        "email_notifications": EMAIL_ENABLED,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.on_event("startup")
async def startup():
    logger.info("=" * 80)
    logger.info("DLP REMEDIATION ENGINE v2.0 STARTING")
    logger.info("=" * 80)
    logger.info("Integration: Azure Logic App → API → Database/Email")
    logger.info("Teams Alerts: Handled by Logic App")
    logger.info(f"Email Notifications: {'✅ Enabled (Graph API)' if EMAIL_ENABLED else '❌ Disabled'}")
    if EMAIL_ENABLED:
        logger.info("Email Service: Microsoft Graph API")
    logger.info("=" * 80)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)