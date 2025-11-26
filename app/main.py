"""
DLP Remediation Engine - Main Application

Integrated with all refactored modules:
- Centralized configuration (config.py)
- Pydantic models (models.py)
- Custom exceptions (exceptions.py)
- Caching layer (cache_service.py)
- Middleware (middleware.py)
- Professional logging (logging_config.py)
- Sensitive data detection (sensitive_data.py)

Usage:
    uvicorn app.main:app --reload
"""

import os
import sys
import traceback
from datetime import datetime
from typing import Optional
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ============================================================================
# STEP 1: INITIALIZE LOGGING FIRST (before any other imports)
# ============================================================================
from logging_config import setup_logging
from config import settings

setup_logging(
    log_level=settings.LOG_LEVEL,
    log_file=settings.LOG_FILE,
    use_json_format=settings.LOG_JSON_FORMAT,
    use_colors=True,
    max_bytes=settings.LOG_MAX_BYTES,
    backup_count=settings.LOG_BACKUP_COUNT
)

logger = logging.getLogger(__name__)

# ============================================================================
# STEP 2: IMPORT DEPENDENCIES
# ============================================================================
from fastapi import FastAPI, Depends, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

# Our modules
from models import (
    EmailCheckRequest,
    EmailCheckResponse,
    RemediationRequest,
    RemediationResponse,
    HealthCheckResponse,
    RiskLevel,
    ViolationType
)
from exceptions import (
    DLPEngineException,
    UserNotFoundException,
    GraphAPIException,
    DatabaseException,
    EmailSendException
)
from middleware import (
    RequestIDMiddleware,
    LoggingMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware
)
from sensitive_data import SensitiveDataDetector
from database import (
    create_db_and_tables,
    SessionLocal,
    log_offense_and_get_count,
    get_offense_count,
    Offense
)
from graph_client import get_user_details, perform_hard_block
from email_notifications import GraphEmailNotificationService
from app.decision_engine import (
    AdvancedDecisionEngine,
    IncidentContext,
    UserContext,
    FileContext,
    OffenseHistory
)

# ============================================================================
# STEP 3: INITIALIZE DATABASE
# ============================================================================
try:
    create_db_and_tables()
    logger.info("✓ Database initialized")
except Exception as e:
    logger.error(f"✗ Database initialization failed: {e}", exc_info=True)

# ============================================================================
# STEP 4: CREATE FASTAPI APP WITH CONFIG
# ============================================================================
app = FastAPI(
    title=settings.API_TITLE,
    description=settings.API_DESCRIPTION,
    version=settings.API_VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# ============================================================================
# STEP 5: ADD MIDDLEWARE (order matters!)
# ============================================================================
# Security headers (first)
app.add_middleware(SecurityHeadersMiddleware)

# Request size limit (10MB in bytes)
app.add_middleware(RequestSizeLimitMiddleware, max_size=10 * 1024 * 1024)

# Logging middleware
app.add_middleware(LoggingMiddleware)

# Request ID tracking (last)
app.add_middleware(RequestIDMiddleware)

# CORS (if needed)
if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# ============================================================================
# STEP 6: INITIALIZE SERVICES
# ============================================================================
decision_engine = AdvancedDecisionEngine()

# Initialize email service
EMAIL_ENABLED = settings.FEATURE_EMAIL_NOTIFICATIONS
try:
    email_service = GraphEmailNotificationService()
    logger.info("✅ Graph Email notifications enabled")
except Exception as e:
    logger.error(f"❌ Failed to initialize email service: {e}")
    EMAIL_ENABLED = False

# ============================================================================
# STEP 7: DEPENDENCIES
# ============================================================================
def get_db():
    """Database session dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============================================================================
# STEP 8: EXCEPTION HANDLERS
# ============================================================================
@app.exception_handler(DLPEngineException)
async def dlp_exception_handler(request: Request, exc: DLPEngineException):
    """Handle all DLP engine exceptions"""
    logger.error(f"DLP Exception: {exc.message}", exc_info=exc.original_exception)
    return JSONResponse(
        status_code=400,
        content=exc.to_dict()
    )

@app.exception_handler(UserNotFoundException)
async def user_not_found_handler(request: Request, exc: UserNotFoundException):
    """Handle user not found errors"""
    logger.warning(f"User not found: {exc.message}")
    return JSONResponse(
        status_code=404,
        content=exc.to_dict()
    )

@app.exception_handler(GraphAPIException)
async def graph_api_handler(request: Request, exc: GraphAPIException):
    """Handle Graph API errors"""
    logger.error(f"Graph API error: {exc.message}", exc_info=exc.original_exception)
    return JSONResponse(
        status_code=502,
        content=exc.to_dict()
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    logger.error(f"Unexpected error: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc) if settings.LOG_LEVEL == "DEBUG" else "An error occurred",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# ============================================================================
# STEP 9: UTILITY CLASSES
# ============================================================================
class SentinelIncidentParser:
    """Parse Microsoft Sentinel incident payloads"""

    @staticmethod
    def parse(incident_payload: dict) -> dict:
        """
        Parse Sentinel incident payload and extract key information

        Args:
            incident_payload: Raw incident payload from Sentinel

        Returns:
            Parsed incident data dictionary
        """
        try:
            # Handle Logic App wrapper structure
            actual_incident = incident_payload

            # Check if payload is wrapped (from Logic App)
            if "object" in incident_payload and "properties" not in incident_payload:
                logger.debug("Detected Logic App wrapper - extracting incident object")
                actual_incident = incident_payload["object"]

            # Extract properties and related entities
            properties = actual_incident.get("properties", {})
            related_entities = properties.get("relatedEntities", [])

            logger.debug(f"Processing incident with {len(related_entities)} related entities")

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
                            logger.debug(f"Constructed UPN from components: {user_upn}")

                    if user_upn:
                        logger.info(f"Found user UPN: {user_upn}")
                        break

            # Extract file name
            file_name = None
            for entity in related_entities:
                if entity.get("kind") == "File":
                    file_name = entity.get("properties", {}).get("fileName", "").replace("%20", " ")
                    if file_name:
                        logger.debug(f"Found file name: {file_name}")
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
            logger.error(f"Error parsing incident: {e}", exc_info=True)
            logger.debug(f"Payload structure: {list(incident_payload.keys())}")
            raise

# ============================================================================
# STEP 10: API ROUTES
# ============================================================================

@app.get("/", response_model=dict)
async def root():
    """Root endpoint - API information"""
    return {
        "service": "DLP Remediation Engine",
        "version": settings.API_VERSION,
        "status": "online",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "check_email": "/check-email",
            "remediate": "/remediate",
            "webhooks": {
                "purview": "/webhook/purview",
                "eventgrid": "/webhook/eventgrid",
                "test": "/webhook/test"
            }
        },
        "features": {
            "email_notifications": EMAIL_ENABLED,
            "account_revocation": settings.FEATURE_ACCOUNT_REVOCATION,
            "caching": settings.CACHE_ENABLED
        }
    }

@app.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """Health check endpoint with detailed status"""
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        db_status = "healthy"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "unhealthy"

    return HealthCheckResponse(
        status="healthy" if db_status == "healthy" else "degraded",
        timestamp=datetime.utcnow(),
        version=settings.API_VERSION,
        database=db_status,
        features={
            "email_blocking": True,
            "teams_alerts": settings.FEATURE_TEAMS_ALERTS,
            "sensitive_data_detection": True,
            "account_revocation": settings.FEATURE_ACCOUNT_REVOCATION,
            "email_notifications": EMAIL_ENABLED,
            "caching": settings.CACHE_ENABLED
        }
    )

@app.post("/check-email", response_model=EmailCheckResponse)
async def check_email(request: EmailCheckRequest, db: Session = Depends(get_db)):
    """
    Check email content for sensitive data

    Validates email content against DLP policies and logs violations
    """
    try:
        logger.info(f"Checking email from {request.sender}")

        # Use centralized sensitive data detector
        detection_result = SensitiveDataDetector.check_sensitive_content(request.content)

        if detection_result["has_sensitive_data"]:
            # Log offense and get count in single transaction
            offense, violation_count = log_offense_and_get_count(
                db,
                request.sender,
                "Email blocked - Sensitive data detected"
            )

            # Determine risk level based on count
            if violation_count >= settings.CRITICAL_VIOLATION_THRESHOLD:
                risk_level = RiskLevel.CRITICAL
                action_required = "revoke_signin"
            elif violation_count >= settings.WARNING_VIOLATION_THRESHOLD:
                risk_level = RiskLevel.HIGH
                action_required = "warning"
            else:
                risk_level = RiskLevel.MEDIUM
                action_required = "educate"

            # Send email notification if enabled
            if EMAIL_ENABLED and email_service:
                try:
                    await email_service.send_violation_notification(
                        recipient=request.sender,
                        violation_types=detection_result["violation_types"],
                        violation_count=violation_count,
                        blocked_content_summary=SensitiveDataDetector.mask_sensitive_data(request.content[:200])
                    )
                    logger.info(f"✓ Email notification sent to {request.sender}")
                except EmailSendException as e:
                    logger.error(f"Failed to send email: {e}")

            return EmailCheckResponse(
                status="blocked",
                has_sensitive_data=True,
                violation_types=[ViolationType(v) for v in detection_result["violation_types"]],
                violation_count=violation_count,
                risk_level=risk_level,
                action_required=action_required,
                masked_content=SensitiveDataDetector.mask_sensitive_data(request.content),
                message=f"Email blocked - {len(detection_result['violation_types'])} sensitive data types detected"
            )

        return EmailCheckResponse(
            status="allowed",
            has_sensitive_data=False,
            violation_types=[],
            violation_count=0,
            risk_level=RiskLevel.LOW,
            action_required="none",
            message="No sensitive data detected"
        )

    except Exception as e:
        logger.error(f"Email check error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/remediate", response_model=RemediationResponse)
async def remediate_endpoint(request: Request, db: Session = Depends(get_db)):
    """
    Process Sentinel incident and perform remediation

    Called by Logic App when DLP incident is detected
    """
    try:
        logger.info("=" * 80)
        logger.info("NEW INCIDENT RECEIVED FROM LOGIC APP")

        incident_payload = await request.json()
        parsed_incident = SentinelIncidentParser.parse(incident_payload)

        user_upn = parsed_incident["user_upn"]
        if not user_upn:
            raise HTTPException(status_code=400, detail="User UPN not found in payload")

        # Get user details with caching
        user_details = await get_user_details(user_upn)
        if not user_details:
            user_details = {
                "displayName": "Unknown",
                "department": "Unknown",
                "jobTitle": "Unknown"
            }

        # Log offense and get count in single transaction
        offense, offense_count = log_offense_and_get_count(
            db,
            user_upn,
            parsed_incident["incident_title"]
        )

        # Create contexts for decision engine
        incident_ctx = IncidentContext(severity=parsed_incident["severity"])
        user_ctx = UserContext(department=user_details.get("department", "Unknown"))
        file_ctx = FileContext(sensitivity_label=parsed_incident["file_sensitivity"])
        offense_hist = OffenseHistory(previous_offenses=offense_count - 1)  # -1 because we just logged

        # Assess risk
        assessment = decision_engine.assess_risk(incident_ctx, user_ctx, file_ctx, offense_hist)

        if not assessment:
            raise HTTPException(status_code=500, detail="Risk assessment failed")

        # Determine actions based on thresholds
        should_revoke = offense_count >= settings.CRITICAL_VIOLATION_THRESHOLD
        send_socialization = offense_count in settings.SOCIALIZATION_THRESHOLDS

        # Detect violation types from content
        violation_types = ["Sensitive Data"]  # Default

        # Send email notification
        email_sent = False
        if EMAIL_ENABLED and email_service:
            try:
                logger.info(f"📧 Sending email notification to {user_upn}")
                result = await email_service.send_violation_notification(
                    recipient=user_upn,
                    violation_types=violation_types,
                    violation_count=offense_count,
                    blocked_content_summary=parsed_incident.get("incident_title"),
                    incident_title=parsed_incident["incident_title"],
                    file_name=parsed_incident.get("file_name")
                )
                email_sent = result
                logger.info(f"✅ Email notification sent: {email_sent}")
            except Exception as e:
                logger.error(f"❌ Email notification failed: {e}", exc_info=True)

        # Send socialization email if threshold reached
        socialization_sent = False
        if EMAIL_ENABLED and send_socialization and email_service:
            try:
                await email_service.send_socialization_invitation(user_upn, offense_count)
                socialization_sent = True
                logger.info(f"✓ Socialization email sent to {user_upn}")
            except Exception as e:
                logger.error(f"Failed to send socialization email: {e}")

        # Revoke account if threshold reached
        account_revoked = False
        if should_revoke and settings.FEATURE_ACCOUNT_REVOCATION:
            logger.info(f"🚨 CRITICAL: User has {offense_count} violations - triggering account revocation")
            try:
                revoke_result = await perform_hard_block(user_upn)
                account_revoked = revoke_result
                logger.info(f"✅ Account revoked: {account_revoked}")
            except Exception as e:
                logger.error(f"❌ Account revocation failed: {e}", exc_info=True)

        # Send admin alert if high risk
        admin_notified = False
        if EMAIL_ENABLED and offense_count >= settings.CRITICAL_VIOLATION_THRESHOLD and email_service:
            try:
                await email_service.send_admin_alert(
                    user=user_upn,
                    incident_title=parsed_incident["incident_title"],
                    violation_count=offense_count,
                    action_taken="Account Revoked" if account_revoked else "Warning Sent",
                    violation_types=violation_types,
                    file_name=parsed_incident.get("file_name")
                )
                admin_notified = True
                logger.info(f"✓ Admin alert sent for {user_upn}")
            except Exception as e:
                logger.error(f"Failed to send admin alert: {e}")

        # Build response
        response = RemediationResponse(
            request_id=parsed_incident["incident_id"],
            timestamp=datetime.utcnow(),
            user=user_upn,
            user_details={
                "display_name": user_details.get("displayName", "Unknown"),
                "department": user_details.get("department", "Unknown"),
                "job_title": user_details.get("jobTitle", "Unknown")
            },
            assessment={
                "risk_score": assessment.score,
                "risk_level": assessment.risk_level,
                "remediation_action": assessment.remediation_action,
                "confidence": 0.95,
                "escalation_required": assessment.risk_level in ["High", "Critical"]
            },
            offense_count=offense_count,
            violation_types=violation_types,
            actions_taken={
                "email_blocked": True,
                "account_revoked": account_revoked,
                "email_notification_sent": email_sent,
                "socialization_sent": socialization_sent,
                "admin_notified": admin_notified
            },
            status="processed",
            message=f"Violation processed. User has {offense_count} total violations."
        )

        logger.info(f"✓ Incident processed for {user_upn}: {offense_count} violations")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing incident: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/webhook/test")
async def test_webhook():
    """Test endpoint - verify webhook is accessible"""
    return {
        "status": "online",
        "service": "DLP Remediation Engine",
        "version": settings.API_VERSION,
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

        # Purview DLP payload structure
        alert_data = payload.get("AlertData", {})

        # Extract user and incident info
        user_upn = alert_data.get("User") or payload.get("User")
        incident_title = alert_data.get("Title") or payload.get("Title", "DLP Policy Violation")
        severity = alert_data.get("Severity", "High")
        file_name = alert_data.get("FileName") or payload.get("FileName")

        logger.info(f"User: {user_upn}, Incident: {incident_title}")

        if not user_upn:
            raise HTTPException(status_code=400, detail="User UPN required")

        # Get user details
        user_details = await get_user_details(user_upn)
        if not user_details:
            user_details = {"displayName": "Unknown", "department": "Unknown", "jobTitle": "Unknown"}

        # Log offense and get count
        offense, offense_count = log_offense_and_get_count(db, user_upn, incident_title)

        # Create contexts for decision engine
        incident_ctx = IncidentContext(severity=severity)
        user_ctx = UserContext(department=user_details.get("department", "Unknown"))
        file_ctx = FileContext(sensitivity_label="Confidential")
        offense_hist = OffenseHistory(previous_offenses=offense_count - 1)

        # Assess risk
        assessment = decision_engine.assess_risk(incident_ctx, user_ctx, file_ctx, offense_hist)

        # Determine actions
        should_revoke = offense_count >= settings.CRITICAL_VIOLATION_THRESHOLD
        violation_types = ["Sensitive Data", "DLP Policy Violation"]

        # Send email notification
        email_sent = False
        if EMAIL_ENABLED and email_service:
            try:
                result = await email_service.send_violation_notification(
                    recipient=user_upn,
                    violation_types=violation_types,
                    violation_count=offense_count,
                    blocked_content_summary=incident_title,
                    incident_title=incident_title,
                    file_name=file_name
                )
                email_sent = result
            except Exception as e:
                logger.error(f"❌ Email failed: {e}")

        # Revoke account if threshold reached
        account_revoked = False
        if should_revoke and settings.FEATURE_ACCOUNT_REVOCATION:
            try:
                revoke_result = await perform_hard_block(user_upn)
                account_revoked = revoke_result
            except Exception as e:
                logger.error(f"❌ Revocation failed: {e}")

        # Send admin alert
        admin_notified = False
        if EMAIL_ENABLED and offense_count >= settings.CRITICAL_VIOLATION_THRESHOLD and email_service:
            try:
                await email_service.send_admin_alert(
                    user=user_upn,
                    incident_title=incident_title,
                    violation_count=offense_count,
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
            "offense_count": offense_count,
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
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Purview webhook error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

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

                    # Parse and process
                    parsed_incident = SentinelIncidentParser.parse(incident_data)
                    user_upn = parsed_incident["user_upn"]

                    if not user_upn:
                        continue

                    # Log offense and get count
                    offense, offense_count = log_offense_and_get_count(
                        db,
                        user_upn,
                        parsed_incident["incident_title"]
                    )

                    # Send notification
                    email_sent = False
                    if EMAIL_ENABLED and email_service:
                        try:
                            result = await email_service.send_violation_notification(
                                recipient=user_upn,
                                violation_types=["Sensitive Data"],
                                violation_count=offense_count,
                                incident_title=parsed_incident["incident_title"],
                                file_name=parsed_incident.get("file_name")
                            )
                            email_sent = result
                        except Exception as e:
                            logger.error(f"Email failed: {e}")

                    results.append({
                        "incident_id": parsed_incident["incident_id"],
                        "user": user_upn,
                        "offense_count": offense_count,
                        "email_sent": email_sent
                    })

            except Exception as e:
                logger.error(f"Event processing error: {e}")
                results.append({"error": str(e)})

        return {"status": "success", "processed": len(results), "results": results}

    except Exception as e:
        logger.error(f"Event Grid webhook error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

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

# ============================================================================
# STEP 11: LOAD UI ROUTES (optional)
# ============================================================================
try:
    from app.ui_routes import router as ui_router
    app.include_router(ui_router)
    logger.info("✓ UI routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ UI routes not loaded: {e}")

# ============================================================================
# STEP 12: STARTUP/SHUTDOWN EVENTS
# ============================================================================
@app.on_event("startup")
async def startup():
    """Application startup handler"""
    logger.info("=" * 80)
    logger.info(f"DLP REMEDIATION ENGINE v{settings.API_VERSION} STARTING")
    logger.info("=" * 80)
    logger.info(f"Environment: {'Production' if settings.is_production() else 'Development'}")
    logger.info(f"Log Level: {settings.LOG_LEVEL}")
    logger.info(f"Database: {settings.DATABASE_URL[:50]}...")
    logger.info(f"Critical Threshold: {settings.CRITICAL_VIOLATION_THRESHOLD} violations")
    logger.info(f"Email Notifications: {'✅ Enabled' if EMAIL_ENABLED else '❌ Disabled'}")
    logger.info(f"Account Revocation: {'✅ Enabled' if settings.FEATURE_ACCOUNT_REVOCATION else '❌ Disabled'}")
    logger.info(f"Caching: {'✅ Enabled' if settings.CACHE_ENABLED else '❌ Disabled'}")

    # Validate configuration
    warnings = settings.validate_config()
    if warnings:
        logger.warning(f"⚠️ Configuration warnings ({len(warnings)}):")
        for warning in warnings:
            logger.warning(f"  - {warning}")

    logger.info("=" * 80)

@app.on_event("shutdown")
async def shutdown():
    """Application shutdown handler"""
    logger.info("=" * 80)
    logger.info("DLP REMEDIATION ENGINE SHUTTING DOWN")
    logger.info("=" * 80)

# ============================================================================
# MAIN
# ============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level=settings.LOG_LEVEL.lower()
    )
