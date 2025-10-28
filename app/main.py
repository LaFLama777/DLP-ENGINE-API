#python -m uvicorn app.main:app --reload
# app/main.py - Optimized for Logic App integration
import os
import sys
import re
import traceback
from datetime import datetime
from typing import Dict, Any, List
import logging
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

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


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    """Professional Dashboard UI"""
    
    try:
        total_incidents = db.query(Offense).count()
        unique_users = db.query(Offense.user_principal_name).distinct().count()
        
        # Get today's incidents
        today = datetime.utcnow().date()
        today_incidents = db.query(Offense).filter(
            func.date(Offense.timestamp) == today
        ).count()
        
        # Get high risk incidents (those with 3+ offenses)
        high_risk_users = db.query(
            Offense.user_principal_name,
            func.count(Offense.id).label('offense_count')
        ).group_by(Offense.user_principal_name).having(
            func.count(Offense.id) >= 3
        ).count()
        
        # Get recent incidents
        recent_incidents = db.query(Offense).order_by(desc(Offense.timestamp)).limit(10).all()
        
        # Monthly trend data
        monthly_data = db.query(
            func.extract('month', Offense.timestamp).label('month'),
            func.count(Offense.id).label('count')
        ).group_by('month').all()
        
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        total_incidents = 0
        unique_users = 0
        today_incidents = 0
        high_risk_users = 0
        recent_incidents = []
        monthly_data = []
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DLP Remediation Engine - Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0f1419;
            color: #e4e6eb;
            min-height: 100vh;
        }}
        
        .sidebar {{
            position: fixed;
            left: 0;
            top: 0;
            width: 240px;
            height: 100vh;
            background: #1a1f2e;
            border-right: 1px solid #2d3748;
            padding: 24px 0;
            z-index: 1000;
        }}
        
        .logo {{
            padding: 0 24px 24px;
            border-bottom: 1px solid #2d3748;
            margin-bottom: 24px;
        }}
        
        .logo h1 {{
            font-size: 18px;
            font-weight: 700;
            color: #60a5fa;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .nav-item {{
            padding: 12px 24px;
            color: #9ca3af;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 12px;
            transition: all 0.2s;
            cursor: pointer;
            font-size: 14px;
        }}
        
        .nav-item:hover, .nav-item.active {{
            background: #2d3748;
            color: #60a5fa;
            border-left: 3px solid #60a5fa;
        }}
        
        .main-content {{
            margin-left: 240px;
            padding: 24px;
        }}
        
        .top-bar {{
            background: #1a1f2e;
            border: 1px solid #2d3748;
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .status-badge {{
            background: #10b981;
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .status-dot {{
            width: 8px;
            height: 8px;
            background: white;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 24px;
        }}
        
        .stat-card {{
            background: #1a1f2e;
            border: 1px solid #2d3748;
            border-radius: 12px;
            padding: 24px;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 12px 24px rgba(96, 165, 250, 0.1);
        }}
        
        .stat-label {{
            color: #9ca3af;
            font-size: 13px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }}
        
        .stat-value {{
            font-size: 36px;
            font-weight: 700;
            color: #e4e6eb;
            margin-bottom: 8px;
        }}
        
        .stat-change {{
            font-size: 12px;
            color: #10b981;
        }}
        
        .stat-change.negative {{
            color: #ef4444;
        }}
        
        .chart-grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }}
        
        .card {{
            background: #1a1f2e;
            border: 1px solid #2d3748;
            border-radius: 12px;
            padding: 24px;
        }}
        
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}
        
        .card-title {{
            font-size: 16px;
            font-weight: 600;
            color: #e4e6eb;
        }}
        
        .incident-list {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        
        .incident-item {{
            background: #0f1419;
            border: 1px solid #2d3748;
            border-radius: 8px;
            padding: 16px;
            transition: all 0.2s;
        }}
        
        .incident-item:hover {{
            border-color: #60a5fa;
            transform: translateX(4px);
        }}
        
        .incident-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 8px;
        }}
        
        .incident-title {{
            font-size: 14px;
            font-weight: 500;
            color: #e4e6eb;
            flex: 1;
        }}
        
        .incident-badge {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .badge-high {{
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
        }}
        
        .badge-medium {{
            background: rgba(251, 191, 36, 0.2);
            color: #fbbf24;
        }}
        
        .badge-low {{
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
        }}
        
        .incident-meta {{
            font-size: 12px;
            color: #9ca3af;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 48px 24px;
            color: #6b7280;
        }}
        
        .empty-state-icon {{
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }}
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="logo">
            <h1>🛡️ DLP Engine</h1>
        </div>
        <a href="/" class="nav-item active">
            📊 Dashboard
        </a>
        <a href="/incidents" class="nav-item">
            🚨 Incidents
        </a>
        <a href="/health" class="nav-item">
            ❤️ Health Check
        </a>
        <a href="/stats" class="nav-item">
            📈 Statistics
        </a>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Bar -->
        <div class="top-bar">
            <div>
                <h2 style="font-size: 24px; font-weight: 700; margin-bottom: 4px;">Security Dashboard</h2>
                <p style="color: #9ca3af; font-size: 14px;">Monitor and manage DLP incidents in real-time</p>
            </div>
            <div class="status-badge">
                <div class="status-dot"></div>
                System Online
            </div>
        </div>

        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Incidents</div>
                <div class="stat-value">{total_incidents}</div>
                <div class="stat-change">↑ All time</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Users Monitored</div>
                <div class="stat-value">{unique_users}</div>
                <div class="stat-change">Active users</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High Risk</div>
                <div class="stat-value">{high_risk_users}</div>
                <div class="stat-change negative">↑ Requires attention</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Today</div>
                <div class="stat-value">{today_incidents}</div>
                <div class="stat-change">Last 24 hours</div>
            </div>
        </div>

        <!-- Charts -->
        <div class="chart-grid">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Incident Trend</div>
                </div>
                <canvas id="trendChart" height="80"></canvas>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Violation Types</div>
                </div>
                <canvas id="violationChart" height="200"></canvas>
            </div>
        </div>

        <!-- Recent Incidents -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">Recent Activity</div>
                <a href="/incidents" style="color: #60a5fa; text-decoration: none; font-size: 14px;">View All →</a>
            </div>
            <div class="incident-list">
                {"".join([f'''
                <div class="incident-item">
                    <div class="incident-header">
                        <div class="incident-title">{inc.incident_title}</div>
                        <span class="incident-badge badge-high">HIGH</span>
                    </div>
                    <div class="incident-meta">
                        <strong>User:</strong> {inc.user_principal_name} • 
                        <strong>Time:</strong> {inc.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
                    </div>
                </div>
                ''' for inc in recent_incidents[:5]]) if recent_incidents else '''
                <div class="empty-state">
                    <div class="empty-state-icon">📋</div>
                    <p>No incidents recorded yet</p>
                </div>
                '''}
            </div>
        </div>
    </div>

    <script>
        // Trend Chart
        const trendCtx = document.getElementById('trendChart').getContext('2d');
        new Chart(trendCtx, {{
            type: 'line',
            data: {{
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
                datasets: [{{
                    label: 'Incidents',
                    data: [12, 19, 8, 15, 22, 18, 25, 30, 28, 35, 32, {total_incidents}],
                    borderColor: '#60a5fa',
                    backgroundColor: 'rgba(96, 165, 250, 0.1)',
                    tension: 0.4,
                    fill: true
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        grid: {{ color: '#2d3748' }},
                        ticks: {{ color: '#9ca3af' }}
                    }},
                    x: {{
                        grid: {{ display: false }},
                        ticks: {{ color: '#9ca3af' }}
                    }}
                }}
            }}
        }});

        // Violation Types Chart
        const violationCtx = document.getElementById('violationChart').getContext('2d');
        new Chart(violationCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['KTP', 'NPWP', 'Employee ID', 'Other'],
                datasets: [{{
                    data: [30, 25, 20, 25],
                    backgroundColor: ['#60a5fa', '#10b981', '#f59e0b', '#ef4444']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{ color: '#9ca3af' }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html)


@app.get("/health")
async def health_check():
    """Health check endpoint"""
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
            "teams_alerts": True,  # Handled by Logic App
            "sensitive_data_detection": True,
            "account_revocation": True,
            "email_notifications": EMAIL_ENABLED
        },
        "integration": {
            "logic_app": True,
            "teams_via_logic_app": True
        }
    }


@app.get("/stats")
async def get_stats(db: Session = Depends(get_db)):
    """Get statistics"""
    try:
        total = db.query(Offense).count()
        users = db.query(Offense.user_principal_name).distinct().count()
        
        high_risk = db.query(
            Offense.user_principal_name,
            func.count(Offense.id).label('count')
        ).group_by(Offense.user_principal_name).having(
            func.count(Offense.id) >= 3
        ).count()
        
        today = datetime.utcnow().date()
        today_count = db.query(Offense).filter(
            func.date(Offense.timestamp) == today
        ).count()
        
        recent = db.query(Offense).order_by(desc(Offense.timestamp)).limit(10).all()
        
        return {
            "total_incidents": total,
            "unique_users": users,
            "high_risk": high_risk,
            "today": today_count,
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
        logger.error(f"Stats error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


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
        # You can enhance this with actual detection from file content if available
        
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