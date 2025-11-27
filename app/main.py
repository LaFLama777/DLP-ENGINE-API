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
# python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
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
from fastapi.responses import JSONResponse, HTMLResponse
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
    redoc_url=None  # We'll create custom dark theme ReDoc
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

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint - Premium Dashboard UI"""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DLP Remediation Engine - Premium Dashboard</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }

            @keyframes gradient {
                0% { background-position: 0% 50%; }
                50% { background-position: 100% 50%; }
                100% { background-position: 0% 50%; }
            }

            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: #000000;
                color: #ffffff;
                min-height: 100vh;
                padding: 0;
                margin: 0;
                overflow-x: hidden;
                overflow-y: auto;
            }

            html {
                overflow-x: hidden;
            }

            body::before {
                content: '';
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background:
                    radial-gradient(circle at 20% 20%, rgba(156, 163, 175, 0.08) 0%, transparent 50%),
                    radial-gradient(circle at 80% 80%, rgba(107, 114, 128, 0.08) 0%, transparent 50%),
                    radial-gradient(circle at 50% 50%, rgba(75, 85, 99, 0.05) 0%, transparent 50%);
                pointer-events: none;
                z-index: 0;
            }
            .container {
                max-width: 1800px;
                margin: 0 auto;
                padding: 3rem 2rem;
                position: relative;
                z-index: 1;
            }

            .header {
                text-align: center;
                margin-bottom: 4rem;
                padding: 2rem 0;
                animation: fadeInUp 0.8s ease;
            }

            .header h1 {
                font-size: 4rem;
                font-weight: 900;
                background: linear-gradient(135deg, #9ca3af 0%, #6b7280 50%, #4b5563 100%);
                background-size: 200% 200%;
                animation: gradient 4s ease infinite;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 1rem;
                letter-spacing: -0.03em;
            }

            .header p {
                color: #71717a;
                font-size: 1.25rem;
                font-weight: 400;
                margin-bottom: 2rem;
            }

            .status-badge {
                display: inline-flex;
                align-items: center;
                gap: 0.75rem;
                padding: 1rem 2rem;
                background: linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(5, 150, 105, 0.15) 100%);
                border: 1px solid rgba(16, 185, 129, 0.4);
                border-radius: 3rem;
                color: #10b981;
                font-weight: 700;
                font-size: 0.9375rem;
                backdrop-filter: blur(20px);
                box-shadow: 0 8px 32px rgba(16, 185, 129, 0.25);
            }
            .grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
                gap: 2rem;
                margin-bottom: 3rem;
            }

            .card {
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
                backdrop-filter: blur(30px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 2rem;
                padding: 2.5rem;
                transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
                animation: fadeInUp 0.8s ease both;
            }

            .card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(90deg, #9ca3af, #6b7280, #4b5563);
                background-size: 200% 100%;
                opacity: 0;
                transition: opacity 0.5s ease;
                animation: gradient 3s ease infinite;
            }

            .card:hover {
                transform: translateY(-12px) scale(1.02);
                border-color: rgba(156, 163, 175, 0.6);
                box-shadow:
                    0 30px 60px rgba(156, 163, 175, 0.3),
                    0 0 80px rgba(156, 163, 175, 0.15),
                    inset 0 1px 0 rgba(255, 255, 255, 0.1);
            }

            .card:hover::before {
                opacity: 1;
            }

            .card:nth-child(1) { animation-delay: 0.1s; }
            .card:nth-child(2) { animation-delay: 0.2s; }
            .card:nth-child(3) { animation-delay: 0.3s; }
            .card:nth-child(4) { animation-delay: 0.4s; }

            .card-title {
                font-size: 0.8125rem;
                font-weight: 800;
                color: #71717a;
                text-transform: uppercase;
                letter-spacing: 0.15em;
                margin-bottom: 1.5rem;
                display: flex;
                align-items: center;
                gap: 0.75rem;
            }

            .card-icon {
                font-size: 1.5rem;
                filter: grayscale(0.3);
            }

            .card-value {
                font-size: 3.5rem;
                font-weight: 900;
                background: linear-gradient(135deg, #ffffff 0%, #a1a1aa 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 1rem;
                line-height: 1;
                letter-spacing: -0.02em;
            }

            .card-description {
                font-size: 0.9375rem;
                color: #52525b;
                font-weight: 500;
            }
            .charts-row {
                display: grid;
                grid-template-columns: 2fr 1fr;
                gap: 2rem;
                margin-bottom: 3rem;
                animation: fadeInUp 1s ease both;
                animation-delay: 0.5s;
            }

            .chart-card {
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
                backdrop-filter: blur(30px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 2rem;
                padding: 3rem;
                transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1);
                height: 450px;
                display: flex;
                flex-direction: column;
            }

            .chart-card:hover {
                transform: translateY(-8px);
                box-shadow: 0 30px 60px rgba(156, 163, 175, 0.2);
                border-color: rgba(156, 163, 175, 0.4);
            }

            .chart-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 2rem;
            }

            .chart-title {
                font-size: 1.5rem;
                font-weight: 800;
                color: #ffffff;
                display: flex;
                align-items: center;
                gap: 0.75rem;
            }

            .chart-badge {
                padding: 0.5rem 1rem;
                background: rgba(156, 163, 175, 0.15);
                border: 1px solid rgba(156, 163, 175, 0.3);
                border-radius: 1rem;
                color: #9ca3af;
                font-size: 0.75rem;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }

            .chart-card canvas {
                max-height: 300px !important;
                width: 100% !important;
                flex-shrink: 0;
            }

            .table-container {
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
                backdrop-filter: blur(30px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 2rem;
                padding: 3rem;
                animation: fadeInUp 1.2s ease both;
                animation-delay: 0.7s;
                max-height: 600px;
                overflow: hidden;
            }

            .table-container > div:last-child {
                max-height: 450px;
                overflow-y: auto;
            }

            .table-container > div:last-child::-webkit-scrollbar {
                width: 8px;
            }

            .table-container > div:last-child::-webkit-scrollbar-track {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 4px;
            }

            .table-container > div:last-child::-webkit-scrollbar-thumb {
                background: rgba(156, 163, 175, 0.3);
                border-radius: 4px;
            }

            .table-container > div:last-child::-webkit-scrollbar-thumb:hover {
                background: rgba(156, 163, 175, 0.5);
            }

            .table-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 2rem;
            }

            .table-title {
                font-size: 1.5rem;
                font-weight: 800;
                color: #ffffff;
                display: flex;
                align-items: center;
                gap: 0.75rem;
            }

            table {
                width: 100%;
                border-collapse: separate;
                border-spacing: 0 0.5rem;
            }

            thead tr {
                background: rgba(255, 255, 255, 0.03);
            }

            th {
                text-align: left;
                padding: 1rem 1.5rem;
                color: #71717a;
                font-weight: 800;
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.1em;
                border-top: 1px solid rgba(255, 255, 255, 0.05);
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            }

            th:first-child {
                border-left: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 1rem 0 0 1rem;
            }

            th:last-child {
                border-right: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 0 1rem 1rem 0;
            }

            tbody tr {
                transition: all 0.3s ease;
            }

            tbody tr:hover {
                background: rgba(156, 163, 175, 0.08);
            }

            td {
                padding: 1.25rem 1.5rem;
                color: #a1a1aa;
                font-size: 0.9375rem;
                font-weight: 500;
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            }

            .btn {
                display: inline-flex;
                align-items: center;
                gap: 0.75rem;
                padding: 1.125rem 2.5rem;
                background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
                color: white;
                text-decoration: none;
                border-radius: 1.25rem;
                font-weight: 700;
                font-size: 1rem;
                transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
                border: none;
                cursor: pointer;
                margin: 0.5rem;
                box-shadow: 0 10px 40px rgba(107, 114, 128, 0.3);
                position: relative;
                overflow: hidden;
            }

            .btn::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
                transition: left 0.5s ease;
            }

            .btn:hover::before {
                left: 100%;
            }

            .btn:hover {
                transform: translateY(-4px) scale(1.05);
                box-shadow: 0 20px 60px rgba(107, 114, 128, 0.5);
                background: linear-gradient(135deg, #9ca3af 0%, #6b7280 100%);
            }

            .btn-secondary {
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                box-shadow: none;
            }

            .btn-secondary:hover {
                background: rgba(255, 255, 255, 0.1);
                border-color: rgba(255, 255, 255, 0.2);
                box-shadow: 0 10px 40px rgba(255, 255, 255, 0.15);
            }

            .cta-section {
                text-align: center;
                margin: 4rem 0;
                animation: fadeInUp 1.4s ease both;
                animation-delay: 0.9s;
            }

            @media (max-width: 1024px) {
                .charts-row {
                    grid-template-columns: 1fr;
                }
            }

            @media (max-width: 768px) {
                .header h1 {
                    font-size: 2.5rem;
                }
                .card-value {
                    font-size: 2.5rem;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ DLP Remediation Engine</h1>
                <p>Enterprise-Grade Data Loss Prevention & Automated Remediation</p>
                <div class="status-badge" id="status">
                    <span>●</span>
                    <span>System Online</span>
                </div>
            </div>

            <!-- Statistics Cards -->
            <div class="grid">
                <div class="card">
                    <div class="card-title">
                        <span class="card-icon">🚨</span>
                        Total Violations
                    </div>
                    <div class="card-value" id="total-violations">--</div>
                    <div class="card-description">All-time incidents detected</div>
                </div>
                <div class="card">
                    <div class="card-title">
                        <span class="card-icon">📅</span>
                        Today's Violations
                    </div>
                    <div class="card-value" id="today-violations">--</div>
                    <div class="card-description">Incidents detected today</div>
                </div>
                <div class="card">
                    <div class="card-title">
                        <span class="card-icon">👥</span>
                        Monitored Users
                    </div>
                    <div class="card-value" id="total-users">--</div>
                    <div class="card-description">Unique users tracked</div>
                </div>
                <div class="card">
                    <div class="card-title">
                        <span class="card-icon">⚠️</span>
                        High Risk Users
                    </div>
                    <div class="card-value" id="high-risk-users">--</div>
                    <div class="card-description">Users with 3+ violations</div>
                </div>
            </div>

            <!-- Charts Row -->
            <div class="charts-row">
                <div class="chart-card">
                    <div class="chart-header">
                        <h3 class="chart-title">
                            <span>📈</span>
                            Violation Trend
                        </h3>
                        <div class="chart-badge">Last 30 Days</div>
                    </div>
                    <div style="flex: 1; position: relative; max-height: 300px;">
                        <canvas id="trendChart"></canvas>
                    </div>
                </div>
                <div class="chart-card">
                    <div class="chart-header">
                        <h3 class="chart-title">
                            <span>🎯</span>
                            Attack Types
                        </h3>
                    </div>
                    <div style="flex: 1; position: relative; max-height: 300px;">
                        <canvas id="typeChart"></canvas>
                    </div>
                    <div id="type-legend" style="margin-top: 1.5rem;"></div>
                </div>
            </div>

            <!-- Recent Incidents Table -->
            <div class="table-container">
                <div class="table-header">
                    <h3 class="table-title">
                        <span>🔔</span>
                        Recent Incidents
                    </h3>
                    <button onclick="loadDashboardData()" class="btn">
                        <span>🔄</span>
                        <span>Refresh</span>
                    </button>
                </div>
                <div style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>User</th>
                                <th>Incident</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody id="incidents-table">
                            <tr><td colspan="4" style="text-align: center; padding: 3rem; color: #52525b;">Loading incidents...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Call to Action -->
            <div class="cta-section">
                <a href="/docs" class="btn">
                    <span>📖</span>
                    <span>API Documentation</span>
                </a>
                <a href="/redoc" class="btn btn-secondary">
                    <span>📚</span>
                    <span>ReDoc</span>
                </a>
                <a href="/health" class="btn btn-secondary">
                    <span>🏥</span>
                    <span>Health Check</span>
                </a>
            </div>
        </div>

        <script>
            let trendChart = null;
            let typeChart = null;

            async function loadDashboardData() {
                try {
                    // Update status badge
                    document.getElementById('status').textContent = '● Online';
                    document.getElementById('status').style.background = 'rgba(34, 197, 94, 0.1)';
                    document.getElementById('status').style.borderColor = 'rgba(34, 197, 94, 0.3)';
                    document.getElementById('status').style.color = '#22c55e';

                    // Load statistics
                    const statsResponse = await fetch('/api/statistics');
                    const stats = await statsResponse.json();

                    document.getElementById('total-violations').textContent = stats.total_violations || 0;
                    document.getElementById('today-violations').textContent = stats.today_violations || 0;
                    document.getElementById('total-users').textContent = stats.total_users || 0;
                    document.getElementById('high-risk-users').textContent = stats.high_risk_users || 0;

                    // Load trend data and create chart
                    const trendResponse = await fetch('/api/violations/trend?days=30');
                    const trendData = await trendResponse.json();
                    createTrendChart(trendData);

                    // Load violation types and create chart
                    const typesResponse = await fetch('/api/violations/by-type');
                    const typesData = await typesResponse.json();
                    createTypeChart(typesData);

                    // Load recent incidents (limited to 8 to prevent layout breaking)
                    const incidentsResponse = await fetch('/api/violations/recent?limit=8');
                    const incidents = await incidentsResponse.json();
                    displayIncidents(incidents);

                } catch (error) {
                    document.getElementById('status').textContent = '● Error Loading';
                    document.getElementById('status').style.background = 'rgba(239, 68, 68, 0.1)';
                    document.getElementById('status').style.color = '#ef4444';
                    console.error('Error loading dashboard:', error);
                }
            }

            function createTrendChart(data) {
                try {
                    const canvas = document.getElementById('trendChart');
                    if (!canvas) {
                        console.error('Trend chart canvas not found');
                        return;
                    }
                    const ctx = canvas.getContext('2d');
                    if (trendChart) {
                        trendChart.destroy();
                        trendChart = null;
                    }

                const labels = data.map(d => {
                    const date = new Date(d.date);
                    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                });
                const counts = data.map(d => d.count);

                const gradient = ctx.createLinearGradient(0, 0, 0, 400);
                gradient.addColorStop(0, 'rgba(107, 114, 128, 0.5)');
                gradient.addColorStop(1, 'rgba(107, 114, 128, 0)');

                trendChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Violations',
                            data: counts,
                            borderColor: '#6b7280',
                            backgroundColor: gradient,
                            fill: true,
                            tension: 0.4,
                            borderWidth: 3,
                            pointBackgroundColor: '#6b7280',
                            pointBorderColor: '#000',
                            pointBorderWidth: 2,
                            pointRadius: 5,
                            pointHoverRadius: 8,
                            pointHoverBackgroundColor: '#9ca3af',
                            pointHoverBorderWidth: 3
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        aspectRatio: 2.5,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: 'rgba(0, 0, 0, 0.9)',
                                padding: 16,
                                titleColor: '#fff',
                                bodyColor: '#a1a1aa',
                                borderColor: 'rgba(107, 114, 128, 0.5)',
                                borderWidth: 1,
                                displayColors: false,
                                titleFont: { size: 14, weight: 'bold' },
                                bodyFont: { size: 13 }
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    color: '#52525b',
                                    font: { size: 12, weight: '600' },
                                    stepSize: 1
                                },
                                grid: {
                                    color: 'rgba(255, 255, 255, 0.05)',
                                    drawBorder: false
                                },
                                border: { display: false }
                            },
                            x: {
                                ticks: {
                                    color: '#52525b',
                                    font: { size: 12, weight: '600' },
                                    maxRotation: 45,
                                    minRotation: 45
                                },
                                grid: { display: false },
                                border: { display: false }
                            }
                        },
                        interaction: {
                            intersect: false,
                            mode: 'index'
                        }
                    }
                });
                } catch (error) {
                    console.error('Error creating trend chart:', error);
                }
            }

            function createTypeChart(data) {
                try {
                    const canvas = document.getElementById('typeChart');
                    if (!canvas) {
                        console.error('Type chart canvas not found');
                        return;
                    }
                    const ctx = canvas.getContext('2d');
                    if (typeChart) {
                        typeChart.destroy();
                        typeChart = null;
                    }

                if (!data || data.length === 0) {
                    ctx.font = '16px Inter';
                    ctx.fillStyle = '#52525b';
                    ctx.textAlign = 'center';
                    ctx.fillText('No data available', ctx.canvas.width / 2, ctx.canvas.height / 2);
                    return;
                }

                const labels = data.map(d => d.type);
                const counts = data.map(d => d.count);
                const colors = ['#6b7280', '#9ca3af', '#4b5563', '#71717a', '#d1d5db'];

                typeChart = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: counts,
                            backgroundColor: colors.slice(0, counts.length),
                            borderColor: '#000000',
                            borderWidth: 4,
                            hoverBorderWidth: 6,
                            hoverOffset: 10
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        aspectRatio: 1.2,
                        plugins: {
                            legend: {
                                display: true,
                                position: 'bottom',
                                labels: {
                                    color: '#71717a',
                                    padding: 20,
                                    font: { size: 13, weight: '600' },
                                    usePointStyle: true,
                                    pointStyle: 'circle'
                                }
                            },
                            tooltip: {
                                backgroundColor: 'rgba(0, 0, 0, 0.9)',
                                padding: 16,
                                borderColor: 'rgba(107, 114, 128, 0.5)',
                                borderWidth: 1,
                                titleFont: { size: 14, weight: 'bold' },
                                bodyFont: { size: 13 }
                            }
                        },
                        cutout: '70%'
                    }
                });

                // Create legend
                const legendHtml = data.map((d, i) => `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 1rem 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
                        <span style="display: flex; align-items: center; gap: 0.75rem; color: #a1a1aa; font-weight: 600;">
                            <span style="width: 16px; height: 16px; background: ${colors[i]}; border-radius: 50%; box-shadow: 0 0 20px ${colors[i]}80;"></span>
                            ${d.type}
                        </span>
                        <strong style="color: #ffffff; font-size: 1.125rem;">${d.count}</strong>
                    </div>
                `).join('');
                document.getElementById('type-legend').innerHTML = legendHtml;
                } catch (error) {
                    console.error('Error creating type chart:', error);
                }
            }

            function displayIncidents(incidents) {
                const tbody = document.getElementById('incidents-table');

                if (!incidents || incidents.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 3rem; color: #52525b;">No incidents found</td></tr>';
                    return;
                }

                const rows = incidents.map(inc => `
                    <tr onclick="window.location.href='/incident/${inc.id}'" style="cursor: pointer;">
                        <td style="font-family: 'Courier New', monospace; font-weight: 700; color: #9ca3af;">
                            <a href="/incident/${inc.id}" style="color: #9ca3af; text-decoration: none; display: block;">
                                #${inc.id}
                            </a>
                        </td>
                        <td style="color: #ffffff; font-weight: 600;">${inc.user}</td>
                        <td style="color: #a1a1aa; max-width: 500px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${inc.incident_title}</td>
                        <td style="color: #71717a; font-weight: 600;">${inc.time_ago}</td>
                    </tr>
                `).join('');

                tbody.innerHTML = rows;
            }

            // Load dashboard on page load
            loadDashboardData();

            // Manual refresh available via the "Refresh" button in the UI
            // Removed auto-refresh to prevent performance issues and excessive API calls
        </script>
    </body>
    </html>
    """

@app.get("/api/statistics")
async def get_statistics(db: Session = Depends(get_db)):
    """Get dashboard statistics"""
    try:
        from datetime import datetime, timedelta
        from sqlalchemy import func, cast, Date
        from database import Offense

        now = datetime.utcnow()
        today_start = datetime(now.year, now.month, now.day)
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)

        # Total violations
        total_violations = db.query(func.count(Offense.id)).scalar() or 0

        # Today's violations
        today_violations = db.query(func.count(Offense.id))\
            .filter(Offense.timestamp >= today_start)\
            .scalar() or 0

        # This week's violations
        week_violations = db.query(func.count(Offense.id))\
            .filter(Offense.timestamp >= week_ago)\
            .scalar() or 0

        # Unique users with violations
        total_users = db.query(func.count(func.distinct(Offense.user_principal_name)))\
            .scalar() or 0

        # High risk users (3+ violations)
        high_risk_users = db.query(Offense.user_principal_name)\
            .group_by(Offense.user_principal_name)\
            .having(func.count(Offense.id) >= 3)\
            .count()

        # Users with violations today
        active_users_today = db.query(func.count(func.distinct(Offense.user_principal_name)))\
            .filter(Offense.timestamp >= today_start)\
            .scalar() or 0

        return {
            "total_violations": total_violations,
            "today_violations": today_violations,
            "week_violations": week_violations,
            "month_violations": db.query(func.count(Offense.id)).filter(Offense.timestamp >= month_ago).scalar() or 0,
            "total_users": total_users,
            "high_risk_users": high_risk_users,
            "active_users_today": active_users_today,
            "average_daily": round(total_violations / max((now - datetime(now.year, now.month, 1)).days, 1), 2)
        }
    except Exception as e:
        logger.error(f"Error fetching statistics: {e}")
        return {
            "total_violations": 0,
            "today_violations": 0,
            "week_violations": 0,
            "month_violations": 0,
            "total_users": 0,
            "high_risk_users": 0,
            "active_users_today": 0,
            "average_daily": 0
        }

@app.get("/api/violations/recent")
async def get_recent_violations(limit: int = 20, db: Session = Depends(get_db)):
    """Get recent violations for incidents table"""
    try:
        from database import Offense

        violations = db.query(Offense)\
            .order_by(Offense.timestamp.desc())\
            .limit(limit)\
            .all()

        return [{
            "id": v.id,
            "user": v.user_principal_name,  # Admin view - no masking
            "incident_title": v.incident_title,  # Admin view - show full details
            "timestamp": v.timestamp.isoformat() if v.timestamp else None,
            "time_ago": _format_time_ago(v.timestamp) if v.timestamp else "Unknown"
        } for v in violations]
    except Exception as e:
        logger.error(f"Error fetching recent violations: {e}")
        return []

@app.get("/api/violations/trend")
async def get_violation_trend(days: int = 30, db: Session = Depends(get_db)):
    """Get violation trend data for charts"""
    try:
        from datetime import datetime, timedelta
        from sqlalchemy import func, cast, Date
        from database import Offense

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        # Group violations by date
        daily_counts = db.query(
            cast(Offense.timestamp, Date).label('date'),
            func.count(Offense.id).label('count')
        ).filter(
            Offense.timestamp >= start_date
        ).group_by(
            cast(Offense.timestamp, Date)
        ).order_by('date').all()

        # Fill in missing dates with 0
        date_dict = {item.date.isoformat(): item.count for item in daily_counts}

        result = []
        current = start_date.date()
        while current <= end_date.date():
            result.append({
                "date": current.isoformat(),
                "count": date_dict.get(current.isoformat(), 0)
            })
            current += timedelta(days=1)

        return result
    except Exception as e:
        logger.error(f"Error fetching trend data: {e}")
        return []

@app.get("/api/violations/by-type")
async def get_violations_by_type(db: Session = Depends(get_db)):
    """Get violations grouped by type"""
    try:
        from database import Offense
        from collections import Counter

        violations = db.query(Offense.incident_title).all()

        # Extract violation types from incident titles
        type_counts = Counter()
        for v in violations:
            title = v.incident_title.lower()

            # Check for specific patterns and categorize
            categorized = False

            if 'ktp' in title or '16 digit' in title or 'national id' in title:
                type_counts['KTP'] += 1
                categorized = True
            elif 'npwp' in title or 'tax id' in title:
                type_counts['NPWP'] += 1
                categorized = True
            elif 'employee' in title or 'kary' in title or 'emp-' in title or 'nip' in title:
                type_counts['Employee ID'] += 1
                categorized = True
            elif 'credit card' in title or 'card number' in title:
                type_counts['Credit Card'] += 1
                categorized = True
            elif 'sensitive data' in title or 'confidential' in title or 'dlp policy' in title:
                # Generic DLP policy violations - categorize as "Sensitive Data"
                type_counts['Sensitive Data'] += 1
                categorized = True

            if not categorized:
                type_counts['Other'] += 1

        return [{"type": k, "count": v} for k, v in type_counts.most_common()]
    except Exception as e:
        logger.error(f"Error fetching violations by type: {e}")
        return []

def _format_time_ago(timestamp: datetime) -> str:
    """Format timestamp as relative time (e.g., '2 hours ago')"""
    try:
        now = datetime.utcnow()
        diff = now - timestamp

        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        elif diff.seconds >= 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.seconds >= 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"
    except:
        return "Unknown"

@app.get("/health")
async def health_check():
    """Health check endpoint with detailed status - HTML view"""
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        db_status = "healthy"
        db_icon = "✅"
        db_color = "#22c55e"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "unhealthy"
        db_icon = "❌"
        db_color = "#ef4444"

    overall_status = "healthy" if db_status == "healthy" else "degraded"
    status_color = "#22c55e" if overall_status == "healthy" else "#f59e0b"

    features = {
        "Email Blocking": True,
        "Teams Alerts": settings.FEATURE_TEAMS_ALERTS,
        "Sensitive Data Detection": True,
        "Account Revocation": settings.FEATURE_ACCOUNT_REVOCATION,
        "Email Notifications": EMAIL_ENABLED,
        "Caching": settings.CACHE_ENABLED
    }

    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Health Check - DLP Engine</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: #000000;
                color: #ffffff;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 2rem;
            }}
            .container {{
                max-width: 800px;
                width: 100%;
            }}
            .card {{
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
                backdrop-filter: blur(30px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 2rem;
                padding: 3rem;
            }}
            .header {{
                text-align: center;
                margin-bottom: 3rem;
            }}
            .header h1 {{
                font-size: 2.5rem;
                font-weight: 800;
                margin-bottom: 0.5rem;
                background: linear-gradient(135deg, #9ca3af 0%, #6b7280 50%, #4b5563 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            .status-badge {{
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.75rem 1.5rem;
                background: rgba({int(status_color[1:3], 16)}, {int(status_color[3:5], 16)}, {int(status_color[5:7], 16)}, 0.1);
                border: 1px solid rgba({int(status_color[1:3], 16)}, {int(status_color[3:5], 16)}, {int(status_color[5:7], 16)}, 0.3);
                border-radius: 1rem;
                color: {status_color};
                font-weight: 700;
                font-size: 1rem;
                margin-top: 1rem;
            }}
            .info-grid {{
                display: grid;
                gap: 1.5rem;
                margin-bottom: 2rem;
            }}
            .info-item {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 1.25rem;
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 1rem;
            }}
            .info-label {{
                color: #9ca3af;
                font-weight: 600;
                font-size: 0.875rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            .info-value {{
                color: #ffffff;
                font-weight: 700;
                font-size: 1.125rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }}
            .features-title {{
                font-size: 1.25rem;
                font-weight: 700;
                margin-bottom: 1.5rem;
                color: #ffffff;
            }}
            .features-grid {{
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 1rem;
            }}
            .feature-item {{
                display: flex;
                align-items: center;
                gap: 0.75rem;
                padding: 1rem;
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 0.75rem;
            }}
            .feature-icon {{
                font-size: 1.25rem;
            }}
            .feature-name {{
                color: #d1d5db;
                font-weight: 500;
                font-size: 0.875rem;
            }}
            .btn {{
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.75rem 1.5rem;
                background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
                border: 1px solid rgba(156, 163, 175, 0.3);
                border-radius: 1rem;
                color: #ffffff;
                font-weight: 700;
                font-size: 0.875rem;
                text-decoration: none;
                transition: all 0.3s ease;
                margin-top: 2rem;
            }}
            .btn:hover {{
                background: linear-gradient(135deg, #9ca3af 0%, #6b7280 100%);
                box-shadow: 0 10px 30px rgba(107, 114, 128, 0.3);
                transform: translateY(-2px);
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <div class="header">
                    <h1>🏥 System Health</h1>
                    <p style="color: #9ca3af; font-size: 1rem;">DLP Remediation Engine v{settings.API_VERSION}</p>
                    <div class="status-badge">
                        <span>●</span>
                        <span>{overall_status.upper()}</span>
                    </div>
                </div>

                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Database</span>
                        <span class="info-value" style="color: {db_color};">
                            <span>{db_icon}</span>
                            <span>{db_status.upper()}</span>
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Timestamp</span>
                        <span class="info-value" style="color: #9ca3af;">
                            {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Version</span>
                        <span class="info-value" style="color: #9ca3af;">
                            {settings.API_VERSION}
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Environment</span>
                        <span class="info-value" style="color: #9ca3af;">
                            Production
                        </span>
                    </div>
                </div>

                <h3 class="features-title">Features Status</h3>
                <div class="features-grid">
                    {''.join([f'''
                    <div class="feature-item">
                        <span class="feature-icon">{'✅' if enabled else '❌'}</span>
                        <span class="feature-name">{name}</span>
                    </div>
                    ''' for name, enabled in features.items()])}
                </div>

                <div style="text-align: center;">
                    <a href="/" class="btn">
                        <span>🏠</span>
                        <span>Back to Dashboard</span>
                    </a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """)

@app.get("/incident/{incident_id}", include_in_schema=False)
async def incident_detail(incident_id: int, db: Session = Depends(get_db)):
    """Incident detail page with admin actions"""
    try:
        from database import Offense

        # Get the specific incident
        incident = db.query(Offense).filter(Offense.id == incident_id).first()
        if not incident:
            return HTMLResponse("<h1>Incident not found</h1>", status_code=404)

        # Get user's violation history
        user_violations = db.query(Offense)\
            .filter(Offense.user_principal_name == incident.user_principal_name)\
            .order_by(Offense.timestamp.desc())\
            .all()

        violation_count = len(user_violations)

        # Determine risk level
        if violation_count >= 3:
            risk_level = "CRITICAL"
            risk_color = "#ef4444"
            risk_icon = "🔴"
        elif violation_count >= 2:
            risk_level = "HIGH"
            risk_color = "#f59e0b"
            risk_icon = "🟠"
        else:
            risk_level = "MEDIUM"
            risk_color = "#3b82f6"
            risk_icon = "🟡"

        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Incident #{incident.id} - DLP Engine</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                    background: #000000;
                    color: #ffffff;
                    min-height: 100vh;
                    padding: 2rem;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                }}
                .header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 2rem;
                }}
                .header h1 {{
                    font-size: 2rem;
                    font-weight: 800;
                    color: #ffffff;
                }}
                .back-btn {{
                    display: inline-flex;
                    align-items: center;
                    gap: 0.5rem;
                    padding: 0.75rem 1.5rem;
                    background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
                    border: 1px solid rgba(156, 163, 175, 0.3);
                    border-radius: 1rem;
                    color: #ffffff;
                    font-weight: 700;
                    text-decoration: none;
                    transition: all 0.3s ease;
                }}
                .back-btn:hover {{
                    background: linear-gradient(135deg, #9ca3af 0%, #6b7280 100%);
                    transform: translateY(-2px);
                }}
                .card {{
                    background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
                    backdrop-filter: blur(30px);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    border-radius: 2rem;
                    padding: 2rem;
                    margin-bottom: 2rem;
                }}
                .section-title {{
                    font-size: 1.25rem;
                    font-weight: 700;
                    margin-bottom: 1.5rem;
                    color: #ffffff;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }}
                .info-grid {{
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 1.5rem;
                    margin-bottom: 2rem;
                }}
                .info-item {{
                    padding: 1.25rem;
                    background: rgba(255, 255, 255, 0.03);
                    border: 1px solid rgba(255, 255, 255, 0.08);
                    border-radius: 1rem;
                }}
                .info-label {{
                    color: #9ca3af;
                    font-weight: 600;
                    font-size: 0.75rem;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                    margin-bottom: 0.5rem;
                }}
                .info-value {{
                    color: #ffffff;
                    font-weight: 600;
                    font-size: 1.125rem;
                }}
                .risk-badge {{
                    display: inline-flex;
                    align-items: center;
                    gap: 0.5rem;
                    padding: 0.5rem 1rem;
                    background: rgba({int(risk_color[1:3], 16)}, {int(risk_color[3:5], 16)}, {int(risk_color[5:7], 16)}, 0.15);
                    border: 1px solid rgba({int(risk_color[1:3], 16)}, {int(risk_color[3:5], 16)}, {int(risk_color[5:7], 16)}, 0.3);
                    border-radius: 1rem;
                    color: {risk_color};
                    font-weight: 700;
                    font-size: 0.875rem;
                }}
                .actions {{
                    display: flex;
                    gap: 1rem;
                    flex-wrap: wrap;
                }}
                .action-btn {{
                    flex: 1;
                    min-width: 200px;
                    padding: 1rem 1.5rem;
                    border: none;
                    border-radius: 1rem;
                    font-weight: 700;
                    font-size: 0.875rem;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 0.5rem;
                }}
                .action-btn:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                }}
                .btn-education {{
                    background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
                    color: #ffffff;
                }}
                .btn-warning {{
                    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
                    color: #ffffff;
                }}
                .btn-revoke {{
                    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
                    color: #ffffff;
                }}
                .history-table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                .history-table thead {{
                    background: rgba(255, 255, 255, 0.05);
                }}
                .history-table th {{
                    padding: 1rem;
                    text-align: left;
                    color: #9ca3af;
                    font-weight: 600;
                    font-size: 0.75rem;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                }}
                .history-table td {{
                    padding: 1rem;
                    border-top: 1px solid rgba(255, 255, 255, 0.05);
                }}
                .history-table tbody tr:hover {{
                    background: rgba(156, 163, 175, 0.08);
                }}
                .success-msg, .error-msg {{
                    padding: 1rem;
                    border-radius: 1rem;
                    margin-bottom: 1rem;
                    font-weight: 600;
                    display: none;
                }}
                .success-msg {{
                    background: rgba(34, 197, 94, 0.1);
                    border: 1px solid rgba(34, 197, 94, 0.3);
                    color: #22c55e;
                }}
                .error-msg {{
                    background: rgba(239, 68, 68, 0.1);
                    border: 1px solid rgba(239, 68, 68, 0.3);
                    color: #ef4444;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 Incident #{incident.id}</h1>
                    <a href="/" class="back-btn">
                        <span>←</span>
                        <span>Back to Dashboard</span>
                    </a>
                </div>

                <div id="success-message" class="success-msg"></div>
                <div id="error-message" class="error-msg"></div>

                <div class="card">
                    <h2 class="section-title">📋 Incident Details</h2>
                    <div class="info-grid">
                        <div class="info-item">
                            <div class="info-label">Incident ID</div>
                            <div class="info-value">#{incident.id}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">User</div>
                            <div class="info-value">{incident.user_principal_name}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Incident Type</div>
                            <div class="info-value">{incident.incident_title}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Timestamp</div>
                            <div class="info-value">{incident.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') if incident.timestamp else 'Unknown'}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Total Violations</div>
                            <div class="info-value">{violation_count}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Risk Level</div>
                            <div class="info-value">
                                <span class="risk-badge">
                                    <span>{risk_icon}</span>
                                    <span>{risk_level}</span>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h2 class="section-title">⚡ Admin Actions</h2>
                    <div class="actions">
                        <button class="action-btn btn-education" onclick="performAction('education')">
                            <span>📚</span>
                            <span>Send Education Material</span>
                        </button>
                        <button class="action-btn btn-warning" onclick="performAction('warning')">
                            <span>⚠️</span>
                            <span>Send Warning Email</span>
                        </button>
                        <button class="action-btn btn-revoke" onclick="performAction('revoke')">
                            <span>🚫</span>
                            <span>Revoke Account Access</span>
                        </button>
                    </div>
                </div>

                <div class="card">
                    <h2 class="section-title">📜 Violation History ({violation_count} total)</h2>
                    <table class="history-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Incident Type</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join([f'''
                            <tr>
                                <td style="color: #9ca3af; font-family: monospace; font-weight: 700;">#{v.id}</td>
                                <td style="color: #ffffff;">{v.incident_title}</td>
                                <td style="color: #9ca3af;">{v.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') if v.timestamp else 'Unknown'}</td>
                            </tr>
                            ''' for v in user_violations])}
                        </tbody>
                    </table>
                </div>
            </div>

            <script>
                async function performAction(action) {{
                    const confirmMessages = {{
                        education: 'Send educational material to this user about data security?',
                        warning: 'Send a warning email to this user?',
                        revoke: 'REVOKE account access for this user? This will disable their account temporarily.'
                    }};

                    if (!confirm(confirmMessages[action])) {{
                        return;
                    }}

                    const successMsg = document.getElementById('success-message');
                    const errorMsg = document.getElementById('error-message');
                    successMsg.style.display = 'none';
                    errorMsg.style.display = 'none';

                    try {{
                        const response = await fetch('/api/incident/{incident.id}/action', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json'
                            }},
                            body: JSON.stringify({{
                                action: action,
                                user_email: '{incident.user_principal_name}'
                            }})
                        }});

                        const result = await response.json();

                        if (response.ok) {{
                            successMsg.textContent = '✅ ' + result.message;
                            successMsg.style.display = 'block';
                            window.scrollTo({{ top: 0, behavior: 'smooth' }});
                        }} else {{
                            errorMsg.textContent = '❌ ' + (result.detail || 'Action failed');
                            errorMsg.style.display = 'block';
                            window.scrollTo({{ top: 0, behavior: 'smooth' }});
                        }}
                    }} catch (error) {{
                        errorMsg.textContent = '❌ Network error: ' + error.message;
                        errorMsg.style.display = 'block';
                        window.scrollTo({{ top: 0, behavior: 'smooth' }});
                    }}
                }}
            </script>
        </body>
        </html>
        """)
    except Exception as e:
        logger.error(f"Error loading incident detail: {e}")
        return HTMLResponse(f"<h1>Error loading incident: {{str(e)}}</h1>", status_code=500)

@app.get("/redoc", include_in_schema=False)
async def custom_redoc():
    """Custom ReDoc with dark theme"""
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{settings.API_TITLE} - API Documentation</title>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
        <style>
            body {{
                margin: 0;
                padding: 0;
                background: #0a0a0a !important;
            }}
        </style>
    </head>
    <body>
        <redoc spec-url="/openapi.json"></redoc>
        <script src="https://cdn.jsdelivr.net/npm/redoc@latest/bundles/redoc.standalone.js"></script>
        <script>
            Redoc.init('/openapi.json', {{
                theme: {{
                    colors: {{
                        primary: {{
                            main: '#6b7280'
                        }},
                        success: {{
                            main: '#22c55e'
                        }},
                        warning: {{
                            main: '#f59e0b'
                        }},
                        error: {{
                            main: '#ef4444'
                        }},
                        text: {{
                            primary: '#ffffff',
                            secondary: '#9ca3af'
                        }},
                        background: {{
                            default: '#0a0a0a',
                            paper: '#1a1a1a'
                        }},
                        border: {{
                            main: '#2a2a2a'
                        }}
                    }},
                    typography: {{
                        fontSize: '14px',
                        fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, sans-serif',
                        headings: {{
                            fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, sans-serif',
                            fontWeight: '700'
                        }},
                        code: {{
                            fontFamily: 'Roboto Mono, Consolas, Monaco, monospace',
                            fontSize: '13px',
                            backgroundColor: '#1a1a1a',
                            color: '#9ca3af'
                        }}
                    }},
                    sidebar: {{
                        backgroundColor: '#0a0a0a',
                        textColor: '#9ca3af',
                        activeTextColor: '#ffffff',
                        groupItems: {{
                            textTransform: 'uppercase'
                        }}
                    }},
                    rightPanel: {{
                        backgroundColor: '#0f0f0f',
                        textColor: '#9ca3af'
                    }},
                    codeBlock: {{
                        backgroundColor: '#1a1a1a'
                    }}
                }},
                scrollYOffset: 0,
                hideDownloadButton: false,
                disableSearch: false,
                expandResponses: '200,201',
                jsonSampleExpandLevel: 2,
                hideSingleRequestSampleTab: true,
                menuToggle: true,
                nativeScrollbars: false,
                pathInMiddlePanel: true,
                sortPropsAlphabetically: true,
                showExtensions: true
            }}, document.getElementById('redoc'));
        </script>
    </body>
    </html>
    """)

@app.post("/api/incident/{incident_id}/action")
async def handle_incident_action(incident_id: int, request: dict, db: Session = Depends(get_db)):
    """Handle admin actions for incidents: education, warning, or revoke"""
    try:
        from database import Offense
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        action = request.get("action")
        user_email = request.get("user_email")

        if not action or not user_email:
            return JSONResponse({"detail": "Missing action or user_email"}, status_code=400)

        # Get incident details
        incident = db.query(Offense).filter(Offense.id == incident_id).first()
        if not incident:
            return JSONResponse({"detail": "Incident not found"}, status_code=404)

        # Determine action based on type
        if action == "education":
            # Send educational email
            subject = "Data Security Best Practices - Education Material"
            body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #3b82f6;">📚 Data Security Education</h2>
                    <p>Dear Team Member,</p>
                    <p>We've detected a potential data security incident related to your account. We want to help you understand best practices for protecting sensitive information.</p>

                    <h3>Key Data Security Guidelines:</h3>
                    <ul>
                        <li><strong>Never share sensitive personal information</strong> (KTP, NPWP, Employee IDs) via email</li>
                        <li><strong>Use secure file sharing platforms</strong> for confidential documents</li>
                        <li><strong>Verify recipient email addresses</strong> before sending sensitive data</li>
                        <li><strong>Encrypt sensitive files</strong> before sharing</li>
                        <li><strong>Report suspicious activities</strong> to IT Security immediately</li>
                    </ul>

                    <h3>What to do if you need to share sensitive data:</h3>
                    <ol>
                        <li>Contact IT Security for approved secure sharing methods</li>
                        <li>Use company-approved encrypted communication channels</li>
                        <li>Request proper authorization before sharing</li>
                    </ol>

                    <p style="margin-top: 20px;">If you have any questions about data security policies, please contact IT Security.</p>

                    <p style="margin-top: 20px; color: #666; font-size: 0.9em;">
                        This is an automated educational message from the DLP Remediation System.<br>
                        Incident ID: #{incident_id}
                    </p>
                </body>
            </html>
            """
            message_text = "Educational material sent successfully"

        elif action == "warning":
            # Send warning email
            violation_count = db.query(Offense).filter(Offense.user_principal_name == user_email).count()
            subject = "⚠️ Data Security Policy Violation Warning"
            body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #f59e0b;">⚠️ Official Warning: Data Security Policy Violation</h2>
                    <p>Dear Team Member,</p>
                    <p><strong>This is a formal warning regarding a violation of company data security policies.</strong></p>

                    <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0;">
                        <strong>Violation Details:</strong><br>
                        Incident ID: #{incident_id}<br>
                        Total Violations: {violation_count}<br>
                        Type: {incident.incident_title}
                    </div>

                    <h3>Immediate Actions Required:</h3>
                    <ol>
                        <li><strong>Review</strong> company data security policies immediately</li>
                        <li><strong>Complete</strong> mandatory data security training within 48 hours</li>
                        <li><strong>Acknowledge</strong> this warning by replying to IT Security</li>
                    </ol>

                    <h3>Consequences of Further Violations:</h3>
                    <ul style="color: #dc2626;">
                        <li>Account access suspension</li>
                        <li>Formal disciplinary action</li>
                        <li>Escalation to management and HR</li>
                    </ul>

                    <p style="margin-top: 20px;"><strong>This is a serious matter.</strong> Please take immediate corrective action to prevent further incidents.</p>

                    <p style="margin-top: 20px;">For questions or concerns, contact IT Security immediately.</p>

                    <p style="margin-top: 20px; color: #666; font-size: 0.9em;">
                        This is an official warning from the DLP Remediation System.<br>
                        Incident ID: #{incident_id} | Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
                    </p>
                </body>
            </html>
            """
            message_text = "Warning email sent successfully"

        elif action == "revoke":
            # Revoke account - this would integrate with Microsoft Graph API
            # For now, send notification and log the action
            subject = "🚫 URGENT: Account Access Suspended - Data Security Violation"
            body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #ef4444;">🚫 Account Access Suspended</h2>
                    <p>Dear Team Member,</p>
                    <p><strong style="color: #dc2626;">Your account access has been temporarily suspended due to critical data security policy violations.</strong></p>

                    <div style="background: #fee2e2; border-left: 4px solid #ef4444; padding: 15px; margin: 20px 0;">
                        <strong>Suspension Details:</strong><br>
                        Incident ID: #{incident_id}<br>
                        Suspension Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
                        Reason: Multiple data security policy violations
                    </div>

                    <h3>What This Means:</h3>
                    <ul>
                        <li>Your account access is temporarily disabled</li>
                        <li>You will not be able to access company systems</li>
                        <li>This action has been escalated to management and HR</li>
                    </ul>

                    <h3>Next Steps:</h3>
                    <ol>
                        <li><strong>Contact HR immediately</strong> for account reinstatement procedures</li>
                        <li><strong>Complete mandatory security training</strong> before reinstatement</li>
                        <li><strong>Meet with your manager</strong> to discuss corrective actions</li>
                    </ol>

                    <p style="margin-top: 20px; color: #dc2626;"><strong>DO NOT attempt to access systems using alternate accounts or methods.</strong></p>

                    <p style="margin-top: 20px;">Contact IT Security and HR for further instructions.</p>

                    <p style="margin-top: 20px; color: #666; font-size: 0.9em;">
                        This is an automated notification from the DLP Remediation System.<br>
                        Incident ID: #{incident_id} | Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
                    </p>
                </body>
            </html>
            """
            message_text = "Account access revocation initiated - User notified"

            # TODO: Integrate with Microsoft Graph API to actually disable the account
            # For now, just send the notification email
            logger.warning(f"REVOKE ACTION: User {user_email} - Incident #{incident_id} - Manual intervention required")

        else:
            return JSONResponse({"detail": "Invalid action"}, status_code=400)

        # Send email if email service is configured
        if EMAIL_ENABLED:
            try:
                msg = MIMEMultipart('alternative')
                msg['From'] = settings.SMTP_FROM_EMAIL
                msg['To'] = user_email
                msg['Subject'] = subject
                msg.attach(MIMEText(body, 'html'))

                with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
                    if settings.SMTP_USE_TLS:
                        server.starttls()
                    if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                    server.send_message(msg)

                logger.info(f"Action '{action}' completed for user {user_email} - Incident #{incident_id}")
            except Exception as e:
                logger.error(f"Failed to send email for action '{action}': {e}")
                return JSONResponse({"detail": f"Action logged but email failed: {str(e)}"}, status_code=500)
        else:
            logger.info(f"Action '{action}' logged for user {user_email} (email service disabled)")
            message_text += " (Email service not configured - action logged only)"

        return {"success": True, "message": message_text, "action": action, "incident_id": incident_id}

    except Exception as e:
        logger.error(f"Error handling incident action: {e}")
        return JSONResponse({"detail": str(e)}, status_code=500)

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
