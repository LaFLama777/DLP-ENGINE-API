
# python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
import os
import sys
import traceback
import asyncio
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

# Modules
from models import (
    RemediationRequest,
    HealthCheckResponse
)
from exceptions import (
    DLPEngineException,
    UserNotFoundException,
    GraphAPIException,
    DatabaseException
)
from middleware import (
    RequestIDMiddleware,
    LoggingMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware
)
from database import (
    create_db_and_tables,
    SessionLocal,
    log_offense_and_get_count,
    get_offense_count,
    Offense
)
from graph_client import get_user_details, perform_hard_block, perform_soft_block
from email_notifications import GraphEmailNotificationService
from app.ui_components import get_professional_sidebar, get_sidebar_css, get_sidebar_javascript, Icons
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
    logger.info("[OK] Database initialized")
except Exception as e:
    logger.error(f"[ERROR] Database initialization failed: {e}", exc_info=True)

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
# STEP 5: ADD MIDDLEWARE 
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
    logger.info("[OK] Graph Email notifications enabled")
except Exception as e:
    logger.error(f"[ERROR] Failed to initialize email service: {e}")
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

            /* Dark theme for select dropdowns */
            select {
                background: rgba(0, 0, 0, 0.5) !important;
                border: 1px solid rgba(255, 255, 255, 0.15) !important;
                color: #ffffff !important;
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23a1a1aa' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e") !important;
                background-repeat: no-repeat !important;
                background-position: right 0.5rem center !important;
                background-size: 1.25em 1.25em !important;
                padding-right: 2.5rem !important;
            }

            select:hover {
                border-color: rgba(255, 255, 255, 0.3) !important;
                background: rgba(0, 0, 0, 0.7) !important;
            }

            select:focus {
                outline: none !important;
                border-color: #667eea !important;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1) !important;
            }

            select option {
                background: #1a1a1a !important;
                color: #ffffff !important;
                padding: 10px !important;
            }

            select option:hover,
            select option:checked {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
                color: #ffffff !important;
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
                grid-template-columns: repeat(4, 1fr);
                gap: 1.5rem;
                margin-bottom: 3rem;
            }

            @media (max-width: 1400px) {
                .grid {
                    grid-template-columns: repeat(2, 1fr);
                }
            }

            @media (max-width: 768px) {
                .grid {
                    grid-template-columns: 1fr;
                }
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
                width: 24px;
                height: 24px;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .card-icon svg {
                width: 24px;
                height: 24px;
                stroke: #71717a;
                stroke-width: 2;
                fill: none;
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
                min-height: 450px;
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
                max-height: 240px !important;
                width: 100% !important;
                height: auto !important;
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

            /* Professional Collapsible Sidebar */
            .sidebar {
                position: fixed;
                left: 0;
                top: 0;
                width: 280px;
                height: 100vh;
                background: linear-gradient(180deg, #0f0f0f 0%, #000000 100%);
                border-right: 1px solid rgba(255, 255, 255, 0.08);
                transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                z-index: 1000;
                overflow: hidden;
            }

            .sidebar.collapsed {
                width: 64px;
            }

            .sidebar-header {
                padding: 24px 20px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.08);
                display: flex;
                align-items: center;
                justify-content: space-between;
                height: 72px;
            }

            .sidebar-brand {
                display: flex;
                align-items: center;
                gap: 12px;
                white-space: nowrap;
                overflow: hidden;
            }

            .brand-icon {
                width: 32px;
                height: 32px;
                background: linear-gradient(135deg, #ffffff 0%, #a3a3a3 100%);
                border-radius: 8px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 800;
                color: #000;
                flex-shrink: 0;
            }

            .brand-text {
                display: flex;
                flex-direction: column;
                opacity: 1;
                transition: opacity 0.2s;
            }

            .sidebar.collapsed .brand-text {
                opacity: 0;
                width: 0;
            }

            .brand-title {
                font-size: 15px;
                font-weight: 700;
                color: #ffffff;
                letter-spacing: -0.01em;
            }

            .brand-subtitle {
                font-size: 10px;
                color: #737373;
                font-weight: 500;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }

            .sidebar-toggle {
                width: 28px;
                height: 28px;
                border-radius: 6px;
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: all 0.2s;
                flex-shrink: 0;
            }

            .sidebar-toggle:hover {
                background: rgba(255, 255, 255, 0.1);
                border-color: rgba(255, 255, 255, 0.2);
            }

            .sidebar-toggle svg {
                width: 16px;
                height: 16px;
                stroke: #a3a3a3;
                transition: transform 0.3s;
            }

            .sidebar.collapsed .sidebar-toggle svg {
                transform: rotate(180deg);
            }

            .sidebar-nav {
                padding: 16px 8px;
                overflow-y: auto;
                height: calc(100vh - 72px);
            }

            .sidebar-nav::-webkit-scrollbar {
                width: 4px;
            }

            .sidebar-nav::-webkit-scrollbar-thumb {
                background: rgba(255, 255, 255, 0.1);
                border-radius: 2px;
            }

            .nav-section {
                margin-bottom: 24px;
            }

            .nav-section-title {
                padding: 8px 12px;
                font-size: 10px;
                font-weight: 600;
                color: #525252;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                white-space: nowrap;
                overflow: hidden;
                transition: opacity 0.2s;
            }

            .sidebar.collapsed .nav-section-title {
                opacity: 0;
                height: 0;
                padding: 0;
            }

            .nav-item {
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 10px 12px;
                margin: 2px 0;
                border-radius: 8px;
                color: #a3a3a3;
                text-decoration: none;
                font-size: 14px;
                font-weight: 500;
                transition: all 0.2s;
                white-space: nowrap;
                position: relative;
            }

            .nav-item:hover {
                background: rgba(255, 255, 255, 0.05);
                color: #ffffff;
            }

            .nav-item.active {
                background: rgba(255, 255, 255, 0.08);
                color: #ffffff;
            }

            .nav-item.active::before {
                content: '';
                position: absolute;
                left: 0;
                top: 50%;
                transform: translateY(-50%);
                width: 3px;
                height: 20px;
                background: #ffffff;
                border-radius: 0 2px 2px 0;
            }

            .nav-icon {
                width: 20px;
                height: 20px;
                flex-shrink: 0;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .nav-icon svg {
                width: 18px;
                height: 18px;
                stroke: currentColor;
                fill: none;
            }

            .nav-text {
                overflow: hidden;
                opacity: 1;
                transition: opacity 0.2s;
            }

            .sidebar.collapsed .nav-text {
                opacity: 0;
                width: 0;
            }

            /* Main content adjustment */
            .main-wrapper {
                margin-left: 280px;
                transition: margin-left 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }

            .main-wrapper.sidebar-collapsed {
                margin-left: 64px;
            }

            @media (max-width: 768px) {
                .sidebar {
                    transform: translateX(-100%);
                }
                .main-wrapper {
                    margin-left: 0 !important;
                }
            }
        </style>
    </head>
    <body>
        <!-- Professional Collapsible Sidebar -->
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-brand">
                    <div class="brand-icon">D</div>
                    <div class="brand-text">
                        <div class="brand-title">DLP Engine</div>
                        <div class="brand-subtitle">Enterprise</div>
                    </div>
                </div>
                <div class="sidebar-toggle" onclick="toggleSidebar()">
                    <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="3" y1="12" x2="21" y2="12"></line>
                        <line x1="3" y1="6" x2="21" y2="6"></line>
                        <line x1="3" y1="18" x2="21" y2="18"></line>
                    </svg>
                </div>
            </div>

            <nav class="sidebar-nav">
                <div class="nav-section">
                    <div class="nav-section-title">Overview</div>
                    <a href="/" class="nav-item active">
                        <div class="nav-icon">
                            <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="3" y="3" width="7" height="7"></rect>
                                <rect x="14" y="3" width="7" height="7"></rect>
                                <rect x="14" y="14" width="7" height="7"></rect>
                                <rect x="3" y="14" width="7" height="7"></rect>
                            </svg>
                        </div>
                        <span class="nav-text">Dashboard</span>
                    </a>
                    <a href="/incidents" class="nav-item">
                        <div class="nav-icon">
                            <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="11" cy="11" r="8"></circle>
                                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                            </svg>
                        </div>
                        <span class="nav-text">All Incidents</span>
                    </a>
                </div>

                <div class="nav-section">
                    <div class="nav-section-title">Monitoring</div>
                    <a href="/health" class="nav-item">
                        <div class="nav-icon">
                            <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
                            </svg>
                        </div>
                        <span class="nav-text">System Health</span>
                    </a>
                    <a href="/redoc" class="nav-item">
                        <div class="nav-icon">
                            <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                                <polyline points="14 2 14 8 20 8"></polyline>
                                <line x1="16" y1="13" x2="8" y2="13"></line>
                                <line x1="16" y1="17" x2="8" y2="17"></line>
                                <polyline points="10 9 9 9 8 9"></polyline>
                            </svg>
                        </div>
                        <span class="nav-text">API Documentation</span>
                    </a>
                </div>

                <div class="nav-section">
                    <div class="nav-section-title">Resources</div>
                    <a href="https://github.com/anthropics/claude-code" target="_blank" class="nav-item">
                        <div class="nav-icon">
                            <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path>
                                <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path>
                            </svg>
                        </div>
                        <span class="nav-text">Documentation</span>
                    </a>
                    <a href="https://portal.azure.com" target="_blank" class="nav-item">
                        <div class="nav-icon">
                            <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"></path>
                            </svg>
                        </div>
                        <span class="nav-text">Azure Portal</span>
                    </a>
                </div>
            </nav>
        </div>

        <div class="main-wrapper" id="mainWrapper">
        <div class="container">
            <!-- Statistics Cards -->
            <div class="grid">
                <div class="card">
                    <div class="card-title">
                        <span class="card-icon">
                            <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                                <line x1="12" y1="9" x2="12" y2="13"></line>
                                <line x1="12" y1="17" x2="12.01" y2="17"></line>
                            </svg>
                        </span>
                        TOTAL VIOLATIONS
                    </div>
                    <div class="card-value" id="total-violations">--</div>
                    <div class="card-description">All-time incidents detected</div>
                </div>
                <div class="card">
                    <div class="card-title">
                        <span class="card-icon">
                            <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>
                                <line x1="16" y1="2" x2="16" y2="6"></line>
                                <line x1="8" y1="2" x2="8" y2="6"></line>
                                <line x1="3" y1="10" x2="21" y2="10"></line>
                            </svg>
                        </span>
                        TODAY'S VIOLATIONS
                    </div>
                    <div class="card-value" id="today-violations">--</div>
                    <div class="card-description">Incidents detected today</div>
                </div>
                <div class="card">
                    <div class="card-title">
                        <span class="card-icon">
                            <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                                <circle cx="9" cy="7" r="4"></circle>
                                <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
                                <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
                            </svg>
                        </span>
                        MONITORED USERS
                    </div>
                    <div class="card-value" id="total-users">--</div>
                    <div class="card-description">Unique users tracked</div>
                </div>
                <div class="card">
                    <div class="card-title">
                        <span class="card-icon">
                            <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                                <line x1="12" y1="9" x2="12" y2="13"></line>
                                <line x1="12" y1="17" x2="12.01" y2="17"></line>
                            </svg>
                        </span>
                        HIGH RISK USERS
                    </div>
                    <div class="card-value" id="high-risk-users">--</div>
                    <div class="card-description">Users with 3+ violations</div>
                </div>
            </div>

            <!-- Charts Row -->
            <div class="charts-row">
                <div class="chart-card">
                    <div class="chart-header" style="flex-wrap: wrap; gap: 12px;">
                        <h3 class="chart-title">
                            <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" style="display: inline-block; vertical-align: middle; margin-right: 8px;">
                                <polyline points="23 6 13.5 15.5 8.5 10.5 1 18"></polyline>
                                <polyline points="17 6 23 6 23 12"></polyline>
                            </svg>
                            Violation Trend
                        </h3>
                        <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                            <select id="periodSelect" onchange="updatePeriodFilter()" style="background: rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.15); color: #a1a1aa; padding: 8px 14px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; min-width: 140px; transition: all 0.2s;">
                                <option value="all">All Time</option>
                                <option value="today">Today</option>
                                <option value="week">Last 7 Days</option>
                                <option value="month">Last 30 Days</option>
                                <option value="custom">Custom Range</option>
                            </select>
                            <div id="customDateRange" style="display: none; gap: 8px; align-items: center;">
                                <input type="date" id="startDate" style="background: rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.15); color: #a1a1aa; padding: 8px 12px; border-radius: 8px; font-size: 13px;">
                                <span style="color: #71717a;">to</span>
                                <input type="date" id="endDate" style="background: rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.15); color: #a1a1aa; padding: 8px 12px; border-radius: 8px; font-size: 13px;">
                                <button onclick="applyCustomDateFilter()" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 8px 16px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.2s; font-size: 13px;">Apply</button>
                            </div>
                        </div>
                    </div>
                    <div style="flex: 1; position: relative; max-height: 300px;">
                        <canvas id="trendChart"></canvas>
                    </div>
                </div>
                <div class="chart-card">
                    <div class="chart-header">
                        <h3 class="chart-title">
                            <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" style="display: inline-block; vertical-align: middle; margin-right: 8px;">
                                <circle cx="12" cy="12" r="10"></circle>
                                <circle cx="12" cy="12" r="6"></circle>
                                <circle cx="12" cy="12" r="2"></circle>
                            </svg>
                            Attack Types
                        </h3>
                    </div>
                    <div style="flex: 0 0 auto; position: relative; max-height: 240px; margin-bottom: 1.5rem;">
                        <canvas id="typeChart"></canvas>
                    </div>
                    <div id="type-legend" style="flex: 1 1 auto; overflow-y: auto; max-height: 200px;"></div>
                </div>
            </div>

            <!-- Recent Incidents Table -->
            <div class="table-container">
                <div class="table-header">
                    <h3 class="table-title">
                        <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" style="display: inline-block; vertical-align: middle; margin-right: 8px;">
                            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
                            <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
                        </svg>
                        Recent Incidents
                    </h3>
                    <div style="display: flex; gap: 12px;">
                        <a href="/incidents" class="btn" style="text-decoration: none;">
                            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                                <circle cx="11" cy="11" r="8"></circle>
                                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                            </svg>
                            <span>View All</span>
                        </a>
                        <button onclick="loadDashboardData()" class="btn">
                            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                                <polyline points="23 4 23 10 17 10"></polyline>
                                <polyline points="1 20 1 14 7 14"></polyline>
                                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
                            </svg>
                            <span>Refresh</span>
                        </button>
                    </div>
                </div>
                <div style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>User</th>
                                <th>Incident</th>
                                <th>Attack Type</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody id="incidents-table">
                            <tr><td colspan="5" style="text-align: center; padding: 3rem; color: #52525b;">Loading incidents...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Call to Action -->
            <div class="cta-section">
                <a href="/docs" class="btn">
                    <span>LEARN</span>
                    <span>API Documentation</span>
                </a>
                <a href="/redoc" class="btn btn-secondary">
                    <span>DOCS</span>
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
            let currentDateFilter = { period: 'all', start_date: null, end_date: null };

            // Date filter functions
            function updatePeriodFilter() {
                const period = document.getElementById('periodSelect').value;
                const customRange = document.getElementById('customDateRange');

                if (period === 'custom') {
                    customRange.style.display = 'flex';
                } else {
                    customRange.style.display = 'none';
                    currentDateFilter = { period: period, start_date: null, end_date: null };
                    loadDashboardData();
                }
            }

            function applyCustomDateFilter() {
                const startDate = document.getElementById('startDate').value;
                const endDate = document.getElementById('endDate').value;

                if (startDate && endDate) {
                    currentDateFilter = { period: 'custom', start_date: startDate, end_date: endDate };
                    loadDashboardData();
                } else {
                    alert('Please select both start and end dates');
                }
            }

            async function loadDashboardData() {
                try {
                    // Build query params with date filter
                    let params = new URLSearchParams();
                    if (currentDateFilter.period) params.append('period', currentDateFilter.period);
                    if (currentDateFilter.start_date) params.append('start_date', currentDateFilter.start_date);
                    if (currentDateFilter.end_date) params.append('end_date', currentDateFilter.end_date);
                    const queryString = params.toString() ? '?' + params.toString() : '';

                    // Load statistics with date filter
                    const statsResponse = await fetch('/api/statistics' + queryString);
                    const stats = await statsResponse.json();

                    document.getElementById('total-violations').textContent = stats.total_violations || 0;
                    document.getElementById('today-violations').textContent = stats.today_violations || 0;
                    document.getElementById('total-users').textContent = stats.total_users || 0;
                    document.getElementById('high-risk-users').textContent = stats.high_risk_users || 0;

                    // Load trend data and create chart
                    const trendResponse = await fetch('/api/violations/trend?days=30' + (queryString ? '&' + params.toString() : ''));
                    const trendData = await trendResponse.json();
                    createTrendChart(trendData);

                    // Load violation types and create chart with date filter
                    const typesResponse = await fetch('/api/violations/by-type' + queryString);
                    const typesData = await typesResponse.json();
                    createTypeChart(typesData);

                    // Load recent incidents with date filter (limited to 8)
                    const incidentsResponse = await fetch('/api/violations/recent?limit=8' + (queryString ? '&' + params.toString() : ''));
                    const incidents = await incidentsResponse.json();
                    displayIncidents(incidents);

                } catch (error) {
                    console.error('Error loading dashboard:', error);
                    alert('Error loading dashboard data. Please refresh the page.');
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
                // Updated color palette to support more violation types
                const colorMap = {
                    'KTP': '#60a5fa',
                    'NPWP': '#10b981',
                    'Employee ID': '#f59e0b',
                    'Credit Card': '#ef4444',
                    'Passport': '#8b5cf6',
                    'Phone Number': '#ec4899',
                    'Email Address': '#06b6d4',
                    'Sensitive Data': '#f97316',
                    'Other': '#71717a'
                };
                const colors = labels.map(label => colorMap[label] || '#6b7280');

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
                        aspectRatio: 1.5,
                        plugins: {
                            legend: {
                                display: false  // Disabled built-in legend, using custom legend below
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

                // Create legend with improved alignment and wrapping
                const legendHtml = data.map((d, i) => `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 1rem 0; border-bottom: 1px solid rgba(255,255,255,0.05); gap: 1rem;">
                        <span style="display: flex; align-items: center; gap: 0.75rem; color: #a1a1aa; font-weight: 600; flex: 1; min-width: 0;">
                            <span style="width: 16px; height: 16px; background: ${colors[i]}; border-radius: 50%; box-shadow: 0 0 20px ${colors[i]}80; flex-shrink: 0;"></span>
                            <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${d.type}</span>
                        </span>
                        <strong style="color: #ffffff; font-size: 1.125rem; flex-shrink: 0;">${d.count}</strong>
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
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 3rem; color: #52525b;">No incidents found</td></tr>';
                    return;
                }

                const rows = incidents.map(inc => {
                    // Detect attack type from incident title (case-insensitive)
                    let attackType = 'Other';
                    let attackColor = '#71717a';
                    const title = inc.incident_title.toLowerCase();

                    if (title.includes('ktp') || title.includes('nik')) {
                        attackType = 'KTP';
                        attackColor = '#60a5fa';
                    } else if (title.includes('npwp')) {
                        attackType = 'NPWP';
                        attackColor = '#10b981';
                    } else if (title.includes('employee')) {
                        attackType = 'Employee ID';
                        attackColor = '#f59e0b';
                    } else if (title.includes('credit card') || title.includes('card number')) {
                        attackType = 'Credit Card';
                        attackColor = '#ef4444';
                    } else if (title.includes('passport') || title.includes('paspor')) {
                        attackType = 'Passport';
                        attackColor = '#8b5cf6';
                    } else if (title.includes('phone') || title.includes('telepon')) {
                        attackType = 'Phone Number';
                        attackColor = '#ec4899';
                    } else if (title.includes('email') || title.includes('e-mail')) {
                        attackType = 'Email Address';
                        attackColor = '#06b6d4';
                    } else if (title.includes('sensitive data') || title.includes('confidential')) {
                        attackType = 'Sensitive Data';
                        attackColor = '#f97316';
                    }

                    return `
                    <tr onclick="window.location.href='/incident/${inc.id}'" style="cursor: pointer;">
                        <td style="font-family: 'Courier New', monospace; font-weight: 700; color: #9ca3af;">
                            <a href="/incident/${inc.id}" style="color: #9ca3af; text-decoration: none; display: block;">
                                #${inc.id}
                            </a>
                        </td>
                        <td style="color: #ffffff; font-weight: 600;">${inc.user}</td>
                        <td style="color: #a1a1aa; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${inc.incident_title}</td>
                        <td>
                            <span style="background: ${attackColor}22; color: ${attackColor}; padding: 6px 14px; border-radius: 8px; font-size: 0.875rem; font-weight: 700; border: 1px solid ${attackColor}44; display: inline-block;">
                                ${attackType}
                            </span>
                        </td>
                        <td style="color: #71717a; font-weight: 600;">${inc.time_ago}</td>
                    </tr>
                `;
                }).join('');

                tbody.innerHTML = rows;
            }

            // Load dashboard on page load
            window.addEventListener('DOMContentLoaded', function() {
                loadDashboardData();
            });

            // Manual refresh available via the "Refresh" button in the UI
            // Removed auto-refresh to prevent performance issues and excessive API calls
        </script>

        <script>
            // Sidebar toggle functionality
            function toggleSidebar() {
                const sidebar = document.getElementById('sidebar');
                const mainWrapper = document.getElementById('mainWrapper');
                sidebar.classList.toggle('collapsed');
                mainWrapper.classList.toggle('sidebar-collapsed');

                // Save state to localStorage
                const isCollapsed = sidebar.classList.contains('collapsed');
                localStorage.setItem('sidebarCollapsed', isCollapsed);
            }

            // Restore sidebar state on load
            window.addEventListener('DOMContentLoaded', () => {
                const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
                if (isCollapsed) {
                    document.getElementById('sidebar').classList.add('collapsed');
                    document.getElementById('mainWrapper').classList.add('sidebar-collapsed');
                }
            });
        </script>
        </div>
        </div>
    </body>
    </html>
    """

@app.get("/api/statistics")
async def get_statistics(
    period: str = "all",
    start_date: str = None,
    end_date: str = None,
    db: Session = Depends(get_db)
):
    """Get dashboard statistics with date filtering"""
    try:
        from datetime import datetime, timedelta
        from sqlalchemy import func, cast, Date
        from database import Offense

        # Jakarta timezone
        jakarta_tz = timedelta(hours=7)
        now = datetime.utcnow()
        now_jakarta = now + jakarta_tz

        # Calculate date range based on period or custom dates
        if start_date and end_date:
            filter_start = datetime.strptime(start_date, "%Y-%m-%d") - jakarta_tz
            filter_end = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1) - jakarta_tz
        elif period == "today":
            today = now_jakarta.date()
            filter_start = datetime.combine(today, datetime.min.time()) - jakarta_tz
            filter_end = datetime.combine(today, datetime.max.time()) - jakarta_tz
        elif period == "week":
            filter_start = (now_jakarta - timedelta(days=7)).replace(hour=0, minute=0, second=0) - jakarta_tz
            filter_end = now - jakarta_tz
        elif period == "month":
            filter_start = (now_jakarta - timedelta(days=30)).replace(hour=0, minute=0, second=0) - jakarta_tz
            filter_end = now - jakarta_tz
        else:  # "all"
            filter_start = None
            filter_end = None

        # Base query with optional date filter
        base_query = db.query(Offense)
        if filter_start and filter_end:
            base_query = base_query.filter(
                Offense.timestamp >= filter_start,
                Offense.timestamp <= filter_end
            )

        # Total violations (filtered)
        total_violations = base_query.count() or 0

        # Today's violations (always today, not filtered)
        today_start = datetime(now.year, now.month, now.day)
        today_violations = db.query(func.count(Offense.id))\
            .filter(Offense.timestamp >= today_start)\
            .scalar() or 0

        # This week's violations
        week_ago = now - timedelta(days=7)
        week_violations = db.query(func.count(Offense.id))\
            .filter(Offense.timestamp >= week_ago)\
            .scalar() or 0

        # This month's violations
        month_ago = now - timedelta(days=30)

        # Unique users with violations (filtered)
        total_users = base_query.with_entities(func.count(func.distinct(Offense.user_principal_name)))\
            .scalar() or 0

        # High risk users (3+ violations) - from filtered data
        high_risk_subquery = base_query.with_entities(
            Offense.user_principal_name,
            func.count(Offense.id).label('offense_count')
        ).group_by(Offense.user_principal_name).subquery()

        high_risk_users = db.query(high_risk_subquery).filter(
            high_risk_subquery.c.offense_count >= 3
        ).count()

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
async def get_recent_violations(
    limit: int = 20,
    period: str = "all",
    start_date: str = None,
    end_date: str = None,
    db: Session = Depends(get_db)
):
    """Get recent violations for incidents table with date filtering"""
    try:
        from database import Offense
        from datetime import timedelta

        # Jakarta timezone and date filtering logic
        jakarta_tz = timedelta(hours=7)
        now = datetime.utcnow()
        now_jakarta = now + jakarta_tz

        # Calculate date range
        if start_date and end_date:
            filter_start = datetime.strptime(start_date, "%Y-%m-%d") - jakarta_tz
            filter_end = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1) - jakarta_tz
        elif period == "today":
            today = now_jakarta.date()
            filter_start = datetime.combine(today, datetime.min.time()) - jakarta_tz
            filter_end = datetime.combine(today, datetime.max.time()) - jakarta_tz
        elif period == "week":
            filter_start = (now_jakarta - timedelta(days=7)).replace(hour=0, minute=0, second=0) - jakarta_tz
            filter_end = now - jakarta_tz
        elif period == "month":
            filter_start = (now_jakarta - timedelta(days=30)).replace(hour=0, minute=0, second=0) - jakarta_tz
            filter_end = now - jakarta_tz
        else:  # "all"
            filter_start = None
            filter_end = None

        # Base query with optional date filter
        query = db.query(Offense).order_by(Offense.timestamp.desc())
        if filter_start and filter_end:
            query = query.filter(
                Offense.timestamp >= filter_start,
                Offense.timestamp <= filter_end
            )

        violations = query.limit(limit).all()

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
async def get_violation_trend(
    days: int = 30,
    period: str = "all",
    start_date: str = None,
    end_date: str = None,
    db: Session = Depends(get_db)
):
    """Get violation trend data for charts with date filtering support"""
    try:
        from datetime import datetime, timedelta
        from sqlalchemy import func, cast, Date
        from database import Offense

        # Jakarta timezone offset
        jakarta_tz = timedelta(hours=7)
        now = datetime.utcnow()
        now_jakarta = now + jakarta_tz

        # Calculate date range based on period or custom dates
        if start_date and end_date:
            filter_start = datetime.strptime(start_date, "%Y-%m-%d") - jakarta_tz
            filter_end = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1) - jakarta_tz
        elif period == "today":
            today = now_jakarta.date()
            filter_start = datetime.combine(today, datetime.min.time()) - jakarta_tz
            filter_end = datetime.combine(today, datetime.max.time()) - jakarta_tz
        elif period == "week":
            filter_start = now - timedelta(days=7)
            filter_end = now
        elif period == "month":
            filter_start = now - timedelta(days=30)
            filter_end = now
        else:  # "all" or default
            filter_end = now
            filter_start = filter_end - timedelta(days=days)

        # Group violations by date
        base_query = db.query(
            cast(Offense.timestamp, Date).label('date'),
            func.count(Offense.id).label('count')
        )

        if period != "all" or (start_date and end_date):
            base_query = base_query.filter(
                Offense.timestamp >= filter_start,
                Offense.timestamp <= filter_end
            )
        else:
            base_query = base_query.filter(Offense.timestamp >= filter_start)

        daily_counts = base_query.group_by(
            cast(Offense.timestamp, Date)
        ).order_by('date').all()

        # Fill in missing dates with 0
        date_dict = {item.date.isoformat(): item.count for item in daily_counts}

        result = []
        current = filter_start.date()
        while current <= filter_end.date():
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
async def get_violations_by_type(
    period: str = "all",
    start_date: str = None,
    end_date: str = None,
    db: Session = Depends(get_db)
):
    """Get violations grouped by type with date filtering"""
    try:
        from database import Offense
        from collections import Counter
        from datetime import timedelta

        # Jakarta timezone and date filtering logic
        jakarta_tz = timedelta(hours=7)
        now = datetime.utcnow()
        now_jakarta = now + jakarta_tz

        # Calculate date range
        if start_date and end_date:
            filter_start = datetime.strptime(start_date, "%Y-%m-%d") - jakarta_tz
            filter_end = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1) - jakarta_tz
        elif period == "today":
            today = now_jakarta.date()
            filter_start = datetime.combine(today, datetime.min.time()) - jakarta_tz
            filter_end = datetime.combine(today, datetime.max.time()) - jakarta_tz
        elif period == "week":
            filter_start = (now_jakarta - timedelta(days=7)).replace(hour=0, minute=0, second=0) - jakarta_tz
            filter_end = now - jakarta_tz
        elif period == "month":
            filter_start = (now_jakarta - timedelta(days=30)).replace(hour=0, minute=0, second=0) - jakarta_tz
            filter_end = now - jakarta_tz
        else:  # "all"
            filter_start = None
            filter_end = None

        # Base query with optional date filter
        query = db.query(Offense.incident_title)
        if filter_start and filter_end:
            query = query.filter(
                Offense.timestamp >= filter_start,
                Offense.timestamp <= filter_end
            )

        violations = query.all()

        # Extract violation types from incident titles
        type_counts = Counter()
        for v in violations:
            title = v.incident_title.lower()

            # Check for specific patterns and categorize
            # Using if-elif-else to ensure each violation is counted only once
            if 'ktp' in title or 'nik' in title or '16 digit' in title or 'national id' in title:
                type_counts['KTP'] += 1
            elif 'npwp' in title or 'tax id' in title or 'tax number' in title:
                type_counts['NPWP'] += 1
            elif 'employee' in title or 'kary' in title or 'emp-' in title or 'nip' in title or 'employee id' in title:
                type_counts['Employee ID'] += 1
            elif 'credit card' in title or 'card number' in title or 'cc number' in title:
                type_counts['Credit Card'] += 1
            elif 'passport' in title or 'paspor' in title:
                type_counts['Passport'] += 1
            elif 'phone' in title or 'telepon' in title or 'mobile' in title:
                type_counts['Phone Number'] += 1
            elif 'email' in title or 'e-mail' in title:
                type_counts['Email Address'] += 1
            elif 'sensitive data' in title or 'confidential' in title or 'dlp policy' in title or 'classified' in title:
                # Generic DLP policy violations - categorize as "Sensitive Data"
                type_counts['Sensitive Data'] += 1
            else:
                # Any other type that doesn't match above patterns
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
        db_icon = "[OK]"
        db_color = "#22c55e"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "unhealthy"
        db_icon = "[ERROR]"
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

            {get_sidebar_css()}
        </style>
    </head>
    <body>
        {get_professional_sidebar('health')}

        <div class="main-wrapper" id="mainWrapper">
        <div class="container">
            <div class="card">
                <div class="header">
                    <h1>
                        {Icons.alert_triangle(32)}
                        System Health
                    </h1>
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
                            <svg viewBox="0 0 24 24" width="20" height="20" stroke="{db_color}" stroke-width="2" fill="none" style="display: inline-block; vertical-align: middle; margin-right: 4px;">
                                {"<circle cx='12' cy='12' r='10'></circle><path d='M9 12l2 2 4-4'></path>" if db_status == "healthy" else "<circle cx='12' cy='12' r='10'></circle><line x1='15' y1='9' x2='9' y2='15'></line><line x1='9' y1='9' x2='15' y2='15'></line>"}
                            </svg>
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
                        <span class="feature-icon">
                            <svg viewBox="0 0 24 24" width="18" height="18" stroke="{'#22c55e' if enabled else '#ef4444'}" stroke-width="2" fill="none">
                                {"<circle cx='12' cy='12' r='10'></circle><path d='M9 12l2 2 4-4'></path>" if enabled else "<circle cx='12' cy='12' r='10'></circle><line x1='15' y1='9' x2='9' y2='15'></line><line x1='9' y1='9' x2='15' y2='15'></line>"}
                            </svg>
                        </span>
                        <span class="feature-name">{name}</span>
                    </div>
                    ''' for name, enabled in features.items()])}
                </div>

                <div style="text-align: center;">
                    <a href="/" class="btn">
                        {Icons.shield(16)}
                        <span>Back to Dashboard</span>
                    </a>
                </div>
            </div>
        </div>
        </div>

        {get_sidebar_javascript()}
    </body>
    </html>
    """)

@app.get("/incidents", include_in_schema=False)
async def incidents_overview(
    db: Session = Depends(get_db),
    search: str = "",
    severity: str = "",
    page: int = 1,
    limit: int = 50
):
    """Incidents overview page with search, filter, and pagination"""
    try:
        from database import Offense
        from sqlalchemy import or_, func

        # Build query
        query = db.query(Offense)

        # Search filter (user email or incident title)
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                or_(
                    Offense.user_principal_name.ilike(search_pattern),
                    Offense.incident_title.ilike(search_pattern)
                )
            )

        # Severity filter
        if severity:
            if severity == "CRITICAL":
                # Get users with 3+ violations
                user_counts = db.query(
                    Offense.user_principal_name,
                    func.count(Offense.id).label('count')
                ).group_by(Offense.user_principal_name).having(func.count(Offense.id) >= 3).all()
                critical_users = [u[0] for u in user_counts]
                query = query.filter(Offense.user_principal_name.in_(critical_users))
            elif severity == "HIGH":
                user_counts = db.query(
                    Offense.user_principal_name,
                    func.count(Offense.id).label('count')
                ).group_by(Offense.user_principal_name).having(func.count(Offense.id) == 2).all()
                high_users = [u[0] for u in user_counts]
                query = query.filter(Offense.user_principal_name.in_(high_users))
            elif severity == "MEDIUM":
                user_counts = db.query(
                    Offense.user_principal_name,
                    func.count(Offense.id).label('count')
                ).group_by(Offense.user_principal_name).having(func.count(Offense.id) == 1).all()
                medium_users = [u[0] for u in user_counts]
                query = query.filter(Offense.user_principal_name.in_(medium_users))

        # Get total count before pagination
        total_incidents = query.count()

        # Pagination
        offset = (page - 1) * limit
        incidents = query.order_by(Offense.timestamp.desc()).offset(offset).limit(limit).all()

        # Calculate violation counts per user for risk levels
        user_violation_counts = {}
        for incident in incidents:
            if incident.user_principal_name not in user_violation_counts:
                count = db.query(func.count(Offense.id))\
                    .filter(Offense.user_principal_name == incident.user_principal_name)\
                    .scalar()
                user_violation_counts[incident.user_principal_name] = count

        # Calculate pagination info
        total_pages = (total_incidents + limit - 1) // limit
        has_prev = page > 1
        has_next = page < total_pages

        # Format incidents for display
        def get_risk_level(count):
            if count >= 3:
                return {"level": "CRITICAL", "color": "#ef4444", "icon": "🔴"}
            elif count == 2:
                return {"level": "MEDIUM", "color": "#f59e0b", "icon": "🟠"}
            else:
                return {"level": "LOW", "color": "#10b981", "icon": "🟢"}

        def get_violation_type_badge(title):
            title_lower = title.lower()
            if 'ktp' in title_lower or '16 digit' in title_lower:
                return '<span class="violation-badge ktp">KTP</span>'
            elif 'npwp' in title_lower or 'tax' in title_lower:
                return '<span class="violation-badge npwp">NPWP</span>'
            elif 'employee' in title_lower or 'kary' in title_lower:
                return '<span class="violation-badge empid">Employee ID</span>'
            else:
                return '<span class="violation-badge other">Sensitive Data</span>'

        def format_time_ago(timestamp):
            if not timestamp:
                return "Unknown"
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            diff = now - timestamp

            if diff.days > 30:
                months = diff.days // 30
                return f"{months} month{'s' if months != 1 else ''} ago"
            elif diff.days > 0:
                return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
            elif diff.seconds >= 3600:
                hours = diff.seconds // 3600
                return f"{hours} hour{'s' if hours != 1 else ''} ago"
            elif diff.seconds >= 60:
                minutes = diff.seconds // 60
                return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
            else:
                return "Just now"

        incidents_html = ""
        for inc in incidents:
            violation_count = user_violation_counts.get(inc.user_principal_name, 1)
            risk = get_risk_level(violation_count)
            violation_badge = get_violation_type_badge(inc.incident_title)
            time_ago = format_time_ago(inc.timestamp)

            incidents_html += f'''
            <tr onclick="window.location.href='/incident/{inc.id}'" style="cursor: pointer;">
                <td>
                    <a href="/incident/{inc.id}" style="color: #9ca3af; text-decoration: none;">
                        #{inc.id}
                    </a>
                </td>
                <td>{inc.user_principal_name}</td>
                <td>{violation_badge}</td>
                <td>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 20px;">{risk['icon']}</span>
                        <span style="color: {risk['color']}; font-weight: 600;">{risk['level']}</span>
                        <span style="color: #6b7280;">({violation_count} violation{'s' if violation_count != 1 else ''})</span>
                    </div>
                </td>
                <td>{time_ago}</td>
            </tr>
            '''

        if not incidents_html:
            incidents_html = '''
            <tr>
                <td colspan="5" style="text-align: center; padding: 40px; color: #6b7280;">
                    <div style="margin-bottom: 16px;">
                        <svg viewBox="0 0 24 24" width="48" height="48" stroke="#6b7280" stroke-width="2" fill="none" style="display: inline-block;">
                            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                            <circle cx="12" cy="7" r="4"></circle>
                        </svg>
                    </div>
                    <div style="font-size: 18px;">No incidents found</div>
                    <div style="font-size: 14px; margin-top: 8px;">Try adjusting your search or filters</div>
                </td>
            </tr>
            '''

        # Build pagination HTML
        pagination_html = ""
        if total_pages > 1:
            pagination_html = '<div class="pagination">'

            # Previous button
            if has_prev:
                prev_url = f"/incidents?search={search}&severity={severity}&page={page-1}&limit={limit}"
                pagination_html += f'<a href="{prev_url}" class="page-btn">← Previous</a>'
            else:
                pagination_html += '<span class="page-btn disabled">← Previous</span>'

            # Page numbers
            start_page = max(1, page - 2)
            end_page = min(total_pages, page + 2)

            if start_page > 1:
                pagination_html += f'<a href="/incidents?search={search}&severity={severity}&page=1&limit={limit}" class="page-num">1</a>'
                if start_page > 2:
                    pagination_html += '<span class="page-num disabled">...</span>'

            for p in range(start_page, end_page + 1):
                if p == page:
                    pagination_html += f'<span class="page-num active">{p}</span>'
                else:
                    pagination_html += f'<a href="/incidents?search={search}&severity={severity}&page={p}&limit={limit}" class="page-num">{p}</a>'

            if end_page < total_pages:
                if end_page < total_pages - 1:
                    pagination_html += '<span class="page-num disabled">...</span>'
                pagination_html += f'<a href="/incidents?search={search}&severity={severity}&page={total_pages}&limit={limit}" class="page-num">{total_pages}</a>'

            # Next button
            if has_next:
                next_url = f"/incidents?search={search}&severity={severity}&page={page+1}&limit={limit}"
                pagination_html += f'<a href="{next_url}" class="page-btn">Next →</a>'
            else:
                pagination_html += '<span class="page-btn disabled">Next →</span>'

            pagination_html += '</div>'

        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>All Incidents - DLP Engine</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}

                body {{
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                    background: #000000;
                    color: #ffffff;
                    min-height: 100vh;
                    background: radial-gradient(circle at 20% 20%, rgba(156, 163, 175, 0.08) 0%, transparent 50%),
                                radial-gradient(circle at 80% 80%, rgba(107, 114, 128, 0.08) 0%, transparent 50%),
                                #000000;
                }}

                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                    padding: 40px 20px;
                }}

                .header {{
                    background: linear-gradient(135deg, #9ca3af 0%, #6b7280 50%, #4b5563 100%);
                    padding: 40px;
                    border-radius: 20px;
                    margin-bottom: 30px;
                    box-shadow: 0 8px 32px rgba(156, 163, 175, 0.2);
                }}

                .header h1 {{
                    font-size: 32px;
                    font-weight: 700;
                    margin-bottom: 8px;
                }}

                .header p {{
                    opacity: 0.9;
                    font-size: 16px;
                }}

                .stats-bar {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}

                .stat-card {{
                    background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    border-radius: 16px;
                    padding: 24px;
                }}

                .stat-label {{
                    color: #9ca3af;
                    font-size: 14px;
                    margin-bottom: 8px;
                }}

                .stat-value {{
                    font-size: 32px;
                    font-weight: 700;
                    color: #ffffff;
                }}

                .controls {{
                    background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    border-radius: 16px;
                    padding: 24px;
                    margin-bottom: 24px;
                }}

                .controls-grid {{
                    display: grid;
                    grid-template-columns: 1fr auto auto auto;
                    gap: 16px;
                    align-items: end;
                }}

                .control-group {{
                    display: flex;
                    flex-direction: column;
                    gap: 8px;
                }}

                .control-group label {{
                    color: #9ca3af;
                    font-size: 14px;
                    font-weight: 500;
                }}

                .control-group input,
                .control-group select {{
                    padding: 12px 16px;
                    background: rgba(255, 255, 255, 0.05);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    border-radius: 8px;
                    color: #ffffff;
                    font-size: 14px;
                }}

                .control-group select option {{
                    background: #1a1a1a;
                    color: #ffffff;
                    padding: 8px;
                }}

                .control-group input:focus,
                .control-group select:focus {{
                    outline: none;
                    border-color: #6b7280;
                }}

                {get_sidebar_css()}

                .menu-item {{
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    padding: 12px 16px;
                    margin: 4px 0;
                    color: #9ca3af;
                    text-decoration: none;
                    border-radius: 8px;
                    transition: all 0.2s;
                    font-weight: 500;
                }}

                .menu-item:hover {{
                    background: rgba(255, 255, 255, 0.05);
                    color: #ffffff;
                    transform: translateX(4px);
                }}

                .menu-item.active {{
                    background: linear-gradient(135deg, rgba(156, 163, 175, 0.15) 0%, rgba(107, 114, 128, 0.15) 100%);
                    color: #ffffff;
                    border-left: 3px solid #6b7280;
                }}

                .menu-item-icon {{
                    font-size: 20px;
                    width: 24px;
                    text-align: center;
                }}

                .menu-item-badge {{
                    margin-left: auto;
                    background: rgba(239, 68, 68, 0.2);
                    color: #fca5a5;
                    padding: 2px 8px;
                    border-radius: 12px;
                    font-size: 11px;
                    font-weight: 600;
                }}

                .main-content {{
                    margin-left: 280px;
                    min-height: 100vh;
                }}

                @media (max-width: 768px) {{
                    .sidebar {{
                        width: 0;
                        overflow: hidden;
                    }}

                    .main-content {{
                        margin-left: 0;
                    }}
                }}

                .btn {{
                    padding: 12px 24px;
                    background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
                    border: none;
                    border-radius: 8px;
                    color: white;
                    font-weight: 600;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                    transition: all 0.3s;
                }}

                .btn:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(107, 114, 128, 0.4);
                }}

                .btn-secondary {{
                    background: rgba(255, 255, 255, 0.05);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                }}

                .table-container {{
                    background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    border-radius: 16px;
                    overflow: hidden;
                }}

                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}

                thead {{
                    background: rgba(255, 255, 255, 0.03);
                }}

                th {{
                    padding: 16px;
                    text-align: left;
                    font-weight: 600;
                    color: #9ca3af;
                    font-size: 14px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                }}

                td {{
                    padding: 16px;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
                    color: #e5e7eb;
                }}

                tbody tr {{
                    transition: all 0.2s;
                }}

                tbody tr:hover {{
                    background: rgba(255, 255, 255, 0.05);
                }}

                .violation-badge {{
                    padding: 4px 12px;
                    border-radius: 12px;
                    font-size: 12px;
                    font-weight: 600;
                    display: inline-block;
                }}

                .violation-badge.ktp {{
                    background: rgba(239, 68, 68, 0.2);
                    color: #fca5a5;
                    border: 1px solid rgba(239, 68, 68, 0.3);
                }}

                .violation-badge.npwp {{
                    background: rgba(245, 158, 11, 0.2);
                    color: #fcd34d;
                    border: 1px solid rgba(245, 158, 11, 0.3);
                }}

                .violation-badge.empid {{
                    background: rgba(59, 130, 246, 0.2);
                    color: #93c5fd;
                    border: 1px solid rgba(59, 130, 246, 0.3);
                }}

                .violation-badge.other {{
                    background: rgba(107, 114, 128, 0.2);
                    color: #d1d5db;
                    border: 1px solid rgba(107, 114, 128, 0.3);
                }}

                .pagination {{
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    gap: 8px;
                    margin-top: 24px;
                    padding: 24px;
                }}

                .page-num,
                .page-btn {{
                    padding: 8px 16px;
                    background: rgba(255, 255, 255, 0.05);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    border-radius: 8px;
                    color: #ffffff;
                    text-decoration: none;
                    font-weight: 500;
                    transition: all 0.2s;
                }}

                .page-num:hover,
                .page-btn:hover {{
                    background: rgba(255, 255, 255, 0.1);
                }}

                .page-num.active {{
                    background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
                    border-color: #6b7280;
                }}

                .page-num.disabled,
                .page-btn.disabled {{
                    opacity: 0.3;
                    cursor: not-allowed;
                }}

                .back-link {{
                    margin-top: 24px;
                    text-align: center;
                }}

                @media (max-width: 768px) {{
                    .controls-grid {{
                        grid-template-columns: 1fr;
                    }}

                    .stats-bar {{
                        grid-template-columns: 1fr;
                    }}
                }}
            </style>
        </head>
        <body>
            {get_professional_sidebar('incidents')}

            <!-- Main Content -->
            <div class="main-wrapper" id="mainWrapper">
            <div class="container">
                <div class="header">
                    <h1>
                        {Icons.search(32)}
                        All Incidents
                    </h1>
                    <p>Complete incident history and management</p>
                </div>

                <div class="stats-bar">
                    <div class="stat-card">
                        <div class="stat-label">Total Incidents</div>
                        <div class="stat-value">{total_incidents}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Current Page</div>
                        <div class="stat-value">{page} / {total_pages if total_pages > 0 else 1}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Showing</div>
                        <div class="stat-value">{len(incidents)}</div>
                    </div>
                </div>

                <div class="controls">
                    <form method="GET" action="/incidents">
                        <div class="controls-grid">
                            <div class="control-group">
                                <label for="search">Search</label>
                                <input
                                    type="text"
                                    id="search"
                                    name="search"
                                    placeholder="Search by user or incident title..."
                                    value="{search}"
                                >
                            </div>

                            <div class="control-group">
                                <label for="severity">Risk Level</label>
                                <select id="severity" name="severity">
                                    <option value="" {'selected' if not severity else ''}>All Levels</option>
                                    <option value="CRITICAL" {'selected' if severity == 'CRITICAL' else ''}>● Critical (3+)</option>
                                    <option value="HIGH" {'selected' if severity == 'HIGH' else ''}>● High (2)</option>
                                    <option value="MEDIUM" {'selected' if severity == 'MEDIUM' else ''}>● Medium (1)</option>
                                </select>
                            </div>

                            <div class="control-group">
                                <label for="limit">Per Page</label>
                                <select id="limit" name="limit">
                                    <option value="25" {'selected' if limit == 25 else ''}>25</option>
                                    <option value="50" {'selected' if limit == 50 else ''}>50</option>
                                    <option value="100" {'selected' if limit == 100 else ''}>100</option>
                                </select>
                            </div>

                            <button type="submit" class="btn">Apply Filters</button>
                        </div>
                    </form>
                </div>

                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>User</th>
                                <th>Violation Type</th>
                                <th>Risk Level</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            {incidents_html}
                        </tbody>
                    </table>
                    {pagination_html}
                </div>

            </div>
            </div>
            </div>

            {get_sidebar_javascript()}
        </body>
        </html>
        """)

    except Exception as e:
        logger.error(f"Error in incidents overview: {e}")
        import traceback
        traceback.print_exc()
        return HTMLResponse(f"<h1>Error loading incidents</h1><p>{str(e)}</p>", status_code=500)

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
            risk_level = "MEDIUM"
            risk_color = "#f59e0b"
            risk_icon = "🟠"
        else:
            risk_level = "LOW"
            risk_color = "#10b981"
            risk_icon = "🟢"

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

                {get_sidebar_css()}
            </style>
        </head>
        <body>
            {get_professional_sidebar('incidents')}

            <div class="main-wrapper" id="mainWrapper">
            <div class="container">
                <div class="header">
                    <h1>
                        {Icons.search(28)}
                        Incident #{incident.id}
                    </h1>
                    <div style="display: flex; gap: 12px;">
                        <a href="/incidents" class="back-btn">
                            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                                <line x1="19" y1="12" x2="5" y2="12"></line>
                                <polyline points="12 19 5 12 12 5"></polyline>
                            </svg>
                            <span>All Incidents</span>
                        </a>
                        <a href="/" class="back-btn" style="background: rgba(255, 255, 255, 0.05);">
                            {Icons.shield(16)}
                            <span>Dashboard</span>
                        </a>
                    </div>
                </div>

                <div id="success-message" class="success-msg"></div>
                <div id="error-message" class="error-msg"></div>

                <div class="card">
                    <h2 class="section-title">
                        <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                            <line x1="16" y1="13" x2="8" y2="13"></line>
                            <line x1="16" y1="17" x2="8" y2="17"></line>
                        </svg>
                        Incident Details
                    </h2>
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
                            <span>TRAINING</span>
                            <span>Send Education Material</span>
                        </button>
                        <button class="action-btn btn-warning" onclick="performAction('warning')">
                            <span>WARNING</span>
                            <span>Send Warning Email</span>
                        </button>
                        <button class="action-btn btn-revoke" onclick="performAction('revoke')">
                            <span>BLOCKED</span>
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
                            successMsg.textContent = '[OK] ' + result.message;
                            successMsg.style.display = 'block';
                            window.scrollTo({{ top: 0, behavior: 'smooth' }});
                        }} else {{
                            errorMsg.textContent = '[ERROR] ' + (result.detail || 'Action failed');
                            errorMsg.style.display = 'block';
                            window.scrollTo({{ top: 0, behavior: 'smooth' }});
                        }}
                    }} catch (error) {{
                        errorMsg.textContent = '[ERROR] Network error: ' + error.message;
                        errorMsg.style.display = 'block';
                        window.scrollTo({{ top: 0, behavior: 'smooth' }});
                    }}
                }}
            </script>
            </div>
            </div>

            {get_sidebar_javascript()}
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
                    <h2 style="color: #3b82f6;">Data Security Education</h2>
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
            subject = "[WARNING] Data Security Policy Violation Warning"
            body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #f59e0b;">WARNING: Official Warning - Data Security Policy Violation</h2>
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
            # CRITICAL FIX: Send notification email FIRST before revoking
            # This ensures user can receive the email before their account is disabled
            subject = "[URGENT] Account Access Being Suspended - Data Security Violation"
            body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #ef4444;">Account Access Suspension Notice</h2>
                    <p>Dear Team Member,</p>
                    <p><strong style="color: #dc2626;">Your account access is being suspended immediately due to critical data security policy violations.</strong></p>

                    <div style="background: #fee2e2; border-left: 4px solid #ef4444; padding: 15px; margin: 20px 0;">
                        <strong>Suspension Details:</strong><br>
                        Incident ID: #{incident_id}<br>
                        Suspension Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
                        Reason: Multiple data security policy violations
                    </div>

                    <h3>What This Means:</h3>
                    <ul>
                        <li>Your account access will be disabled immediately</li>
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

            # Send email FIRST before revoking access
            email_sent = False
            if EMAIL_ENABLED:
                try:
                    logger.info(f"[EMAIL] Sending notification email BEFORE revoking access for {user_email}...")
                    email_sent = await email_service.send_email_via_graph(
                        recipient=user_email,
                        subject=subject,
                        html_body=body
                    )

                    if email_sent:
                        logger.info(f"[OK] Notification email sent successfully to {user_email}")

                        # Wait 3 seconds to ensure email delivery before revoking
                        import asyncio
                        logger.info(f"⏳ Waiting 3 seconds to ensure email delivery...")
                        await asyncio.sleep(3)
                        logger.info(f"[OK] Email delivery window completed, proceeding with revocation...")
                    else:
                        logger.warning(f"[WARNING] Email send returned False, but continuing with revocation")

                except Exception as e:
                    logger.error(f"[WARNING] Failed to send notification email (continuing with revocation): {e}")

            # Actually revoke user access via Microsoft Graph API AFTER email sent
            if EMAIL_ENABLED:
                try:
                    logger.info(f"[CRITICAL] Revoking access for user: {user_email}")
                    revoke_result = await email_service.revoke_user_access(user_email)

                    if revoke_result["ok"]:
                        logger.info(f"[OK] Successfully revoked access for {user_email}: Account blocked={revoke_result['blocked']}, Sessions revoked={revoke_result['sessions_revoked']}")
                        message_text = f"Email sent, account DISABLED and sessions REVOKED for {user_email}"
                    else:
                        logger.error(f"[ERROR] Failed to revoke access for {user_email}: {revoke_result['message']}")
                        message_text = f"Email sent, but revocation failed: {revoke_result['message']}"
                except Exception as e:
                    logger.error(f"[ERROR] Exception during revocation for {user_email}: {e}")
                    message_text = f"Email sent, but revocation error: {str(e)}"
            else:
                logger.warning(f"REVOKE ACTION: User {user_email} - Incident #{incident_id} - Email service disabled, cannot revoke access")

        else:
            return JSONResponse({"detail": "Invalid action"}, status_code=400)

        # Send email for education and warning actions (revoke already sent email above)
        if EMAIL_ENABLED and action in ["education", "warning"]:
            try:
                # Use Microsoft Graph API to send email (await since we're in async context)
                success = await email_service.send_email_via_graph(
                    recipient=user_email,
                    subject=subject,
                    html_body=body
                )

                if success:
                    logger.info(f"[OK] Action '{action}' completed for user {user_email} - Incident #{incident_id}")
                else:
                    logger.error(f"[ERROR] Failed to send email for action '{action}' - Graph API returned false")
                    return JSONResponse({"detail": "Action logged but email failed to send via Graph API"}, status_code=500)
            except Exception as e:
                logger.error(f"[ERROR] Failed to send email for action '{action}': {e}")
                return JSONResponse({"detail": f"Action logged but email failed: {str(e)}"}, status_code=500)
        elif not EMAIL_ENABLED and action in ["education", "warning"]:
            logger.info(f"Action '{action}' logged for user {user_email} (email service disabled)")
            message_text += " (Email service not configured - action logged only)"
        # For revoke action, email was already sent before revocation

        return {"success": True, "message": message_text, "action": action, "incident_id": incident_id}

    except Exception as e:
        logger.error(f"Error handling incident action: {e}")
        return JSONResponse({"detail": str(e)}, status_code=500)

@app.post("/api/remediate")
async def sentinel_remediate(request: dict, db: Session = Depends(get_db)):
    """
    Accepts remediation requests from Microsoft Sentinel/Logic Apps with 3-tier risk escalation:
    - LOW (count=1): Education email only, NO blocking
    - MEDIUM (count=2): Warning email + session revoke (soft block)
    - CRITICAL (count=3+): Email FIRST -> 3s delay -> account disabled
    """
    try:
        user_email = request.get("userPrincipalName")
        incident_id_str = request.get("incidentId", "Unknown")
        incident_title = request.get("incidentTitle", "Sentinel Incident")
        severity = request.get("severity", "High")
        actions = request.get("actions", [])
        source = request.get("source", "sentinel")

        logger.info(f"📨 Remediation request from {source} for user: {user_email}")
        logger.info(f"   Incident: {incident_id_str} | Severity: {severity}")
        logger.info(f"   Actions requested: {actions}")

        if not user_email:
            return JSONResponse(
                {"ok": False, "message": "Missing userPrincipalName"},
                status_code=400
            )

        # Log to database for dashboard visibility
        try:
            offense, violation_count = log_offense_and_get_count(
                db,
                user_email,
                f"Sentinel Alert: {incident_title}"
            )
            logger.info(f"   Logged to database - Violation count: {violation_count}")
        except Exception as db_error:
            logger.error(f"    Database logging failed (continuing anyway): {db_error}")
            violation_count = 1

        results = {
            "ok": True,
            "blocked": False,
            "sessions_revoked": False,
            "email_sent": False,
            "message": "",
            "details": [],
            "violation_count": violation_count,
            "risk_level": ""
        }

        # ===== 3-TIER RISK ESCALATION LOGIC =====

        # SCENARIO 1: LOW RISK (count=1) - Education email only
        if violation_count == 1:
            logger.info(f"🟢 LOW RISK - Violation #{violation_count} for {user_email}")
            logger.info(f"   Action: Education email only, NO blocking")
            results["risk_level"] = "LOW"

            # Send education email
            if EMAIL_ENABLED and email_service:
                try:
                    logger.info(f"   📧 Sending education email...")
                    result = await email_service.send_violation_notification(
                        recipient=user_email,
                        violation_types=["Sensitive Data Detection"],
                        violation_count=violation_count,
                        blocked_content_summary=incident_title,
                        incident_title=incident_title,
                        file_name="Detected via Sentinel"
                    )
                    results["email_sent"] = result
                    results["details"].append({
                        "action": "educationEmail",
                        "status": result,
                        "message": "Education email sent successfully" if result else "Email send failed"
                    })
                    logger.info(f"   ✅ Education email sent to {user_email}")
                except Exception as e:
                    logger.error(f"   ❌ Email failed: {e}")
                    results["details"].append({
                        "action": "educationEmail",
                        "status": False,
                        "message": f"Email error: {str(e)}"
                    })

            results["message"] = f"LOW risk - Education email sent to {user_email} (no blocking)"

        # SCENARIO 2: MEDIUM RISK (count=2) - Warning email + Session revoke
        elif violation_count == 2:
            logger.info(f"🟠 MEDIUM RISK - Violation #{violation_count} for {user_email}")
            logger.info(f"   Action: Warning email + session revoke (soft block)")
            results["risk_level"] = "MEDIUM"

            # Send warning email
            if EMAIL_ENABLED and email_service:
                try:
                    logger.info(f"   📧 Sending warning email...")
                    result = await email_service.send_violation_notification(
                        recipient=user_email,
                        violation_types=["Sensitive Data Detection"],
                        violation_count=violation_count,
                        blocked_content_summary=incident_title,
                        incident_title=incident_title,
                        file_name="Detected via Sentinel"
                    )
                    results["email_sent"] = result
                    results["details"].append({
                        "action": "warningEmail",
                        "status": result,
                        "message": "Warning email sent successfully" if result else "Email send failed"
                    })
                    logger.info(f"   ✅ Warning email sent to {user_email}")
                except Exception as e:
                    logger.error(f"   ❌ Email failed: {e}")
                    results["details"].append({
                        "action": "warningEmail",
                        "status": False,
                        "message": f"Email error: {str(e)}"
                    })

            # Revoke sessions (soft block - account stays active)
            if settings.FEATURE_ACCOUNT_REVOCATION:
                try:
                    logger.info(f"   🔄 Performing soft block (session revoke only)...")
                    revoke_result = await perform_soft_block(user_email)
                    results["sessions_revoked"] = revoke_result
                    results["details"].append({
                        "action": "softBlock",
                        "status": revoke_result,
                        "message": "Sessions revoked (account still active)" if revoke_result else "Session revoke failed"
                    })
                    logger.info(f"   ✅ Sessions revoked for {user_email} (account still active, can re-login)")
                except Exception as e:
                    logger.error(f"   ❌ Session revocation failed: {e}")
                    results["ok"] = False
                    results["details"].append({
                        "action": "softBlock",
                        "status": False,
                        "message": f"Session revoke error: {str(e)}"
                    })

            results["message"] = f"MEDIUM risk - Warning sent + sessions revoked for {user_email}"

        # SCENARIO 3: CRITICAL RISK (count>=3) - Email FIRST -> 3s delay -> Account disabled
        else:  # violation_count >= 3
            logger.info(f"🔴 CRITICAL RISK - Violation #{violation_count} for {user_email}")
            logger.info(f"   Action: Email FIRST → 3s delay → Account disabled")
            results["risk_level"] = "CRITICAL"

            # Step 1: Send email FIRST (user gets notified before being blocked)
            if EMAIL_ENABLED and email_service:
                try:
                    logger.info(f"   📧 Sending critical alert email FIRST (before blocking)...")
                    result = await email_service.send_violation_notification(
                        recipient=user_email,
                        violation_types=["Sensitive Data Detection"],
                        violation_count=violation_count,
                        blocked_content_summary=incident_title,
                        incident_title=incident_title,
                        file_name="Detected via Sentinel"
                    )
                    results["email_sent"] = result
                    results["details"].append({
                        "action": "criticalEmail",
                        "status": result,
                        "message": "Critical alert email sent" if result else "Email send failed"
                    })
                    logger.info(f"   ✅ Critical alert email sent to {user_email}")
                except Exception as e:
                    logger.error(f"   ❌ Email failed: {e}")
                    results["details"].append({
                        "action": "criticalEmail",
                        "status": False,
                        "message": f"Email error: {str(e)}"
                    })

            # Step 2: Wait 3 seconds (email-first mechanism for better UX)
            logger.info(f"   ⏳ Waiting 3 seconds to ensure email delivery...")
            await asyncio.sleep(3)
            logger.info(f"   ✅ 3 second delay completed")

            # Step 3: Disable account (hard block)
            if settings.FEATURE_ACCOUNT_REVOCATION:
                try:
                    logger.info(f"   🔒 Disabling account for {user_email}...")
                    block_result = await perform_hard_block(user_email)
                    results["blocked"] = block_result
                    results["details"].append({
                        "action": "hardBlock",
                        "status": block_result,
                        "message": "Account DISABLED" if block_result else "Account disable failed"
                    })
                    logger.info(f"   ✅ Account DISABLED for {user_email}")
                except Exception as e:
                    logger.error(f"   ❌ Account revocation failed: {e}")
                    results["ok"] = False
                    results["details"].append({
                        "action": "hardBlock",
                        "status": False,
                        "message": f"Account disable error: {str(e)}"
                    })

            results["message"] = f"CRITICAL risk - Email sent + account disabled for {user_email}"

        # Log final summary
        logger.info(f"✅ Remediation summary: {results['message']}")
        return JSONResponse(results)

    except Exception as e:
        logger.error(f"[ERROR] Error in remediation endpoint: {e}")
        return JSONResponse(
            {"ok": False, "message": f"Remediation error: {str(e)}"},
            status_code=500
        )

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

        # Determine risk level and actions 
        violation_types = ["Sensitive Data", "DLP Policy Violation"]
        email_sent = False
        session_revoked = False
        account_disabled = False
        admin_notified = False
        action_taken = "None"

        # ============================================================================
        # SCENARIO 1: LOW RISK (count=1) - Education email only
        # ============================================================================
        if offense_count == 1:
            logger.info(f"🟢 LOW RISK - Violation #{offense_count} for {user_upn}")
            action_taken = "Education Email"

            # Send education email
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
                    logger.info(f"✅ Education email sent to {user_upn}")
                except Exception as e:
                    logger.error(f"❌ Email failed: {e}")

        # ============================================================================
        # SCENARIO 2: MEDIUM RISK (count=2) - Warning email + Session revoke
        # ============================================================================
        elif offense_count == 2:
            logger.info(f"🟠 MEDIUM RISK - Violation #{offense_count} for {user_upn}")
            action_taken = "Warning Email + Session Revoke"

            # Send warning email
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
                    logger.info(f"✅ Warning email sent to {user_upn}")
                except Exception as e:
                    logger.error(f"❌ Email failed: {e}")

            # Revoke sessions (soft block - account still active)
            if settings.FEATURE_ACCOUNT_REVOCATION:
                try:
                    revoke_result = await perform_soft_block(user_upn)
                    session_revoked = revoke_result
                    logger.info(f"✅ Sessions revoked for {user_upn} (account still active)")
                except Exception as e:
                    logger.error(f"❌ Session revocation failed: {e}")

        # ============================================================================
        # SCENARIO 3: CRITICAL RISK (count>=3) - Email FIRST → 3s delay → Account disabled
        # ============================================================================
        else:  # offense_count >= 3
            logger.info(f"🔴 CRITICAL RISK - Violation #{offense_count} for {user_upn}")
            action_taken = "Email First → Account Disabled"

            # Step 1: Send email FIRST (user gets notified before being blocked)
            if EMAIL_ENABLED and email_service:
                try:
                    logger.info(f"📧 Sending critical alert email FIRST (before blocking)...")
                    result = await email_service.send_violation_notification(
                        recipient=user_upn,
                        violation_types=violation_types,
                        violation_count=offense_count,
                        blocked_content_summary=incident_title,
                        incident_title=incident_title,
                        file_name=file_name
                    )
                    email_sent = result
                    logger.info(f"✅ Critical alert email sent to {user_upn}")
                except Exception as e:
                    logger.error(f"❌ Email failed: {e}")

            # Step 2: Wait 3 seconds (email-first mechanism for better UX)
            logger.info(f"⏳ Waiting 3 seconds to ensure email delivery...")
            await asyncio.sleep(3)
            logger.info(f"✅ 3 second delay completed")

            # Step 3: Disable account (hard block)
            if settings.FEATURE_ACCOUNT_REVOCATION:
                try:
                    logger.info(f"🔒 Disabling account for {user_upn}...")
                    revoke_result = await perform_hard_block(user_upn)
                    account_disabled = revoke_result
                    logger.info(f"✅ Account DISABLED for {user_upn}")
                except Exception as e:
                    logger.error(f"❌ Account revocation failed: {e}")

            # Send admin alert for critical violations
            if EMAIL_ENABLED and email_service:
                try:
                    await email_service.send_admin_alert(
                        user=user_upn,
                        incident_title=incident_title,
                        violation_count=offense_count,
                        action_taken=f"Account Disabled (Email sent 3s before blocking)",
                        violation_types=violation_types,
                        file_name=file_name
                    )
                    admin_notified = True
                    logger.info(f"✅ Admin alert sent")
                except Exception as e:
                    logger.error(f"❌ Admin alert failed: {e}")

        response = {
            "status": "success",
            "incident_id": payload.get("CorrelationId", "unknown"),
            "user": user_upn,
            "offense_count": offense_count,
            "risk_score": assessment.score if assessment else 0,
            "risk_level": assessment.risk_level if assessment else "Unknown",
            "action_taken": action_taken,
            "actions": {
                "email_sent": email_sent,
                "session_revoked": session_revoked,
                "account_disabled": account_disabled,
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
    logger.warning(f"[WARNING] UI routes not loaded: {e}")

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
        logger.warning(f"[WARNING] Configuration warnings ({len(warnings)}):")
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
