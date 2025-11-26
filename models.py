"""
Pydantic Models for API Requests and Responses

Defines all data models for type safety and validation.

Usage:
    from models import EmailCheckRequest, RemediationResponse

    @app.post("/check-email", response_model=EmailCheckResponse)
    async def check_email(request: EmailCheckRequest):
        ...
"""

from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


# ============================================================================
# ENUMS
# ============================================================================

class RiskLevel(str, Enum):
    """Risk level classification"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class RemediationAction(str, Enum):
    """Remediation action types"""
    WARN_EDUCATE = "Warn & Educate"
    SOFT_REMEDIATION = "Soft Remediation"
    HARD_BLOCK = "Hard Block"


class ViolationType(str, Enum):
    """Types of DLP violations"""
    KTP = "KTP"
    NPWP = "NPWP"
    EMPLOYEE_ID = "Employee ID"
    SENSITIVE_DATA = "Sensitive Data"
    CONFIDENTIAL_FILE = "Confidential File"


class IncidentSeverity(str, Enum):
    """Incident severity levels"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


# ============================================================================
# REQUEST MODELS
# ============================================================================

class EmailCheckRequest(BaseModel):
    """Request model for /check-email endpoint"""

    sender: EmailStr = Field(
        ...,
        description="Email address of the sender",
        example="user@example.com"
    )
    content: str = Field(
        ...,
        min_length=1,
        max_length=1_000_000,
        description="Email content to scan for sensitive data"
    )

    @field_validator('content')
    @classmethod
    def content_not_empty(cls, v):
        if not v or v.strip() == "":
            raise ValueError("Content cannot be empty or whitespace only")
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "sender": "user@example.com",
                "content": "Please review this document containing KTP: 1234567890123456"
            }
        }
    )


class RemediationRequest(BaseModel):
    """Request model for /remediate endpoint (Sentinel incidents)"""

    incident_id: Optional[str] = Field(None, description="Sentinel incident ID")
    user_upn: Optional[str] = Field(None, description="User Principal Name")
    incident_title: Optional[str] = Field(None, description="Incident title")
    severity: Optional[IncidentSeverity] = Field(
        default=IncidentSeverity.MEDIUM,
        description="Incident severity"
    )
    file_name: Optional[str] = Field(None, description="Name of the file involved")
    file_sensitivity: Optional[str] = Field(
        default="Confidential",
        description="File sensitivity label"
    )

    model_config = ConfigDict(use_enum_values=True)


# ============================================================================
# RESPONSE MODELS
# ============================================================================

class ViolationDetail(BaseModel):
    """Details about a specific violation type"""
    type: ViolationType
    count: int = Field(..., ge=0, description="Number of violations of this type")

    model_config = ConfigDict(use_enum_values=True)


class UserDetails(BaseModel):
    """User information from Microsoft Graph"""
    display_name: str = Field(..., description="User's display name")
    department: str = Field(..., description="User's department")
    job_title: str = Field(..., description="User's job title")


class RiskAssessmentResponse(BaseModel):
    """Risk assessment details"""
    risk_score: int = Field(..., ge=0, le=100, description="Calculated risk score (0-100)")
    risk_level: RiskLevel = Field(..., description="Risk classification")
    remediation_action: RemediationAction = Field(..., description="Recommended action")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Assessment confidence")
    escalation_required: bool = Field(..., description="Whether escalation is needed")

    model_config = ConfigDict(use_enum_values=True)


class ActionsTaken(BaseModel):
    """Actions performed by the DLP system"""
    email_blocked: bool = Field(default=False, description="Was the email blocked")
    account_revoked: bool = Field(default=False, description="Was the account revoked")
    email_notification_sent: bool = Field(
        default=False,
        description="Was notification email sent to user"
    )
    socialization_sent: bool = Field(
        default=False,
        description="Was training invitation sent"
    )
    admin_notified: bool = Field(default=False, description="Was admin alerted")
    teams_alert_sent: bool = Field(default=False, description="Was Teams alert sent")


class EmailCheckResponse(BaseModel):
    """Response model for /check-email endpoint"""

    status: str = Field(..., description="'blocked' or 'allowed'")
    reason: Optional[str] = Field(None, description="Reason for the decision")
    violations: List[ViolationDetail] = Field(
        default_factory=list,
        description="Detailed violation information"
    )
    violation_types: List[ViolationType] = Field(
        default_factory=list,
        description="Types of violations found"
    )
    violation_count: int = Field(
        default=0,
        ge=0,
        description="Total violations for this user"
    )
    masked_content: Optional[str] = Field(
        None,
        description="Content with sensitive data masked"
    )
    action_required: str = Field(
        default="none",
        description="Action required: 'none', 'warning', or 'revoke_signin'"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Response timestamp"
    )

    model_config = ConfigDict(
        use_enum_values=True,
        json_schema_extra={
            "example": {
                "status": "blocked",
                "reason": "Sensitive data detected",
                "violations": [
                    {"type": "KTP", "count": 1},
                    {"type": "NPWP", "count": 1}
                ],
                "violation_types": ["KTP", "NPWP"],
                "violation_count": 2,
                "masked_content": "KTP: 123***********456, NPWP: 12***********45",
                "action_required": "warning",
                "timestamp": "2025-11-25T10:30:00Z"
            }
        }
    )


class RemediationResponse(BaseModel):
    """Response model for /remediate endpoint"""

    request_id: str = Field(..., description="Unique request identifier")
    incident_id: str = Field(..., description="Sentinel incident ID")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Processing timestamp"
    )
    user: str = Field(..., description="User Principal Name")
    user_details: UserDetails = Field(..., description="User information from Azure AD")
    assessment: RiskAssessmentResponse = Field(..., description="Risk assessment results")
    offense_count: int = Field(..., ge=0, description="Total violations for this user")
    violation_types: List[ViolationType] = Field(
        ...,
        description="Types of violations detected"
    )
    actions_taken: ActionsTaken = Field(..., description="Actions performed by system")
    status: str = Field(..., description="Processing status")
    message: str = Field(..., description="Human-readable status message")

    model_config = ConfigDict(
        use_enum_values=True,
        json_schema_extra={
            "example": {
                "request_id": "550e8400-e29b-41d4-a716-446655440000",
                "incident_id": "INC-12345",
                "timestamp": "2025-11-25T10:30:00Z",
                "user": "user@example.com",
                "user_details": {
                    "display_name": "John Doe",
                    "department": "Finance",
                    "job_title": "Financial Analyst"
                },
                "assessment": {
                    "risk_score": 75,
                    "risk_level": "High",
                    "remediation_action": "Soft Remediation",
                    "confidence": 0.95,
                    "escalation_required": True
                },
                "offense_count": 2,
                "violation_types": ["KTP", "Confidential File"],
                "actions_taken": {
                    "email_blocked": True,
                    "account_revoked": False,
                    "email_notification_sent": True,
                    "socialization_sent": False,
                    "admin_notified": True,
                    "teams_alert_sent": True
                },
                "status": "processed",
                "message": "Violation processed. User has 2 total violations."
            }
        }
    )


class HealthCheckResponse(BaseModel):
    """Response model for /health endpoint"""

    status: str = Field(..., description="'healthy' or 'degraded'")
    database: str = Field(..., description="Database connection status")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Check timestamp"
    )
    version: str = Field(..., description="API version")
    features: Dict[str, Any] = Field(
        default_factory=dict,
        description="Feature flags and status"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "healthy",
                "database": "connected",
                "timestamp": "2025-11-25T10:30:00Z",
                "version": "2.0.0",
                "features": {
                    "email_blocking": True,
                    "teams_alerts": True,
                    "sensitive_data_detection": True,
                    "account_revocation": True,
                    "email_notifications": True,
                    "email_service": "Graph API"
                }
            }
        }
    )


class WebhookStatusResponse(BaseModel):
    """Response model for /webhook/status endpoint"""

    service: str = Field(default="DLP Webhook Service")
    status: str = Field(default="online")
    endpoints: Dict[str, Dict[str, str]] = Field(..., description="Available endpoints")
    email_notifications: bool = Field(..., description="Email notification status")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ErrorResponse(BaseModel):
    """Standard error response model"""

    error: str = Field(..., description="Error type or class name")
    message: str = Field(..., description="Human-readable error message")
    detail: Optional[str] = Field(None, description="Additional error details")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Error timestamp"
    )
    request_id: Optional[str] = Field(None, description="Request ID for tracking")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "error": "ValidationError",
                "message": "Invalid email format",
                "detail": "sender: value is not a valid email address",
                "timestamp": "2025-11-25T10:30:00Z",
                "request_id": "550e8400-e29b-41d4-a716-446655440000"
            }
        }
    )


# ============================================================================
# INTERNAL MODELS (not exposed via API)
# ============================================================================

class IncidentContext(BaseModel):
    """Context information about an incident"""
    severity: IncidentSeverity = Field(default=IncidentSeverity.MEDIUM)

    model_config = ConfigDict(use_enum_values=True)


class UserContext(BaseModel):
    """Context information about a user"""
    department: str = Field(default="Unknown")


class FileContext(BaseModel):
    """Context information about a file"""
    sensitivity_label: str = Field(default="Public")


class OffenseHistory(BaseModel):
    """User's offense history"""
    previous_offenses: int = Field(default=0, ge=0)


class RiskAssessment(BaseModel):
    """Internal risk assessment model"""
    score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    remediation_action: RemediationAction

    model_config = ConfigDict(use_enum_values=True)


# ============================================================================
# STATISTICS MODELS
# ============================================================================

class UserStatistics(BaseModel):
    """Statistics for a specific user"""
    user_principal_name: str
    violation_count: int = Field(..., ge=0)
    last_violation: datetime
    risk_level: RiskLevel

    model_config = ConfigDict(use_enum_values=True)


class DatabaseStatistics(BaseModel):
    """Database statistics"""
    total_offenses: int = Field(..., ge=0)
    unique_users: int = Field(..., ge=0)
    high_risk_users: int = Field(..., ge=0)
    today_incidents: int = Field(..., ge=0)
    latest_offense_time: Optional[datetime] = None


if __name__ == "__main__":
    """Test model validation"""
    print("="*60)
    print("Pydantic Models - Validation Test")
    print("="*60)

    # Test EmailCheckRequest
    print("\n1. Testing EmailCheckRequest...")
    try:
        valid_request = EmailCheckRequest(
            sender="user@example.com",
            content="Test email with KTP: 1234567890123456"
        )
        print(f"   ✅ Valid request: {valid_request.sender}")
    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Test invalid email
    print("\n2. Testing invalid email...")
    try:
        invalid_request = EmailCheckRequest(
            sender="not-an-email",
            content="Test content"
        )
        print("   ❌ Should have failed validation!")
    except Exception as e:
        print(f"   ✅ Correctly rejected: {type(e).__name__}")

    # Test EmailCheckResponse
    print("\n3. Testing EmailCheckResponse...")
    response = EmailCheckResponse(
        status="blocked",
        reason="Sensitive data detected",
        violations=[
            ViolationDetail(type=ViolationType.KTP, count=1),
            ViolationDetail(type=ViolationType.NPWP, count=1)
        ],
        violation_types=[ViolationType.KTP, ViolationType.NPWP],
        violation_count=2,
        action_required="warning"
    )
    print(f"   ✅ Response created: {response.status}")
    print(f"   Violations: {len(response.violations)}")

    # Test JSON serialization
    print("\n4. Testing JSON serialization...")
    json_output = response.model_dump_json(indent=2)
    print(f"   ✅ JSON output ({len(json_output)} bytes)")

    print("\n" + "="*60)
    print("✅ All model tests passed!")
    print("="*60)
