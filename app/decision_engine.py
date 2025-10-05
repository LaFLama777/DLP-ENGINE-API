from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta

class RiskLevel(Enum):
    """Risk level enumeration"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class RemediationAction(Enum):
    """Remediation action types"""
    WARN_EDUCATE = "Warn & Educate"
    SOFT_REMEDIATION = "Soft Remediation"
    HARD_BLOCK = "Hard Block"
    ESCALATE_SECURITY = "Escalate to Security Team"

@dataclass
class UserContext:
    """User context from MS Graph API"""
    user_id: str
    department: str
    role: str
    job_title: str
    is_privileged_account: bool = False
    account_enabled: bool = True
    manager_id: Optional[str] = None

@dataclass
class FileContext:
    """File metadata from MS Graph API"""
    file_name: str
    file_size_mb: float
    sensitivity_label: str  # Public, Internal, Confidential, Highly Confidential
    file_type: str
    classification_tags: List[str]
    contains_pii: bool = False
    contains_financial_data: bool = False
    contains_phi: bool = False  # Protected Health Information

@dataclass
class OffenseHistory:
    """User offense history from internal DB"""
    total_offenses: int
    offenses_last_30_days: int
    offenses_last_90_days: int
    last_offense_date: Optional[datetime]
    previous_risk_levels: List[str]
    completed_training: bool = False

@dataclass
class IncidentContext:
    """Full incident context"""
    incident_id: str
    incident_severity: str  # Low, Medium, High, Critical
    incident_type: str  # Data Exfiltration, Unauthorized Share, Policy Violation, etc.
    destination: str  # External Email, Cloud Storage, USB, etc.
    timestamp: datetime
    source_ip: str
    user_agent: str

@dataclass
class RiskAssessment:
    """Risk assessment output"""
    risk_level: RiskLevel
    risk_score: int  # 0-100
    remediation_action: RemediationAction
    justification: List[str]
    confidence: float  # 0.0-1.0
    recommended_actions: List[str]
    escalation_required: bool


class AdvancedDecisionEngine:
    """
    Advanced DLP Remediation Decision Engine
    Integrates with Azure Sentinel, MS Graph API, and Internal DB
    """
    
    # Sensitivity weights
    SENSITIVITY_WEIGHTS = {
        "Public": 0,
        "Internal": 10,
        "Confidential": 30,
        "Highly Confidential": 50
    }
    
    # Department risk multipliers
    DEPT_RISK_MULTIPLIER = {
        "Finance": 1.5,
        "Legal": 1.5,
        "Executive": 1.8,
        "HR": 1.4,
        "IT": 1.3,
        "R&D": 1.4,
        "Sales": 1.1,
        "Marketing": 1.0,
        "Operations": 1.0
    }
    
    # Incident type base scores
    INCIDENT_TYPE_SCORES = {
        "Data Exfiltration": 40,
        "Unauthorized Share": 30,
        "Policy Violation": 20,
        "Suspicious Download": 25,
        "Mass File Transfer": 35,
        "After Hours Access": 15
    }
    
    def __init__(self, enable_logging: bool = True):
        self.enable_logging = enable_logging
    
    def log(self, message: str):
        """Internal logging"""
        if self.enable_logging:
            print(f"[Decision Engine] {message}")
    
    def calculate_risk_score(
        self,
        incident: IncidentContext,
        user: UserContext,
        file: FileContext,
        history: OffenseHistory
    ) -> int:
        """
        Calculate comprehensive risk score (0-100)
        """
        score = 0
        
        # 1. Base incident severity (0-30 points)
        severity_scores = {"Low": 5, "Medium": 15, "High": 25, "Critical": 30}
        score += severity_scores.get(incident.incident_severity, 15)
        self.log(f"Severity score: {severity_scores.get(incident.incident_severity, 15)}")
        
        # 2. Incident type score (0-40 points)
        type_score = self.INCIDENT_TYPE_SCORES.get(incident.incident_type, 20)
        score += type_score
        self.log(f"Incident type score: {type_score}")
        
        # 3. File sensitivity (0-50 points)
        sensitivity_score = self.SENSITIVITY_WEIGHTS.get(file.sensitivity_label, 10)
        
        # Boost for special data types
        if file.contains_pii:
            sensitivity_score += 15
        if file.contains_financial_data:
            sensitivity_score += 15
        if file.contains_phi:
            sensitivity_score += 20
        
        sensitivity_score = min(sensitivity_score, 50)  # Cap at 50
        score += sensitivity_score
        self.log(f"File sensitivity score: {sensitivity_score}")
        
        # 4. User offense history (0-40 points)
        history_score = 0
        if history.total_offenses >= 3:
            history_score = 40
        elif history.total_offenses == 2:
            history_score = 30
        elif history.total_offenses == 1:
            history_score = 15
        
        # Recent offense bonus
        if history.offenses_last_30_days > 0:
            history_score += 10
        
        history_score = min(history_score, 40)
        score += history_score
        self.log(f"Offense history score: {history_score}")
        
        # 5. Department risk multiplier
        dept_multiplier = self.DEPT_RISK_MULTIPLIER.get(user.department, 1.0)
        score = int(score * dept_multiplier)
        self.log(f"Department multiplier ({user.department}): {dept_multiplier}x")
        
        # 6. Privileged account penalty
        if user.is_privileged_account:
            score += 15
            self.log("Privileged account penalty: +15")
        
        # 7. Training completion mitigation
        if history.completed_training and history.total_offenses < 2:
            score = int(score * 0.9)  # 10% reduction
            self.log("Training completed: -10% score")
        
        # 8. File size factor (large transfers are riskier)
        if file.file_size_mb > 100:
            score += 10
            self.log(f"Large file transfer ({file.file_size_mb}MB): +10")
        elif file.file_size_mb > 500:
            score += 20
            self.log(f"Very large file transfer ({file.file_size_mb}MB): +20")
        
        # Cap score at 100
        final_score = min(score, 100)
        self.log(f"Final risk score: {final_score}/100")
        
        return final_score
    
    def determine_risk_level(self, risk_score: int) -> RiskLevel:
        """Convert risk score to risk level"""
        if risk_score >= 75:
            return RiskLevel.CRITICAL
        elif risk_score >= 50:
            return RiskLevel.HIGH
        elif risk_score >= 25:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def determine_remediation_action(
        self,
        risk_level: RiskLevel,
        history: OffenseHistory,
        incident: IncidentContext
    ) -> RemediationAction:
        """
        Determine appropriate remediation action based on risk level and context
        """
        # Critical risk or repeat offenders (3+) -> Hard Block
        if risk_level == RiskLevel.CRITICAL or history.total_offenses >= 3:
            return RemediationAction.HARD_BLOCK
        
        # High risk -> Escalate to security team or Hard Block
        if risk_level == RiskLevel.HIGH:
            if history.total_offenses >= 2:
                return RemediationAction.HARD_BLOCK
            else:
                return RemediationAction.ESCALATE_SECURITY
        
        # Medium risk -> Soft Remediation
        if risk_level == RiskLevel.MEDIUM:
            return RemediationAction.SOFT_REMEDIATION
        
        # Low risk -> Warn & Educate
        return RemediationAction.WARN_EDUCATE
    
    def generate_justification(
        self,
        risk_score: int,
        incident: IncidentContext,
        user: UserContext,
        file: FileContext,
        history: OffenseHistory
    ) -> List[str]:
        """Generate detailed justification for the decision"""
        justifications = []
        
        # Severity justification
        if incident.incident_severity in ["High", "Critical"]:
            justifications.append(f"High severity incident: {incident.incident_severity}")
        
        # Repeat offender
        if history.total_offenses >= 2:
            justifications.append(f"Repeat offender: {history.total_offenses} previous violations")
        
        if history.offenses_last_30_days > 0:
            justifications.append(f"Recent violations: {history.offenses_last_30_days} in last 30 days")
        
        # Sensitive data
        if file.sensitivity_label in ["Confidential", "Highly Confidential"]:
            justifications.append(f"Sensitive data: {file.sensitivity_label}")
        
        if file.contains_pii:
            justifications.append("File contains Personally Identifiable Information (PII)")
        
        if file.contains_financial_data:
            justifications.append("File contains financial data")
        
        if file.contains_phi:
            justifications.append("File contains Protected Health Information (PHI)")
        
        # Department risk
        if user.department in ["Finance", "Legal", "Executive"]:
            justifications.append(f"High-risk department: {user.department}")
        
        # Privileged account
        if user.is_privileged_account:
            justifications.append(f"Privileged account: {user.role}")
        
        # Large file transfer
        if file.file_size_mb > 100:
            justifications.append(f"Large file transfer: {file.file_size_mb}MB")
        
        return justifications
    
    def generate_recommended_actions(
        self,
        remediation_action: RemediationAction,
        incident: IncidentContext,
        user: UserContext,
        history: OffenseHistory
    ) -> List[str]:
        """Generate specific recommended actions"""
        actions = []
        
        if remediation_action == RemediationAction.HARD_BLOCK:
            actions.extend([
                "Immediately revoke user session",
                "Delete/quarantine the file",
                "Block user access temporarily",
                "Notify Security Operations Center (SOC)",
                "Initiate security investigation",
                "Notify user's manager via Teams",
                "Document incident for compliance review"
            ])
        
        elif remediation_action == RemediationAction.ESCALATE_SECURITY:
            actions.extend([
                "Notify Security Team via Teams channel",
                "Flag incident for manual review",
                "Restrict file sharing permissions",
                "Monitor user activity for 48 hours",
                "Notify user's manager"
            ])
        
        elif remediation_action == RemediationAction.SOFT_REMEDIATION:
            actions.extend([
                "Redact sensitive data from file",
                "Restrict external sharing link",
                "Notify manager via Teams",
                "Send policy reminder to user",
                "Log warning in user profile"
            ])
        
        elif remediation_action == RemediationAction.WARN_EDUCATE:
            actions.extend([
                "Send policy reminder email to user",
                "Log warning for tracking",
                "Assign security awareness training",
                "Notify via email with training resources"
            ])
        
        # Add training recommendation if not completed
        if not history.completed_training:
            actions.append("Assign mandatory DLP training module")
        
        return actions
    
    def assess_risk(
        self,
        incident: IncidentContext,
        user: UserContext,
        file: FileContext,
        history: OffenseHistory
    ) -> RiskAssessment:
        """
        Main decision engine method - comprehensive risk assessment
        """
        self.log("=" * 60)
        self.log(f"Starting Risk Assessment for Incident: {incident.incident_id}")
        self.log(f"User: {user.user_id} | Department: {user.department} | Role: {user.role}")
        self.log(f"File: {file.file_name} | Sensitivity: {file.sensitivity_label}")
        self.log("=" * 60)
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(incident, user, file, history)
        
        # Determine risk level
        risk_level = self.determine_risk_level(risk_score)
        self.log(f"Risk Level: {risk_level.value}")
        
        # Determine remediation action
        remediation_action = self.determine_remediation_action(risk_level, history, incident)
        self.log(f"Remediation Action: {remediation_action.value}")
        
        # Generate justification
        justifications = self.generate_justification(risk_score, incident, user, file, history)
        
        # Generate recommended actions
        recommended_actions = self.generate_recommended_actions(
            remediation_action, incident, user, history
        )
        
        # Calculate confidence based on data completeness
        confidence = self._calculate_confidence(user, file, history)
        
        # Determine if escalation is required
        escalation_required = risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]
        
        self.log("=" * 60)
        self.log("Risk Assessment Complete")
        self.log("=" * 60)
        
        return RiskAssessment(
            risk_level=risk_level,
            risk_score=risk_score,
            remediation_action=remediation_action,
            justification=justifications,
            confidence=confidence,
            recommended_actions=recommended_actions,
            escalation_required=escalation_required
        )
    
    def _calculate_confidence(
        self,
        user: UserContext,
        file: FileContext,
        history: OffenseHistory
    ) -> float:
        """Calculate confidence score based on data completeness"""
        confidence = 1.0
        
        # Reduce confidence if key data is missing
        if not user.department:
            confidence -= 0.1
        if not user.role:
            confidence -= 0.1
        if not file.sensitivity_label:
            confidence -= 0.15
        if history.total_offenses == 0 and not history.last_offense_date:
            confidence -= 0.05
        
        return max(confidence, 0.5)  # Minimum 50% confidence
    