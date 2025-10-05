from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from enum import Enum
import logging
import uuid
from datetime import datetime
import os
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient

# Configuration (Akan dibaca dari main.py atau environment variables)
TENANT_ID = os.getenv('TENANT_ID')
BOT_CLIENT_ID = os.getenv('BOT_CLIENT_ID')
AZURE_CLIENT_SECRET = os.getenv('BOT_CLIENT_SECRET') 
TEAMS_CHANNEL_ID = os.getenv('GRAPH_CHANNEL_ID')
TEAMS_TEAM_ID = os.getenv('GRAPH_TEAM_ID')

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class RemediationAction(Enum):
    HARD_BLOCK = "hard_block"
    SOFT_REMEDIATION = "soft_remediation"
    WARN_EDUCATE = "warn_educate"
    NOTIFY_ONLY = "notify_only"

class CommunicationChannel(Enum):
    SECURITY_TEAMS = "security_teams"
    MANAGER_EMAIL = "manager_email"
    USER_TRAINING = "user_training"

@dataclass
class SentinelIncident:
    incident_id: str
    title: str
    severity: str
    status: str
    created_time: str
    user_principal_name: Optional[str]
    file_name: Optional[str]
    file_directory: Optional[str]
    application_name: Optional[str]
    alert_details: Dict[str, Any]
    entities: List[Dict[str, Any]]

@dataclass
class UserContext:
    user_id: str
    upn: str
    department: Optional[str]
    role: Optional[str]
    manager_email: Optional[str]
    offense_history: int
    risk_score: float

@dataclass
class FileContext:
    file_name: str
    file_path: str
    sensitivity_label: Optional[str]
    owner: str
    created_date: str
    modified_date: str
    size_bytes: int

@dataclass
class RemediationDecision:
    incident_id: str
    risk_level: RiskLevel
    action: RemediationAction
    reasoning: str
    user_context: UserContext
    file_context: Optional[FileContext]
    communication_channels: List[CommunicationChannel]
    remediation_steps: List[str]
    estimated_completion_time: str

@dataclass
class RemediationResponse:
    request_id: str
    incident_id: str
    timestamp: str
    decision: RemediationDecision
    actions_taken: List[str]
    notifications_sent: List[Dict[str, Any]]
    audit_log: Dict[str, Any]

class MicrosoftGraphClient:
    def __init__(self):
        if not all([AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET]):
            raise ValueError("Azure credentials (Tenant, Client ID, Client Secret) not found in environment variables.")
        self.credential = ClientSecretCredential(
            tenant_id=AZURE_TENANT_ID,
            client_id=AZURE_CLIENT_ID,
            client_secret=AZURE_CLIENT_SECRET
        )
        self.graph_client = GraphServiceClient(credentials=self.credential, scopes=['https://graph.microsoft.com/.default'])

    async def get_user_profile(self, upn: str) -> Dict[str, Any]:
        try:
            user = await self.graph_client.users.by_user_id(upn).get()
            return {
                "id": user.id, "upn": user.user_principal_name, "display_name": user.display_name,
                "department": user.department, "job_title": user.job_title,
            }
        except Exception as e:
            logger.error(f"Error getting user profile for {upn}: {str(e)}")
            return {}

    async def send_teams_message(self, team_id: str, channel_id: str, message_payload: Dict[str, Any]) -> bool:
        try:
            await self.graph_client.teams.by_team_id(team_id).channels.by_channel_id(channel_id).messages.post(message_payload)
            return True
        except Exception as e:
            logger.error(f"Error sending Teams message: {str(e)}")
            return False

class SentinelIncidentParser:
    @staticmethod
    def parse_incident(incident_data: Dict[str, Any]) -> SentinelIncident:
        properties = incident_data.get("properties", {})
        user_upn, file_name, file_directory, app_name = None, None, None, None
        entities = properties.get("relatedEntities", [])
        for entity in entities:
            entity_props = entity.get("properties", {})
            if entity.get("kind") == "Account":
                user_upn = entity_props.get("additionalData", {}).get("UserPrincipalName")
            elif entity.get("kind") == "File":
                file_name = entity_props.get("fileName", "").replace("%20", " ")
                file_directory = entity_props.get("directory")
            elif entity.get("kind") == "CloudApplication":
                app_name = entity_props.get("appName")
        return SentinelIncident(
            incident_id=incident_data.get("name", ""), title=properties.get("title", ""),
            severity=properties.get("severity", ""), status=properties.get("status", ""),
            created_time=properties.get("createdTimeUtc", ""), user_principal_name=user_upn,
            file_name=file_name, file_directory=file_directory, application_name=app_name,
            alert_details=properties.get("alerts", [{}])[0] if properties.get("alerts") else {},
            entities=entities
        )

# Placeholder classes and functions for full implementation
class RemediationDecisionEngine:
    async def make_decision(self, incident: SentinelIncident) -> dict:
        # Placeholder for decision logic
        return {"risk_level": "Low", "action": "Notify Only"}

class TeamsNotificationService:
    async def send_remediation_notification(self, decision: dict) -> dict:
        # Placeholder for notification
        return {"status": "sent"}

async def apply_remediation_actions(decision: dict) -> List[str]:
    # Placeholder for actions
    return ["Action placeholder executed"]