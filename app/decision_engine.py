from dataclasses import dataclass
from typing import Optional

@dataclass
class IncidentContext:
    """Dataclass representing the context of an incident."""
    severity: str  # e.g., 'Low', 'Medium', 'High'

@dataclass
class UserContext:
    """Dataclass representing the user's context."""
    department: str  # e.g., 'Finance', 'HR', 'IT'

@dataclass
class FileContext:
    """Dataclass representing the file's context."""
    sensitivity_label: str  # e.g., 'Public', 'Confidential'

@dataclass
class OffenseHistory:
    """Dataclass representing the user's offense history."""
    previous_offenses: int  # Number of previous offenses

@dataclass
class RiskAssessment:
    """Dataclass representing the final risk assessment output."""
    score: int  # Calculated risk score (0-100)
    risk_level: str  # e.g., 'Low', 'Medium', 'High', 'Critical'
    remediation_action: str  # e.g., 'Warn & Educate', 'Soft Remediation', 'Hard Block'

class AdvancedDecisionEngine:
    """
    A class for calculating risk scores and determining risk levels and remediation actions
    based on incident, user, file, and offense history contexts.
    """
    
    def calculate_risk_score(self, incident: IncidentContext, user: UserContext, file: FileContext, offense: OffenseHistory) -> int:
        """
        Calculate a risk score (0-100) based on multiple factors:
        - Incident severity
        - File sensitivity label
        - User's department risk
        - User's offense history
        
        This method includes detailed print statements to log the calculation steps.
        
        Args:
        - incident (IncidentContext): The incident details.
        - user (UserContext): The user details.
        - file (FileContext): The file details.
        - offense (OffenseHistory): The offense history.
        
        Returns:
        - int: The final risk score (clamped between 0 and 100).
        """
        # Step 1: Map incident severity to a base score
        severity_map = {'Low': 20, 'Medium': 50, 'High': 80}  # Custom mapping
        base_score = severity_map.get(incident.severity, 0)  # Default to 0 if invalid
        print(f"Step 1: Base score from incident severity '{incident.severity}': {base_score}")
        
        # Step 2: Apply file sensitivity multiplier
        file_multiplier = 1.0 if file.sensitivity_label == 'Public' else 1.5  # 'Confidential' has higher multiplier
        print(f"Step 2: File sensitivity multiplier for '{file.sensitivity_label}': {file_multiplier}")
        
        # Step 3: Apply user's department risk multiplier
        department_multipliers = {'Finance': 1.5, 'HR': 1.2, 'IT': 1.0, 'Marketing': 1.1}  # Example multipliers
        dept_multiplier = department_multipliers.get(user.department, 1.0)  # Default to 1.0 if department not found
        print(f"Step 3: Department risk multiplier for '{user.department}': {dept_multiplier}")
        
        # Step 4: Add points from offense history
        offense_points = min(offense.previous_offenses * 10, 50)  # 10 points per offense, capped at 50
        print(f"Step 4: Offense points from {offense.previous_offenses} previous offenses: {offense_points}")
        
        # Step 5: Compute intermediate score
        intermediate_score = (base_score + offense_points) * file_multiplier * dept_multiplier
        print(f"Step 5: Intermediate score after applying all factors: {intermediate_score}")
        
        # Step 6: Clamp the score to 0-100
        final_score = int(min(max(intermediate_score, 0), 100))  # Ensure it's between 0 and 100
        print(f"Step 6: Final clamped score: {final_score}")
        
        return final_score
    
    def get_risk_level(self, score: int) -> str:
        """
        Determine the risk level based on the calculated score.
        
        Args:
        - score (int): The risk score (0-100).
        
        Returns:
        - str: The risk level ('Low', 'Medium', 'High', or 'Critical').
        """
        if score < 30:
            return 'Low'
        elif score < 60:
            return 'Medium'
        elif score < 80:
            return 'High'
        else:
            return 'Critical'
    
    def get_remediation_action(self, score: int) -> str:
        """
        Determine the remediation action based on the calculated score.
        
        Args:
        - score (int): The risk score (0-100).
        
        Returns:
        - str: The remediation action ('Warn & Educate', 'Soft Remediation', or 'Hard Block').
        """
        if score < 40:
            return 'Warn & Educate'
        elif score < 70:
            return 'Soft Remediation'
        else:
            return 'Hard Block'
    
    def assess_risk(self, incident: IncidentContext, user: UserContext, file: FileContext, offense: OffenseHistory) -> Optional[RiskAssessment]:
        """
        Orchestrate the full risk assessment process.
        
        Args:
        - incident (IncidentContext): The incident details.
        - user (UserContext): The user details.
        - file (FileContext): The file details.
        - offense (OffenseHistory): The offense history.
        
        Returns:
        - RiskAssessment: An instance containing the score, risk level, and remediation action.
        - None: If an error occurs (though this method doesn't explicitly handle errors).
        """
        try:
            score = self.calculate_risk_score(incident, user, file, offense)
            risk_level = self.get_risk_level(score)
            remediation_action = self.get_remediation_action(score)
            return RiskAssessment(score=score, risk_level=risk_level, remediation_action=remediation_action)
        except Exception as e:
            print(f"Error during risk assessment: {str(e)}")
            return None  # Fallback in case of any issues

