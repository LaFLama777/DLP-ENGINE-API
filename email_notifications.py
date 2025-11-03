import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List
import logging

logger = logging.getLogger(__name__)


class EmailNotificationService:
    """Send email notifications for DLP violations"""
    
    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.office365.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.sender_email = os.getenv("SENDER_EMAIL")
        self.sender_password = os.getenv("SENDER_PASSWORD")
        self.admin_email = os.getenv("ADMIN_EMAIL")
        
        if not all([self.sender_email, self.sender_password]):
            logger.warning("Email credentials not configured")
    
    def send_violation_notification(self, 
                                    recipient: str,
                                    violation_type: str,
                                    violation_count: int,
                                    blocked_content_summary: str = None) -> bool:
        """
        Send email to user notifying them their email was blocked
        
        Args:
            recipient: User email address
            violation_type: Type of violation (KTP, NPWP, etc.)
            violation_count: Number of violations
            blocked_content_summary: Brief summary of blocked content
            
        Returns:
            bool: True if sent successfully
        """
        if not self.sender_email or not self.sender_password:
            logger.error("Email credentials not configured")
            return False
        
        subject = "⚠️ Email Delivery Failed - DLP Policy Violation"
        
        # Create HTML email
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #f5f5f5;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 600px;
                    margin: 40px auto;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 24px;
                }}
                .content {{
                    padding: 30px;
                }}
                .alert-box {{
                    background: #fff3cd;
                    border-left: 4px solid #ffc107;
                    padding: 15px;
                    margin: 20px 0;
                }}
                .info-box {{
                    background: #f8f9fa;
                    border-radius: 4px;
                    padding: 15px;
                    margin: 20px 0;
                }}
                .info-item {{
                    display: flex;
                    padding: 8px 0;
                    border-bottom: 1px solid #dee2e6;
                }}
                .info-item:last-child {{
                    border-bottom: none;
                }}
                .info-label {{
                    font-weight: 600;
                    width: 150px;
                    color: #6c757d;
                }}
                .info-value {{
                    color: #212529;
                }}
                .footer {{
                    background: #f8f9fa;
                    padding: 20px;
                    text-align: center;
                    font-size: 12px;
                    color: #6c757d;
                }}
                .btn {{
                    display: inline-block;
                    padding: 12px 24px;
                    background: #007bff;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    margin: 10px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚫 Email Delivery Failed</h1>
                </div>
                <div class="content">
                    <p>Dear User,</p>
                    
                    <div class="alert-box">
                        <strong>⚠️ Your email was blocked by the Data Loss Prevention (DLP) system.</strong>
                    </div>
                    
                    <p>Your recent email was not delivered because it contains sensitive information that violates company security policies.</p>
                    
                    <div class="info-box">
                        <div class="info-item">
                            <div class="info-label">Violation Type:</div>
                            <div class="info-value">{violation_type}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Violation Count:</div>
                            <div class="info-value">{violation_count}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Timestamp:</div>
                            <div class="info-value">{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
                        </div>
                    </div>
                    
                    <h3>🔒 What was detected:</h3>
                    <p>The system detected the following types of sensitive data:</p>
                    <ul>
                        <li><strong>KTP (ID Card Number)</strong> - 16 digit identification numbers</li>
                        <li><strong>NPWP (Tax ID)</strong> - Tax identification numbers</li>
                        <li><strong>Employee ID</strong> - Internal employee identifiers</li>
                    </ul>
                    
                    {"<div class='alert-box'><strong>⚠️ IMPORTANT:</strong> You have " + str(violation_count) + " violations. After 3 violations, your account sign-in will be revoked and you must contact IT support to regain access.</div>" if violation_count >= 2 else ""}
                    
                    <h3>📋 Next Steps:</h3>
                    <ol>
                        <li>Review your email content and remove any sensitive information</li>
                        <li>Use approved secure channels for sharing sensitive data</li>
                        <li>Contact IT Security if you need assistance: <a href="mailto:{self.admin_email or 'security@company.com'}">{self.admin_email or 'security@company.com'}</a></li>
                    </ol>
                    
                    {"<p style='color: #dc3545; font-weight: bold;'>⚠️ Your account has been locked due to repeated violations. Please contact IT support immediately.</p>" if violation_count >= 3 else ""}
                    
                    <p>If you believe this is an error, please contact your IT Security team.</p>
                </div>
                <div class="footer">
                    <p>This is an automated message from the DLP Remediation System.</p>
                    <p>Please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = self.sender_email
            msg['To'] = recipient
            msg['Subject'] = subject
            
            msg.attach(MIMEText(html_content, 'html'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            logger.info(f"Violation notification sent to {recipient}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {recipient}: {e}")
            return False
    
    def send_socialization_invitation(self, 
                                     recipient: str,
                                     violation_count: int) -> bool:
        """
        Send socialization/training invitation after multiple violations
        
        Args:
            recipient: User email address
            violation_count: Number of violations
            
        Returns:
            bool: True if sent successfully
        """
        if not self.sender_email or not self.sender_password:
            logger.error("Email credentials not configured")
            return False
        
        subject = "📚 Mandatory Security Training - DLP Policy Socialization"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #f5f5f5;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 600px;
                    margin: 40px auto;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                .content {{
                    padding: 30px;
                }}
                .warning-box {{
                    background: #fff3cd;
                    border-left: 4px solid #ffc107;
                    padding: 15px;
                    margin: 20px 0;
                }}
                .btn {{
                    display: inline-block;
                    padding: 12px 30px;
                    background: #28a745;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    margin: 20px 0;
                    font-weight: 600;
                }}
                .footer {{
                    background: #f8f9fa;
                    padding: 20px;
                    text-align: center;
                    font-size: 12px;
                    color: #6c757d;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📚 Security Training Required</h1>
                </div>
                <div class="content">
                    <p>Dear User,</p>
                    
                    <div class="warning-box">
                        <strong>⚠️ You have accumulated {violation_count} DLP policy violations.</strong>
                    </div>
                    
                    <p>Due to repeated violations of our Data Loss Prevention policies, you are required to attend a mandatory security training session.</p>
                    
                    <h3>📋 Training Details:</h3>
                    <ul>
                        <li><strong>Topic:</strong> Data Security & DLP Best Practices</li>
                        <li><strong>Duration:</strong> 1 hour</li>
                        <li><strong>Format:</strong> Online via Microsoft Teams</li>
                        <li><strong>Deadline:</strong> Within 3 business days</li>
                    </ul>
                    
                    <h3>📚 What You'll Learn:</h3>
                    <ul>
                        <li>Understanding sensitive data types (KTP, NPWP, Employee IDs)</li>
                        <li>Proper handling of confidential information</li>
                        <li>Secure communication channels</li>
                        <li>Company security policies and procedures</li>
                    </ul>
                    
                    <div style="text-align: center;">
                        <a href="https://teams.microsoft.com/l/meetup-join/" class="btn">Join Training Session</a>
                    </div>
                    
                    <p><strong>Note:</strong> Failure to complete this training may result in account suspension.</p>
                    
                    <p>If you have questions, contact IT Security at <a href="mailto:{self.admin_email or 'security@company.com'}">{self.admin_email or 'security@company.com'}</a></p>
                </div>
                <div class="footer">
                    <p>This is an automated message from the DLP Remediation System.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = self.sender_email
            msg['To'] = recipient
            msg['Subject'] = subject
            
            msg.attach(MIMEText(html_content, 'html'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            logger.info(f"Socialization invitation sent to {recipient}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send socialization email to {recipient}: {e}")
            return False
    
    def send_admin_alert(self, 
                        user: str,
                        violation_type: str,
                        violation_count: int,
                        action_taken: str) -> bool:
        """
        Send alert to admin about high-risk user activity
        
        Args:
            user: User who triggered the violation
            violation_type: Type of violation
            violation_count: Total violation count
            action_taken: Action taken by the system
            
        Returns:
            bool: True if sent successfully
        """
        if not self.admin_email:
            logger.warning("Admin email not configured")
            return False
        
        subject = f"🚨 DLP Alert: High-Risk Activity - {user}"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: #dc3545;">🚨 DLP Security Alert</h2>
            <p><strong>User:</strong> {user}</p>
            <p><strong>Violation Type:</strong> {violation_type}</p>
            <p><strong>Total Violations:</strong> {violation_count}</p>
            <p><strong>Action Taken:</strong> {action_taken}</p>
            <p><strong>Timestamp:</strong> {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
            
            {"<p style='color: red; font-weight: bold;'>⚠️ CRITICAL: User account has been locked due to repeated violations.</p>" if violation_count >= 3 else ""}
            
            <p>Please review this incident in the DLP dashboard.</p>
        </body>
        </html>
        """
        
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = self.sender_email
            msg['To'] = self.admin_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(html_content, 'html'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            logger.info(f"Admin alert sent for user {user}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send admin alert: {e}")
            return False


# Utility functions
def send_violation_email(recipient: str, violation_type: str, violation_count: int) -> bool:
    """Quick function to send violation notification"""
    service = EmailNotificationService()
    return service.send_violation_notification(recipient, violation_type, violation_count)


def send_socialization_email(recipient: str, violation_count: int) -> bool:
    """Quick function to send socialization invitation"""
    service = EmailNotificationService()
    return service.send_socialization_invitation(recipient, violation_count)