"""
Email Notification Service using Microsoft Graph API

This module provides email notification functionality for DLP violations,
security training invitations, and admin alerts. All sensitive data is
automatically masked before being included in emails to prevent DLP loops.

Usage:
    from email_notifications import GraphEmailNotificationService

    service = GraphEmailNotificationService()
    await service.send_violation_notification(
        recipient="user@example.com",
        violation_types=["KTP", "NPWP"],
        violation_count=2
    )
"""

import logging
from typing import List, Optional
from datetime import datetime
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.users.item.send_mail.send_mail_post_request_body import SendMailPostRequestBody
from msgraph.generated.models.message import Message
from msgraph.generated.models.item_body import ItemBody
from msgraph.generated.models.body_type import BodyType
from msgraph.generated.models.recipient import Recipient
from msgraph.generated.models.email_address import EmailAddress

# Import from our modules
from config import settings
from exceptions import EmailSendException
from sensitive_data import SensitiveDataDetector

logger = logging.getLogger(__name__)


class GraphEmailNotificationService:
    """Send email notifications using Microsoft Graph API - No SMTP needed!"""
    
    def __init__(self):
        # Use centralized configuration from settings
        self.tenant_id = settings.TENANT_ID
        self.client_id = settings.BOT_CLIENT_ID
        self.client_secret = settings.BOT_CLIENT_SECRET
        self.sender_email = settings.SENDER_EMAIL
        self.admin_email = settings.ADMIN_EMAIL

        # Validate configuration
        if not all([self.tenant_id, self.client_id, self.client_secret, self.sender_email]):
            logger.error("[ERROR] Missing Graph API credentials!")
            logger.error(f"   TENANT_ID: {'Set' if self.tenant_id else 'NOT SET'}")
            logger.error(f"   BOT_CLIENT_ID: {'Set' if self.client_id else 'NOT SET'}")
            logger.error(f"   BOT_CLIENT_SECRET: {'Set' if self.client_secret else 'NOT SET'}")
            logger.error(f"   SENDER_EMAIL: {'Set' if self.sender_email else 'NOT SET'}")
            raise EmailSendException(
                "Missing required email configuration",
                details={"configured_fields": [f for f in ["tenant_id", "client_id", "client_secret", "sender_email"] if getattr(self, f)]}
            )
        else:
            logger.info("[OK] Graph Email Service initialized")
    
    def _get_graph_client(self) -> Optional[GraphServiceClient]:
        """Initialize Graph client with service principal authentication"""
        try:
            credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            return GraphServiceClient(credentials=credential)
        except Exception as e:
            logger.error(f"[ERROR] Failed to initialize Graph client: {e}")
            raise EmailSendException(
                "Failed to initialize Graph client",
                details={"error": str(e)},
                original_exception=e
            )
    
    async def send_email_via_graph(
        self, 
        recipient: str, 
        subject: str, 
        html_body: str
    ) -> bool:
        """
        Send email using Microsoft Graph API
        
        Args:
            recipient: Email address of recipient
            subject: Email subject
            html_body: HTML content of email
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            client = self._get_graph_client()
            if not client:
                logger.error("[ERROR] Cannot send email - Graph client initialization failed")
                return False
            
            logger.info(f"[EMAIL] Preparing email via Graph API")
            logger.info(f"   From: {self.sender_email}")
            logger.info(f"   To: {recipient}")
            logger.info(f"   Subject: {subject}")
            
            # Create the message
            message = Message()
            message.subject = subject
            message.body = ItemBody()
            message.body.content_type = BodyType.Html
            message.body.content = html_body
            message.to_recipients = [
                Recipient(
                    email_address=EmailAddress(
                        address=recipient
                    )
                )
            ]
            
            # Create send mail request
            send_mail_body = SendMailPostRequestBody()
            send_mail_body.message = message
            send_mail_body.save_to_sent_items = True
            
            # Send the email using the sender's mailbox
            await client.users.by_user_id(self.sender_email).send_mail.post(send_mail_body)
            
            logger.info(f"[OK] Email successfully sent via Graph API to {recipient}")
            return True
            
        except Exception as e:
            logger.error(f"[ERROR] Failed to send email via Graph API: {e}")
            logger.error(f"   Error type: {type(e).__name__}")
            import traceback
            logger.error(f"   Traceback: {traceback.format_exc()}")
            return False
    
    async def send_violation_notification(
        self,
        recipient: str,
        violation_types: List[str],
        violation_count: int,
        blocked_content_summary: str = None,
        incident_title: str = None,
        file_name: str = None
    ) -> bool:
        """
        Send DLP violation notification email

        Args:
            recipient: User's email address
            violation_types: List of violation types detected
            violation_count: Total number of violations for this user
            blocked_content_summary: Sample of blocked content (will be masked)
            incident_title: Title of the incident
            file_name: Name of the file that triggered the violation

        Returns:
            bool: True if email sent successfully
        """

        # ⚠️ CRITICAL: ALWAYS MASK ALL SENSITIVE DATA BEFORE PROCESSING
        # This prevents the notification emails from triggering DLP policies
        if blocked_content_summary:
            blocked_content_summary = SensitiveDataDetector.mask_sensitive_data(str(blocked_content_summary))

        if incident_title:
            incident_title = SensitiveDataDetector.mask_sensitive_data(str(incident_title))

        if file_name:
            file_name = SensitiveDataDetector.mask_sensitive_data(str(file_name))

        if not all([self.tenant_id, self.client_id, self.client_secret, self.sender_email]):
            logger.error("[ERROR] Email credentials not configured!")
            return False
        
        # Convert list to string if needed
        violation_type_str = ", ".join(violation_types) if isinstance(violation_types, list) else str(violation_types)

        # Determine severity - 3-TIER SYSTEM
        is_low = violation_count == 1
        is_medium = violation_count == 2
        is_critical = violation_count >= 3

        # DLP-safe subject line (no emojis, clear categorization for exception rules)
        # Different subject for each risk level
        if is_low:
            subject = "[EDUCATION] Security Training - DLP Policy Awareness"
        elif is_medium:
            subject = f"[WARNING] Email Blocked - DLP Policy Violation #{violation_count}"
        else:  # is_critical
            subject = f"[CRITICAL] Account Locked - DLP Policy Violation #{violation_count}"
        
        # Build violation tags HTML
        violation_tags_html = ""
        for vtype in (violation_types if isinstance(violation_types, list) else [violation_types]):
            violation_tags_html += f'<span class="violation-tag">{vtype}</span>'
        
        # Create HTML email with complete styling
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #f5f5f5;
                    margin: 0;
                    padding: 0;
                    line-height: 1.6;
                }}
                .container {{
                    max-width: 650px;
                    margin: 20px auto;
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    overflow: hidden;
                }}
                .header {{
                    background-color: {'#dc3545' if is_critical else ('#ffc107' if is_medium else '#10b981')};
                    background: {'linear-gradient(135deg, #dc3545 0%, #bd2130 100%)' if is_critical else ('linear-gradient(135deg, #ffc107 0%, #e0a800 100%)' if is_medium else 'linear-gradient(135deg, #10b981 0%, #059669 100%)')};
                    color: {'white' if (is_critical or is_low) else '#212529'};
                    padding: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 28px;
                    font-weight: 700;
                }}
                .header p {{
                    margin: 10px 0 0 0;
                    font-size: 16px;
                    opacity: 0.95;
                }}
                .content {{
                    padding: 35px;
                }}
                .alert-box {{
                    background: {'#fff5f5' if is_critical else ('#fff3cd' if is_medium else '#d1f4e0')};
                    border-left: 4px solid {'#dc3545' if is_critical else ('#ffc107' if is_medium else '#10b981')};
                    padding: 18px;
                    margin: 25px 0;
                    border-radius: 4px;
                }}
                .alert-box strong {{
                    color: {'#721c24' if is_critical else ('#856404' if is_medium else '#065f46')};
                    font-size: 15px;
                }}
                .info-box {{
                    background: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 25px 0;
                }}
                .info-item {{
                    display: flex;
                    padding: 12px 0;
                    border-bottom: 1px solid #dee2e6;
                }}
                .info-item:last-child {{
                    border-bottom: none;
                }}
                .info-label {{
                    font-weight: 600;
                    width: 180px;
                    color: #495057;
                }}
                .info-value {{
                    color: #212529;
                    flex: 1;
                }}
                .redacted-box {{
                    background: #fff9e6;
                    border: 2px dashed #ffc107;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 25px 0;
                    font-family: 'Courier New', monospace;
                }}
                .redacted-box p {{
                    color: #856404;
                    margin: 8px 0;
                }}
                .warning-badge {{
                    display: inline-block;
                    background: {'#dc3545' if is_critical else ('#ffc107' if is_medium else '#10b981')};
                    color: {'white' if (is_critical or is_low) else '#212529'};
                    padding: 8px 16px;
                    border-radius: 20px;
                    font-size: 13px;
                    font-weight: 700;
                    text-transform: uppercase;
                    margin: 10px 0;
                }}
                .steps-list {{
                    background: #e7f3ff;
                    border-left: 4px solid #007bff;
                    padding: 20px 20px 20px 45px;
                    margin: 25px 0;
                    border-radius: 4px;
                }}
                .steps-list ol {{
                    margin: 0;
                    padding-left: 20px;
                }}
                .steps-list li {{
                    margin: 12px 0;
                    color: #004085;
                }}
                .violation-types {{
                    display: flex;
                    flex-wrap: wrap;
                    gap: 10px;
                    margin: 15px 0;
                }}
                .violation-tag {{
                    background: #dc3545;
                    color: white;
                    padding: 6px 14px;
                    border-radius: 15px;
                    font-size: 12px;
                    font-weight: 600;
                }}
                .education-section {{
                    background: #d1ecf1;
                    border: 1px solid #bee5eb;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 25px 0;
                }}
                .education-section h3 {{
                    color: #0c5460;
                    margin-top: 0;
                }}
                .education-section ul {{
                    margin: 10px 0;
                    padding-left: 20px;
                }}
                .education-section li {{
                    margin: 8px 0;
                    color: #0c5460;
                }}
                .critical-warning {{
                    background: #f8d7da;
                    border: 2px solid #dc3545;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 25px 0;
                    text-align: center;
                }}
                .critical-warning h3 {{
                    color: #721c24;
                    margin: 0 0 10px 0;
                }}
                .critical-warning p {{
                    color: #721c24;
                    font-size: 16px;
                    font-weight: 600;
                    margin: 5px 0;
                }}
                .footer {{
                    background: #f8f9fa;
                    padding: 20px;
                    text-align: center;
                    font-size: 12px;
                    color: #6c757d;
                    border-top: 1px solid #dee2e6;
                }}
                .footer p {{
                    margin: 5px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{'CRITICAL ALERT' if is_critical else ('Email Blocked' if is_medium else 'Security Training Notice')}</h1>
                    <p>Data Loss Prevention System</p>
                </div>

                <div class="content">
                    <p style="font-size: 16px; color: #212529;">Dear User,</p>

                    <div class="alert-box">
                        <strong>{'WARNING: YOUR ACCOUNT HAS BEEN LOCKED' if is_critical else ('WARNING: Your email/document was blocked by our security system' if is_medium else 'EDUCATION: Your email/document contains sensitive information')}</strong>
                    </div>

                    <p>{'Your account has been locked because you have reached the maximum violation limit (3 violations). All sign-in sessions have been revoked to protect company data.' if is_critical else ('Your recent email or document was blocked because it contains <strong>sensitive information</strong> that violates company security policies.' if is_medium else 'We detected that your recent email or document contains <strong>sensitive information</strong>. This message is for <strong>educational purposes</strong> to help you understand our data security policies.')}</p>
                    
                    <div class="info-box">
                        <div class="info-item">
                            <div class="info-label">Violation Type:</div>
                            <div class="info-value">
                                <div class="violation-types">
                                    {violation_tags_html}
                                </div>
                            </div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Violation Count:</div>
                            <div class="info-value"><strong style="font-size: 18px; color: {'#dc3545' if is_critical else ('#ffc107' if is_medium else '#10b981')};">{violation_count}</strong> / 3 violations</div>
                        </div>
                        {f'<div class="info-item"><div class="info-label">File Name:</div><div class="info-value">{file_name}</div></div>' if file_name else ''}
                        {f'<div class="info-item"><div class="info-label">Incident:</div><div class="info-value">{incident_title}</div></div>' if incident_title else ''}
                        <div class="info-item">
                            <div class="info-label">Timestamp:</div>
                            <div class="info-value">{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</div>
                        </div>
                    </div>
                    
                    {f'''
                    <h3 style="color: #495057; margin-top: 30px;">Detected Content (Redacted for Security):</h3>
                    <div class="redacted-box">
                        <p><strong>Sample of blocked content:</strong></p>
                        <p style="font-size: 14px; margin-top: 10px;">
                            {blocked_content_summary}
                        </p>
                        <p style="font-size: 11px; color: #856404; margin-top: 15px; border-top: 1px dashed #ffc107; padding-top: 10px;">
                            <strong>Note:</strong> Actual sensitive data has been redacted for security purposes. The original content contained identifiable information.
                        </p>
                    </div>
                    ''' if blocked_content_summary else ''}
                    
                    <div class="education-section">
                        <h3>What Sensitive Data Was Detected?</h3>
                        <p>Our DLP system identified the following types of protected information in your content:</p>
                        <ul>
                            <li><strong>KTP (Kartu Tanda Penduduk)</strong> - Indonesian National ID Card numbers (16 digits)</li>
                            <li><strong>NPWP (Nomor Pokok Wajib Pajak)</strong> - Indonesian Tax Identification numbers (15-16 digits)</li>
                            <li><strong>Employee ID</strong> - Internal company employee identification numbers</li>
                            <li><strong>Confidential Documents</strong> - Files marked with confidential sensitivity labels</li>
                        </ul>
                        <p style="margin-top: 15px;"><strong>Why this matters:</strong> These data types are protected by Indonesian regulations (UU ITE, GDPR compliance) and company security policies. Unauthorized sharing can lead to identity theft, fraud, or regulatory penalties.</p>
                    </div>
                    
                    {'<div class="critical-warning"><h3>ACCOUNT LOCKED - IMMEDIATE ACTION REQUIRED</h3><p>You have reached the maximum violation limit (3 violations).</p><p>Your account sign-in has been revoked to protect company data.</p><p style="margin-top: 15px; font-size: 14px;">To regain access, you must:</p><ul style="text-align: left; display: inline-block; margin: 10px auto;"><li>Contact IT Security immediately</li><li>Complete mandatory security training</li><li>Review and acknowledge security policies</li></ul><p style="margin-top: 15px;"><strong>Contact:</strong> <a href="mailto:' + (self.admin_email or 'security@company.com') + '" style="color: #dc3545;">' + (self.admin_email or 'security@company.com') + '</a></p></div>' if is_critical else ''}

                    {f'<div class="alert-box"><strong>WARNING:</strong> You have <strong>{violation_count} out of 3</strong> violations. One more violation will result in automatic account suspension and mandatory security training.</div>' if is_medium else ''}

                    {'<div style="background: #d1f4e0; border-left: 4px solid #10b981; padding: 20px; margin: 25px 0; border-radius: 4px;"><p style="margin: 0; color: #065f46;"><strong>Good News:</strong> This is your first violation, so <strong>no action has been taken against your account</strong>. We are providing this education to help you understand our data security policies and prevent future violations.</p><p style="margin: 10px 0 0 0; color: #065f46;">Think of this as a <strong>friendly reminder</strong> to be more careful when handling sensitive information.</p></div>' if is_low else ''}
                    
                    <div class="steps-list">
                        <h3 style="color: #004085; margin-top: 0;">{'Immediate Actions Required:' if is_critical else ('Required Actions:' if is_medium else 'What You Should Know:')}</h3>
                        <ol>
                            {('<li><strong>Contact IT Security immediately:</strong> <a href="mailto:' + (self.admin_email or 'security@company.com') + '">' + (self.admin_email or 'security@company.com') + '</a> to unlock your account</li><li><strong>Complete mandatory security training</strong> before your account can be restored</li><li><strong>Review security policies</strong> and acknowledge understanding</li>') if is_critical else ('<li><strong>Review your content:</strong> Remove all sensitive information (KTP, NPWP, Employee IDs) before sending</li><li><strong>Use approved channels:</strong> For sharing sensitive data, use secure company portals or encrypted file sharing systems</li><li><strong>Verify recipient:</strong> Ensure the recipient is authorized to receive confidential information</li><li><strong>Apply data masking:</strong> When sharing examples, mask sensitive digits (e.g., 321***********456)</li><li><strong>Be more careful:</strong> One more violation will result in automatic account suspension</li><li><strong>Need help?</strong> Contact IT Security: <a href="mailto:' + (self.admin_email or 'security@company.com') + '">' + (self.admin_email or 'security@company.com') + '</a></li>' if is_medium else '<li><strong>Understand what data is sensitive:</strong> KTP, NPWP, Employee IDs, and other protected information should not be shared via regular email</li><li><strong>Use secure channels:</strong> For legitimate business needs, use encrypted file sharing or company-approved platforms</li><li><strong>Double-check before sending:</strong> Always review your attachments and email content before sending</li><li><strong>Learn more:</strong> Read our data security policies and best practices guides</li><li><strong>Questions?</strong> Contact IT Security: <a href="mailto:' + (self.admin_email or 'security@company.com') + '">' + (self.admin_email or 'security@company.com') + '</a></li>')}
                        </ol>
                    </div>
                    
                    <div class="education-section">
                        <h3>Best Practices for Data Security:</h3>
                        <ul>
                            <li><strong>Never include full ID numbers</strong> in emails or non-encrypted documents</li>
                            <li><strong>Use "Read Only" permissions</strong> when sharing documents in SharePoint/OneDrive</li>
                            <li><strong>Apply sensitivity labels</strong> to documents containing confidential data</li>
                            <li><strong>Encrypt emails</strong> containing sensitive information using Microsoft's encryption features</li>
                            <li><strong>Think before you share</strong> - Ask: "Does this person need to know this information?"</li>
                        </ul>
                    </div>
                    
                    <p style="margin-top: 30px; padding: 15px; background: #e7f3ff; border-radius: 4px; font-size: 14px;">
                        <strong>Tip:</strong> If you believe this is a legitimate business need, request access through the proper channels with manager approval and use the company's secure data sharing platform.
                    </p>
                    
                    <p style="margin-top: 25px; color: #6c757d;">If you believe this alert is in error or need assistance understanding these policies, please contact your IT Security team immediately.</p>
                </div>
                
                <div class="footer">
                    <p><strong>This is an automated security notification</strong></p>
                    <p>DLP Remediation Engine v2.0 | Powered by Microsoft Purview & Azure Sentinel</p>
                    <p>Please do not reply to this email - it is sent from an unmonitored mailbox</p>
                    <p style="margin-top: 10px; font-size: 11px;">© {datetime.now().year} Company Security Team. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return await self.send_email_via_graph(recipient, subject, html_content)
    
    async def send_socialization_invitation(
        self, 
        recipient: str,
        violation_count: int
    ) -> bool:
        """
        Send mandatory security training invitation after multiple violations
        
        Args:
            recipient: User's email address
            violation_count: Total number of violations
            
        Returns:
            bool: True if email sent successfully
        """
        
        if not all([self.tenant_id, self.client_id, self.client_secret, self.sender_email]):
            logger.error("Email credentials not configured")
            return False

        # DLP-safe subject line (no emojis)
        subject = "[MANDATORY] Security Training Required - DLP Policy Socialization"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #f5f5f5;
                    margin: 0;
                    padding: 0;
                    line-height: 1.6;
                }}
                .container {{
                    max-width: 650px;
                    margin: 20px auto;
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    overflow: hidden;
                }}
                .header {{
                    background-color: #007bff;
                    background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 28px;
                    font-weight: 700;
                }}
                .content {{
                    padding: 35px;
                }}
                .warning-box {{
                    background: #fff3cd;
                    border-left: 4px solid #ffc107;
                    padding: 18px;
                    margin: 25px 0;
                    border-radius: 4px;
                }}
                .training-box {{
                    background: #d1ecf1;
                    border: 1px solid #bee5eb;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 25px 0;
                }}
                .training-item {{
                    display: flex;
                    padding: 10px 0;
                    border-bottom: 1px solid #bee5eb;
                }}
                .training-item:last-child {{
                    border-bottom: none;
                }}
                .training-label {{
                    font-weight: 600;
                    width: 120px;
                    color: #0c5460;
                }}
                .training-value {{
                    color: #0c5460;
                }}
                .btn {{
                    display: inline-block;
                    padding: 15px 35px;
                    background: #28a745;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    margin: 20px 0;
                    font-weight: 600;
                    font-size: 16px;
                    text-align: center;
                }}
                .module-list {{
                    background: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 25px 0;
                }}
                .module-list h4 {{
                    color: #495057;
                    margin-top: 0;
                }}
                .footer {{
                    background: #f8f9fa;
                    padding: 20px;
                    text-align: center;
                    font-size: 12px;
                    color: #6c757d;
                    border-top: 1px solid #dee2e6;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Security Training Required</h1>
                    <p>Mandatory DLP Policy Socialization</p>
                </div>
                
                <div class="content">
                    <p style="font-size: 16px;">Dear User,</p>
                    
                    <div class="warning-box">
                        <strong>WARNING: You have accumulated {violation_count} DLP policy violations</strong>
                    </div>
                    
                    <p>Due to repeated violations of our Data Loss Prevention (DLP) policies, you are <strong>required to complete mandatory security training</strong> within the next 3 business days.</p>
                    
                    <p>This training is essential to help you understand:</p>
                    <ul>
                        <li>What constitutes sensitive data</li>
                        <li>How to handle confidential information properly</li>
                        <li>Company security policies and procedures</li>
                        <li>Legal and regulatory compliance requirements</li>
                    </ul>
                    
                    <div class="training-box">
                        <h3 style="color: #0c5460; margin-top: 0;">Training Details</h3>
                        <div class="training-item">
                            <div class="training-label">Topic:</div>
                            <div class="training-value">Data Security & DLP Best Practices</div>
                        </div>
                        <div class="training-item">
                            <div class="training-label">Duration:</div>
                            <div class="training-value">60 minutes (self-paced)</div>
                        </div>
                        <div class="training-item">
                            <div class="training-label">Format:</div>
                            <div class="training-value">Online via Microsoft Teams / Learning Portal</div>
                        </div>
                        <div class="training-item">
                            <div class="training-label">Deadline:</div>
                            <div class="training-value">Within 3 business days from receipt</div>
                        </div>
                        <div class="training-item">
                            <div class="training-label">Certificate:</div>
                            <div class="training-value">Yes - Required for compliance records</div>
                        </div>
                    </div>
                    
                    <div class="module-list">
                        <h4>Training Modules (60 minutes total):</h4>
                        <ol style="margin: 15px 0; padding-left: 20px;">
                            <li><strong>Introduction to Data Security</strong> (10 min)
                                <ul style="margin-top: 5px; font-size: 14px;">
                                    <li>Understanding sensitive data types</li>
                                    <li>Indonesian data protection regulations (UU ITE)</li>
                                </ul>
                            </li>
                            <li><strong>Identifying Sensitive Information</strong> (15 min)
                                <ul style="margin-top: 5px; font-size: 14px;">
                                    <li>KTP, NPWP, and Employee IDs</li>
                                    <li>Financial and health records</li>
                                    <li>Company confidential information</li>
                                </ul>
                            </li>
                            <li><strong>DLP Policies & Procedures</strong> (15 min)
                                <ul style="margin-top: 5px; font-size: 14px;">
                                    <li>Company DLP policies explained</li>
                                    <li>Violation consequences and escalation</li>
                                    <li>Reporting security incidents</li>
                                </ul>
                            </li>
                            <li><strong>Secure Communication Channels</strong> (10 min)
                                <ul style="margin-top: 5px; font-size: 14px;">
                                    <li>Using encryption and sensitivity labels</li>
                                    <li>Secure file sharing best practices</li>
                                    <li>Email security features</li>
                                </ul>
                            </li>
                            <li><strong>Practical Scenarios & Quiz</strong> (10 min)
                                <ul style="margin-top: 5px; font-size: 14px;">
                                    <li>Real-world case studies</li>
                                    <li>Knowledge assessment (passing score: 80%)</li>
                                </ul>
                            </li>
                        </ol>
                    </div>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="https://teams.microsoft.com/l/meetup-join/" class="btn">Start Training Now</a>
                        <p style="font-size: 13px; color: #6c757d; margin-top: 10px;">Training link will be active for 3 business days</p>
                    </div>
                    
                    <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 15px; margin: 25px 0;">
                        <p style="margin: 0; color: #856404;"><strong>Important:</strong> Failure to complete this training within the deadline may result in:</p>
                        <ul style="color: #856404; margin: 10px 0;">
                            <li>Temporary account suspension</li>
                            <li>Escalation to your manager and HR</li>
                            <li>Mandatory in-person training session</li>
                            <li>Formal documentation in your personnel file</li>
                        </ul>
                    </div>
                    
                    <p style="margin-top: 25px;">Upon successful completion, you will receive:</p>
                    <ul>
                        <li>Security awareness certificate</li>
                        <li>Updated access permissions</li>
                        <li>Reset of violation counter (with probationary period)</li>
                    </ul>
                    
                    <p style="margin-top: 25px; color: #6c757d;">If you have questions or need assistance scheduling the training, please contact:</p>
                    <p style="text-align: center; font-size: 16px; margin: 15px 0;">
                        <strong>IT Security Team:</strong> <a href="mailto:{self.admin_email}" style="color: #007bff;">{self.admin_email}</a>
                    </p>
                    
                    <p style="margin-top: 30px; padding: 15px; background: #e7f3ff; border-radius: 4px; font-size: 14px;">
                        <strong>Pro Tip:</strong> Set aside uninterrupted time to complete the training. You can pause and resume, but all modules must be completed for certification.
                    </p>
                </div>
                
                <div class="footer">
                    <p><strong>This is a mandatory training requirement</strong></p>
                    <p>DLP Remediation Engine v2.0 | Security Awareness Program</p>
                    <p>For technical support, contact IT Help Desk</p>
                    <p style="margin-top: 10px; font-size: 11px;">© {datetime.now().year} Company Security Team. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return await self.send_email_via_graph(recipient, subject, html_content)
    
    async def send_admin_alert(
        self,
        user: str,
        incident_title: str,
        violation_count: int,
        action_taken: str,
        violation_types: List[str] = None,
        file_name: str = None
    ) -> bool:
        """
        Send alert to admin about high-risk user activity

        Args:
            user: User's email address
            incident_title: Title of the incident
            violation_count: Total violations for this user
            action_taken: Action performed by the system
            violation_types: Types of violations detected
            file_name: Name of the file involved

        Returns:
            bool: True if email sent successfully
        """

        # ⚠️ CRITICAL: MASK ALL SENSITIVE DATA BEFORE PROCESSING
        # Admin emails must also be DLP-safe
        if incident_title:
            incident_title = SensitiveDataDetector.mask_sensitive_data(str(incident_title))

        if file_name:
            file_name = SensitiveDataDetector.mask_sensitive_data(str(file_name))

        if not self.admin_email:
            logger.warning("Admin email not configured")
            return False

        if not all([self.tenant_id, self.client_id, self.client_secret, self.sender_email]):
            logger.error("Email credentials not configured")
            return False

        is_critical = violation_count >= 3
        # DLP-safe subject line (no emojis, clear categorization)
        subject = f"[{'CRITICAL' if is_critical else 'ALERT'}] High-Risk Activity: {user}"
        
        violation_types_str = ", ".join(violation_types) if violation_types else "Unknown"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #f5f5f5;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 700px;
                    margin: 20px auto;
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    overflow: hidden;
                }}
                .header {{
                    background-color: {'#dc3545' if is_critical else '#ffc107'};
                    background: {'linear-gradient(135deg, #dc3545 0%, #c82333 100%)' if is_critical else 'linear-gradient(135deg, #ffc107 0%, #e0a800 100%)'};
                    color: {'white' if is_critical else '#212529'};
                    padding: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 28px;
                    font-weight: 700;
                }}
                .content {{
                    padding: 35px;
                }}
                .alert-section {{
                    background: {'#fff5f5' if is_critical else '#fff9e6'};
                    border-left: 4px solid {'#dc3545' if is_critical else '#ffc107'};
                    padding: 20px;
                    margin: 25px 0;
                    border-radius: 4px;
                }}
                .info-grid {{
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 15px;
                    margin: 25px 0;
                }}
                .info-card {{
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 8px;
                    border: 1px solid #dee2e6;
                }}
                .info-card-label {{
                    font-size: 12px;
                    color: #6c757d;
                    font-weight: 600;
                    text-transform: uppercase;
                    margin-bottom: 5px;
                }}
                .info-card-value {{
                    font-size: 20px;
                    color: #212529;
                    font-weight: 700;
                }}
                .detail-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 25px 0;
                }}
                .detail-table th {{
                    background: #f8f9fa;
                    padding: 12px;
                    text-align: left;
                    font-weight: 600;
                    color: #495057;
                    border-bottom: 2px solid #dee2e6;
                }}
                .detail-table td {{
                    padding: 12px;
                    border-bottom: 1px solid #dee2e6;
                }}
                .action-badge {{
                    display: inline-block;
                    padding: 6px 12px;
                    border-radius: 15px;
                    font-size: 12px;
                    font-weight: 600;
                    background: {'#dc3545' if is_critical else '#28a745'};
                    color: white;
                }}
                .btn {{
                    display: inline-block;
                    padding: 12px 25px;
                    background: #007bff;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    font-weight: 600;
                    margin: 20px 10px 20px 0;
                }}
                .footer {{
                    background: #f8f9fa;
                    padding: 20px;
                    text-align: center;
                    font-size: 12px;
                    color: #6c757d;
                    border-top: 1px solid #dee2e6;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{'CRITICAL SECURITY ALERT' if is_critical else 'DLP Security Alert'}</h1>
                    <p>Immediate Administrative Action Required</p>
                </div>
                
                <div class="content">
                    <p style="font-size: 16px; font-weight: 600;">Security Team,</p>
                    
                    <div class="alert-section">
                        <p style="margin: 0; font-size: 15px; {'color: #721c24;' if is_critical else 'color: #856404;'}">
                            <strong>{'CRITICAL: User account has been automatically locked due to repeated policy violations' if is_critical else 'WARNING: High-risk DLP activity detected requiring review'}</strong>
                        </p>
                    </div>
                    
                    <div class="info-grid">
                        <div class="info-card">
                            <div class="info-card-label">Violation Count</div>
                            <div class="info-card-value" style="color: {'#dc3545' if is_critical else '#ffc107'};">{violation_count}</div>
                        </div>
                        <div class="info-card">
                            <div class="info-card-label">Risk Level</div>
                            <div class="info-card-value" style="color: {'#dc3545' if is_critical else '#ffc107'};">{'CRITICAL' if is_critical else 'HIGH'}</div>
                        </div>
                    </div>
                    
                    <h3 style="color: #495057; margin-top: 30px;">Incident Details</h3>
                    <table class="detail-table">
                        <tr>
                            <th>Field</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td><strong>User</strong></td>
                            <td>{user}</td>
                        </tr>
                        <tr>
                            <td><strong>Total Violations</strong></td>
                            <td><span style="font-size: 18px; font-weight: 700; color: {'#dc3545' if is_critical else '#ffc107'};">{violation_count}</span></td>
                        </tr>
                        <tr>
                            <td><strong>Violation Types</strong></td>
                            <td>{violation_types_str}</td>
                        </tr>
                        <tr>
                            <td><strong>Incident Title</strong></td>
                            <td>{incident_title}</td>
                        </tr>
                        {f'<tr><td><strong>File Name</strong></td><td>{file_name}</td></tr>' if file_name else ''}
                        <tr>
                            <td><strong>Action Taken</strong></td>
                            <td><span class="action-badge">{action_taken}</span></td>
                        </tr>
                        <tr>
                            <td><strong>Timestamp</strong></td>
                            <td>{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</td>
                        </tr>
                    </table>
                    
                    {'''
                    <div style="background: #f8d7da; border: 2px solid #dc3545; border-radius: 8px; padding: 20px; margin: 25px 0;">
                        <h3 style="color: #721c24; margin-top: 0;">Critical Actions Performed</h3>
                        <ul style="color: #721c24; margin: 10px 0;">
                            <li><strong>Account sign-in revoked</strong> - User cannot access company resources</li>
                            <li><strong>Active sessions terminated</strong> - All current sessions have been logged out</li>
                            <li><strong>Email notification sent</strong> - User has been notified of account lock</li>
                            <li><strong>Security training assigned</strong> - Mandatory training required for account restoration</li>
                        </ul>
                    </div>
                    
                    <h3 style="color: #495057;">Required Administrative Actions</h3>
                    <ol style="line-height: 1.8;">
                        <li><strong>Review incident details</strong> in the DLP dashboard</li>
                        <li><strong>Contact user's manager</strong> for incident review and discussion</li>
                        <li><strong>Verify legitimate business need</strong> if user claims authorized access</li>
                        <li><strong>Schedule security training</strong> before account restoration</li>
                        <li><strong>Document incident</strong> in user's security record</li>
                        <li><strong>Consider additional measures</strong> based on violation severity and user history</li>
                    </ol>
                    ''' if is_critical else '''
                    <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 20px; margin: 25px 0;">
                        <h3 style="color: #856404; margin-top: 0;">Recommended Actions</h3>
                        <ul style="color: #856404; margin: 10px 0;">
                            <li><strong>Monitor user activity</strong> - Watch for additional violations</li>
                            <li><strong>Review with manager</strong> - Discuss proper data handling procedures</li>
                            <li><strong>Consider training</strong> - Proactive security awareness session</li>
                        </ul>
                    </div>
                    '''}
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="https://dlp-engine-a9g7hjfvczfjmdn.eastus-01.azurewebsites.net/" class="btn">View Full Dashboard</a>
                        <a href="https://portal.azure.com/" class="btn">Azure Portal</a>
                    </div>
                    
                    <div style="background: #e7f3ff; border-left: 4px solid #007bff; padding: 15px; margin: 25px 0; border-radius: 4px;">
                        <p style="margin: 0; color: #004085;">
                            <strong>Note:</strong> This alert was automatically generated by the DLP Remediation Engine. All actions have been logged and are available for audit review.
                        </p>
                    </div>
                    
                    <p style="margin-top: 25px; color: #6c757d; font-size: 14px;">
                        For questions or to escalate this incident, contact the Security Operations Center (SOC).
                    </p>
                </div>
                
                <div class="footer">
                    <p><strong>Automated Security Alert - DLP Remediation Engine v2.0</strong></p>
                    <p>Incident ID: DLP-{datetime.now().strftime("%Y%m%d%H%M%S")}</p>
                    <p>This message was sent to: {self.admin_email}</p>
                    <p style="margin-top: 10px; font-size: 11px;">© {datetime.now().year} Company Security Team. Confidential - For authorized personnel only.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return await self.send_email_via_graph(self.admin_email, subject, html_content)

    async def revoke_user_sessions(self, user_email: str) -> dict:
        """
        Revoke all active sign-in sessions for a user

        Args:
            user_email: User's email address (UPN)

        Returns:
            dict: {"ok": bool, "status": int, "message": str}
        """
        try:
            client = self._get_graph_client()

            # Call Microsoft Graph API to revoke sessions
            await client.users.by_user_id(user_email).revoke_sign_in_sessions.post()

            logger.info(f"[OK] Revoked all sign-in sessions for user: {user_email}")
            return {
                "ok": True,
                "status": 200,
                "message": f"All sign-in sessions revoked for {user_email}"
            }

        except Exception as e:
            logger.error(f"[ERROR] Failed to revoke sessions for {user_email}: {e}")
            return {
                "ok": False,
                "status": 500,
                "message": f"Failed to revoke sessions: {str(e)}"
            }

    async def block_user_account(self, user_email: str, block: bool = True) -> dict:
        """
        Block or unblock a user account

        Args:
            user_email: User's email address (UPN)
            block: True to block account, False to unblock

        Returns:
            dict: {"ok": bool, "status": int, "message": str}
        """
        try:
            client = self._get_graph_client()

            # Prepare the update payload
            from msgraph.generated.models.user import User
            user_update = User()
            user_update.account_enabled = not block  # accountEnabled=false blocks the user

            # Update user account status
            await client.users.by_user_id(user_email).patch(user_update)

            action = "blocked" if block else "unblocked"
            logger.info(f"[OK] Successfully {action} user account: {user_email}")
            return {
                "ok": True,
                "status": 200,
                "message": f"User account {action}: {user_email}"
            }

        except Exception as e:
            error_msg = str(e)
            logger.error(f"[ERROR] Failed to {'block' if block else 'unblock'} user {user_email}: {e}")
            logger.error(f"   Exception type: {type(e).__name__}")

            # Check for common permission errors
            if "Insufficient privileges" in error_msg or "Authorization_RequestDenied" in error_msg:
                logger.error("   [WARNING] PERMISSION ISSUE: Missing User.ReadWrite.All or admin consent not granted")
                logger.error("   [INFO] See AZURE_PERMISSIONS.md for setup instructions")
            elif "Resource" in error_msg and "not found" in error_msg:
                logger.error(f"   [WARNING] USER NOT FOUND: {user_email} doesn't exist in Azure AD")

            return {
                "ok": False,
                "status": 500,
                "message": f"Failed to {'block' if block else 'unblock'} account: {str(e)}"
            }

    async def revoke_user_access(self, user_email: str) -> dict:
        """
        Full revocation: Block account AND revoke all sessions

        This is the recommended approach for high-risk users.

        Args:
            user_email: User's email address (UPN)

        Returns:
            dict: {"ok": bool, "blocked": bool, "sessions_revoked": bool, "message": str}
        """
        logger.info(f"[CRITICAL] Initiating full access revocation for user: {user_email}")

        # Step 1: Block the account
        block_result = await self.block_user_account(user_email, block=True)

        # Log block result details
        if not block_result["ok"]:
            logger.error(f"   [ERROR] Account blocking failed: {block_result.get('message', 'Unknown error')}")

        # Step 2: Revoke all active sessions
        sessions_result = await self.revoke_user_sessions(user_email)

        # Log sessions result details
        if not sessions_result["ok"]:
            logger.error(f"   [ERROR] Session revocation failed: {sessions_result.get('message', 'Unknown error')}")

        overall_success = block_result["ok"] and sessions_result["ok"]

        if overall_success:
            logger.info(f"[OK] Full access revocation completed for {user_email}")
            message = f"Account blocked and all sessions revoked for {user_email}"
        else:
            logger.warning(f"[WARNING] Partial revocation for {user_email}")
            message = f"Partial revocation: Block={block_result['ok']}, Sessions={sessions_result['ok']}"

            # Add detailed failure message
            if not block_result["ok"]:
                message += f" | Block error: {block_result.get('message', 'Unknown')}"
            if not sessions_result["ok"]:
                message += f" | Sessions error: {sessions_result.get('message', 'Unknown')}"

        return {
            "ok": overall_success,
            "blocked": block_result["ok"],
            "sessions_revoked": sessions_result["ok"],
            "message": message,
            "details": {
                "block_result": block_result,
                "sessions_result": sessions_result
            }
        }


# Utility functions for backward compatibility
async def send_violation_email(
    recipient: str, 
    violation_types: List[str], 
    violation_count: int, 
    blocked_content: str = None,
    incident_title: str = None,
    file_name: str = None
) -> bool:
    """Quick function to send violation notification via Graph API"""
    service = GraphEmailNotificationService()
    return await service.send_violation_notification(
        recipient, 
        violation_types, 
        violation_count, 
        blocked_content,
        incident_title,
        file_name
    )


async def send_socialization_email(recipient: str, violation_count: int) -> bool:
    """Quick function to send socialization invitation via Graph API"""
    service = GraphEmailNotificationService()
    return await service.send_socialization_invitation(recipient, violation_count)


async def send_admin_alert(
    user: str,
    incident_title: str,
    violation_count: int,
    action_taken: str,
    violation_types: List[str] = None,
    file_name: str = None
) -> bool:
    """Quick function to send admin alert via Graph API"""
    service = GraphEmailNotificationService()
    return await service.send_admin_alert(
        user, 
        incident_title, 
        violation_count, 
        action_taken,
        violation_types,
        file_name
    )