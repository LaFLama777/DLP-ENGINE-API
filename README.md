# 🛡️ DLP Remediation Engine

**Version 2.0.0** | Advanced Data Loss Prevention & Automated Response System

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green.svg)](https://fastapi.tiangolo.com/)
[![Azure](https://img.shields.io/badge/Azure-Cloud-0078D4.svg)](https://azure.microsoft.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📋 Overview

A sophisticated, cloud-native Data Loss Prevention (DLP) engine that automatically detects, analyzes, and remediates security incidents involving sensitive data leakage. Built for enterprise environments, this system integrates with Microsoft Azure services (Sentinel, Purview, Microsoft 365) to provide real-time threat response and compliance enforcement.

### 🎯 Key Features

- **🔍 Intelligent Detection** - Automatically identifies sensitive data patterns (KTP, NPWP, Employee IDs)
- **⚡ Real-time Response** - Instant blocking and remediation of policy violations
- **🤖 Risk-based Engine** - Advanced decision engine calculates risk scores based on multiple factors
- **📧 Email Notifications** - Microsoft Graph API-powered notification system
- **🔒 Account Management** - Automatic account revocation for repeat offenders
- **📊 Analytics Dashboard** - Beautiful web UI with real-time statistics and charts
- **🔗 Multi-source Integration** - Works with Azure Sentinel, Microsoft Purview DLP, and custom webhooks
- **💾 PostgreSQL Backend** - Robust offense tracking with Supabase integration

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Data Sources                              │
│  Azure Sentinel │ Microsoft Purview │ Custom Logic Apps     │
└────────────┬────────────────┬────────────────┬──────────────┘
             │                │                │
             └────────────────┼────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │   FastAPI Server   │
                    │   (Main Engine)    │
                    └─────────┬──────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
│ Decision       │  │ Database        │  │ Notification    │
│ Engine         │  │ (PostgreSQL)    │  │ Service         │
│ (Risk Scoring) │  │                 │  │ (Graph API)     │
└────────────────┘  └─────────────────┘  └─────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Azure subscription with:
  - Azure App Service
  - Azure Sentinel workspace
  - Microsoft 365 E5 license (for Purview DLP)
  - Azure AD app registration
- PostgreSQL database (Supabase recommended)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/dlp-engine.git
   cd dlp-engine
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   
   Create a `.env` file in the root directory:
   ```env
   # Database Configuration
   DATABASE_URL=postgresql://user:password@host:5432/dbname?sslmode=require
   
   # Azure AD / Microsoft Graph API
   TENANT_ID=your-tenant-id
   BOT_CLIENT_ID=your-app-client-id
   BOT_CLIENT_SECRET=your-client-secret
   
   # Email Configuration
   SENDER_EMAIL=dlp-bot@yourcompany.com
   ADMIN_EMAIL=security-team@yourcompany.com
   ```

4. **Initialize the database**
   ```bash
   python -c "from database import create_db_and_tables; create_db_and_tables()"
   ```

5. **Run locally**
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

6. **Access the dashboard**
   - API: http://localhost:8000
   - Web UI: http://localhost:8000/
   - API Docs: http://localhost:8000/docs

---

## 📡 API Endpoints

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check and system status |
| `POST` | `/remediate` | Process Sentinel incidents (Logic App webhook) |
| `POST` | `/check-email` | Validate email content for sensitive data |
| `POST` | `/webhook/purview` | Receive Purview DLP alerts |
| `POST` | `/webhook/eventgrid` | Azure Event Grid webhook |

### UI Routes

| Route | Description |
|-------|-------------|
| `/` | Main dashboard with statistics |
| `/ui/incidents` | View all incidents with pagination |
| `/ui/users` | User violation rankings |
| `/ui/health` | System health check page |
| `/ui/stats` | Detailed statistics |

### Example Request

**Processing a DLP Incident:**
```bash
curl -X POST http://localhost:8000/remediate \
  -H "Content-Type: application/json" \
  -d @sentinel_payload.json
```

**Check Email Content:**
```bash
curl -X POST http://localhost:8000/check-email \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "user@company.com",
    "content": "KTP: 3201234567890123 NPWP: 123456789012345"
  }'
```

---

## 🧠 Decision Engine

The advanced decision engine calculates risk scores (0-100) based on:

1. **Incident Severity** - Low (20), Medium (50), High (80)
2. **File Sensitivity** - Public (1.0x), Confidential (1.5x)
3. **User Department** - Finance (1.5x), HR (1.2x), IT (1.0x), Marketing (1.1x)
4. **Offense History** - +10 points per violation (max 50)

### Risk Levels & Actions

| Score | Risk Level | Action |
|-------|-----------|--------|
| 0-29 | Low | Warn & Educate |
| 30-59 | Medium | Warn & Educate |
| 60-79 | High | Soft Remediation |
| 80-100 | Critical | Hard Block + Account Revocation |

### Violation Thresholds

- **1st Violation**: Email warning with security education
- **2nd Violation**: Escalated warning with manager notification
- **3rd Violation**: 🚨 **CRITICAL** - Account locked + Mandatory training

---

## 🔐 Sensitive Data Detection

The system detects the following patterns:

### Indonesian National ID (KTP)
```regex
\b\d{16}\b
```
Example: `3201234567890123`

### Tax ID (NPWP)
```regex
npwp[:\s-]*(\d{15,16})
```
Example: `NPWP: 123456789012345`

### Employee ID
```regex
\b(EMP|KARY|NIP)[-\s]?\d{4,6}\b
```
Example: `EMP-123456`

### Data Masking
Sensitive data in notifications is automatically masked:
- KTP: `321***********456` (first 3, last 3)
- NPWP: `12***********45` (first 2, last 2)

---

## 📧 Email Notifications

Powered by **Microsoft Graph API** (no SMTP required), the system sends:

1. **Violation Alerts** - Immediate notification to users
   - Violation count tracker
   - Redacted content sample
   - Security best practices
   - Next steps guidance

2. **Socialization Invitations** - Mandatory training after 3rd/5th violations
   - 60-minute self-paced course
   - 5 training modules
   - Certification required

3. **Admin Alerts** - Critical incident notifications
   - Full incident details
   - User history
   - Actions taken
   - Recommended follow-up

---

## 🎨 Web Dashboard

Beautiful, responsive web interface with:

- 📊 **Real-time Statistics** - Total incidents, active users, high-risk alerts
- 📈 **Trend Charts** - Monthly incident trends and violation type distribution
- 🔔 **Recent Activity** - Live incident feed with user details
- 👥 **User Rankings** - Violation count leaderboard
- ❤️ **Health Monitor** - System status and service availability

**Technology Stack:**
- FastAPI backend
- HTML/CSS with custom styling (dark theme)
- Chart.js for data visualization
- Responsive design for mobile/desktop

---

## 🔄 Integration Guide

### Azure Sentinel Integration

1. Create a Logic App workflow
2. Add Sentinel incident trigger
3. Configure HTTP POST action to `/remediate` endpoint
4. Map incident properties to request body

**Required Fields:**
```json
{
  "properties": {
    "title": "Incident title",
    "severity": "High",
    "relatedEntities": [
      {
        "kind": "Account",
        "properties": {
          "additionalData": {
            "UserPrincipalName": "user@company.com"
          }
        }
      }
    ]
  }
}
```

### Microsoft Purview DLP Integration

1. Create DLP policy in Microsoft 365 Compliance Center
2. Configure alert webhook to `/webhook/purview`
3. Set alert threshold and conditions

### Azure Event Grid Integration

1. Create Event Grid subscription
2. Point to `/webhook/eventgrid` endpoint
3. Handle subscription validation

---

## 🗄️ Database Schema

### `offenses` Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | Integer | Primary key |
| `user_principal_name` | String | User email (indexed) |
| `incident_title` | String | Violation description |
| `timestamp` | DateTime | UTC timestamp (indexed) |

**Indexes:** `user_principal_name`, `timestamp` for fast queries

---

## 🚢 Deployment

### Azure App Service (Recommended)

The project includes GitHub Actions workflow for CI/CD:

```yaml
# .github/workflows/main_dlp-engine.yml
- Automatic deployment on push to main branch
- Uses Azure Web App deployment action
- OpenID Connect authentication
```

**Manual Deployment:**

1. **Create Azure Web App**
   ```bash
   az webapp up --name dlp-engine --runtime "PYTHON:3.11"
   ```

2. **Configure App Settings**
   - Add all environment variables from `.env`
   - Enable HTTPS only
   - Set startup command: `gunicorn app.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000`

3. **Deploy Code**
   ```bash
   git push azure main
   ```

4. **Verify Deployment**
   ```bash
   curl https://dlp-engine.azurewebsites.net/health
   ```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
CMD ["gunicorn", "app.main:app", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]
```

---

## 🧪 Testing

### Run Tests
```bash
# Verify project structure
python test.py

# Test database connection
python test_db.py

# Verify imports
python verify_imports.py
```

### Test Endpoints
```bash
# Health check
curl http://localhost:8000/health

# Test email validation
curl -X POST http://localhost:8000/check-email \
  -H "Content-Type: application/json" \
  -d '{"sender": "test@example.com", "content": "KTP: 1234567890123456"}'
```

---

## 📊 Monitoring & Logging

### Application Insights Integration

The system logs to:
- **Access logs**: `/home/site/wwwroot/logs/access.log`
- **Error logs**: `/home/site/wwwroot/logs/error.log`

### Key Metrics to Monitor

- Response times (target: <500ms)
- Error rates (target: <1%)
- Database connection pool usage
- Email delivery success rate
- Account revocation success rate

---

## 🔧 Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | ✅ Yes | PostgreSQL connection string |
| `TENANT_ID` | ✅ Yes | Azure AD tenant ID |
| `BOT_CLIENT_ID` | ✅ Yes | Azure AD app client ID |
| `BOT_CLIENT_SECRET` | ✅ Yes | Azure AD client secret |
| `SENDER_EMAIL` | ✅ Yes | Email sender address |
| `ADMIN_EMAIL` | ⚠️ Optional | Admin notification email (default: admin@company.com) |

### Customization

**Adjust Risk Scoring:**
```python
# app/decision_engine.py
severity_map = {'Low': 20, 'Medium': 50, 'High': 80}
department_multipliers = {'Finance': 1.5, 'HR': 1.2, 'IT': 1.0}
```

**Modify Detection Patterns:**
```python
# app/main.py - SensitiveDataDetector class
@staticmethod
def detect_custom_pattern(text: str) -> List[str]:
    pattern = r'YOUR_REGEX_PATTERN'
    return re.findall(pattern, text)
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

**Coding Standards:**
- Follow PEP 8 style guide
- Add docstrings to all functions
- Include type hints
- Write unit tests for new features

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Authors

- **Project Lead** - Security Engineering Team
- **Contributors** - See [CONTRIBUTORS.md](CONTRIBUTORS.md)

---

## 🙏 Acknowledgments

- Microsoft Azure Security Team
- FastAPI Framework
- SQLAlchemy ORM
- Chart.js for visualizations
- Open-source community

---

## 📞 Support

For issues, questions, or feature requests:

- 📧 Email: security-team@yourcompany.com
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/dlp-engine/issues)
- 📚 Documentation: [Wiki](https://github.com/yourusername/dlp-engine/wiki)

---

## 🗺️ Roadmap

### Version 2.1 (Q2 2025)
- [ ] Machine learning-based anomaly detection
- [ ] Multi-language support (Indonesian/English)
- [ ] Slack/Teams bot integration
- [ ] Advanced reporting and analytics

### Version 3.0 (Q4 2025)
- [ ] Multi-tenant support
- [ ] Custom rule builder UI
- [ ] Mobile app for administrators
- [ ] Integration with SIEM platforms

---

## ⚠️ Security Notice

This system handles sensitive security data. Please ensure:

- All communications use HTTPS/TLS
- Environment variables are stored securely (Azure Key Vault recommended)
- Database connections use SSL/TLS
- Regular security audits are conducted
- Access logs are monitored
- Follow principle of least privilege for service accounts

---

## 📖 Additional Resources

- [Azure Sentinel Documentation](https://docs.microsoft.com/en-us/azure/sentinel/)
- [Microsoft Purview DLP Guide](https://docs.microsoft.com/en-us/microsoft-365/compliance/dlp-learn-about-dlp)
- [Microsoft Graph API Reference](https://docs.microsoft.com/en-us/graph/overview)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---

<div align="center">

**Built with ❤️ for enterprise security**

[⬆ Back to Top](#️-dlp-remediation-engine)

</div>
