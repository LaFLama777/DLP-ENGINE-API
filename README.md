# DLP Remediation Engine

**Version**: 2.0.0
**Status**: Production Ready

## Overview

Enterprise Data Loss Prevention (DLP) remediation engine with automated incident response and risk assessment capabilities.

## Features

- ✅ Real-time sensitive data detection
- ✅ Automated risk assessment
- ✅ Microsoft Graph API integration
- ✅ Email notification system
- ✅ Account revocation workflows
- ✅ Compliance logging and audit trails

## Tech Stack

- **Framework**: FastAPI 0.109.0
- **Language**: Python 3.11+
- **Database**: PostgreSQL / SQLite
- **Cloud**: Azure App Service
- **API**: Microsoft Graph SDK

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env  # Edit with your values

# Run locally
uvicorn app.main:app --reload
```

## Documentation

Detailed documentation is available locally in the `Md/` folder:
- `DEPLOYMENT_GUIDE.md` - Deployment instructions
- `PROJECT_STRUCTURE_GUIDE.md` - Architecture overview
- `CODE_ANALYSIS_REPORT.md` - Code quality report

## API Endpoints

- `GET /health` - Health check
- `POST /check-email` - Email content analysis
- `POST /remediate` - Incident remediation
- `GET /docs` - Interactive API documentation

## Environment Variables

Required configuration (see `.env.example`):
- `TENANT_ID` - Azure AD Tenant ID
- `BOT_CLIENT_ID` - Application Client ID
- `BOT_CLIENT_SECRET` - Client Secret
- `SENDER_EMAIL` - DLP notification email
- `ADMIN_EMAIL` - Administrator email
- `DATABASE_URL` - Database connection string

## License

Proprietary - Internal Use Only

## Support

For issues or questions, contact the security team.
