# DLP Remediation Engine

An automated Data Loss Prevention system that integrates with Microsoft Sentinel and Purview to detect and respond to sensitive data violations in real-time.

## What it does

This system monitors your organization for data leakage and automatically takes action when violations occur:

- Detects sensitive data patterns (government IDs, employee numbers, etc.)
- Calculates risk scores based on user behavior and violation history
- Sends notifications to violators and administrators
- Can automatically revoke sessions or block accounts for serious violations
- Provides a web dashboard for monitoring and incident management

## Requirements

- Python 3.11 or higher
- Azure App Registration with Microsoft Graph API permissions
- PostgreSQL database (or SQLite for local development)
- Optional: Microsoft Sentinel or Purview for automatic incident ingestion

## Getting Started

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment variables**

   Copy `.env.example` to `.env` and fill in your values:
   ```bash
   cp .env.example .env
   ```

   Required settings:
   - `TENANT_ID` - Your Azure AD tenant ID
   - `BOT_CLIENT_ID` - Application (client) ID from Azure App Registration
   - `BOT_CLIENT_SECRET` - Client secret value
   - `SENDER_EMAIL` - Email address for sending notifications
   - `ADMIN_EMAIL` - Email address for admin alerts

3. **Run locally**
   ```bash
   uvicorn app.main:app --reload
   ```

   Then open http://localhost:8000 in your browser.

## Key Endpoints

- `GET /` - Web dashboard with statistics and incident list
- `GET /health` - Health check endpoint
- `POST /api/remediate` - Receive incidents from Sentinel playbooks
- `POST /webhook/purview` - Receive alerts from Purview DLP policies
- `POST /check-email` - Validate email content for sensitive data
- `GET /docs` - Interactive API documentation (Swagger UI)

## Architecture

The system consists of several components:

- **FastAPI Server** - Main application handling webhooks and API requests
- **Database Layer** - Tracks violations and offense history
- **Decision Engine** - Calculates risk scores and determines appropriate actions
- **Notification Service** - Sends emails via Microsoft Graph API
- **Graph Client** - Manages user account operations (session revocation, blocking)

## Deployment

For Azure deployment, see `Md/DEPLOYMENT_GUIDE.md`.

The application is configured for Azure App Service with:
- GitHub Actions CI/CD pipeline (`.github/workflows/main_dlp-engine.yml`)
- Automatic deployment on push to main branch
- Environment variables managed in Azure portal

## Integration

### Microsoft Sentinel

Use the included playbook template (`sentinel-playbook-fixed.json`) to automatically send DLP incidents to the `/api/remediate` endpoint.

### Microsoft Purview

Configure webhook alerts to point to `/webhook/purview` for automatic processing of DLP policy violations.

### Power Automate / Logic Apps

See `Md/POWER_AUTOMATE_SETUP.md` for integrating with custom workflows.

## Documentation

Additional documentation is available in the `Md/` folder:

- `DEPLOYMENT_GUIDE.md` - Detailed Azure deployment instructions
- `SENTINEL_INTEGRATION.md` - Setting up Sentinel playbooks
- `AZURE_PERMISSIONS.md` - Required Graph API permissions
- `REVOCATION_FEATURE.md` - Account revocation feature details
- `PROJECT_STRUCTURE_GUIDE.md` - Code organization and architecture

## Development

The codebase uses:
- **FastAPI** for the web framework
- **SQLAlchemy** for database ORM
- **Pydantic** for data validation and settings management
- **Microsoft Graph SDK** for Azure AD and email operations

Main modules:
- `app/main.py` - Application entry point and route definitions
- `config.py` - Centralized configuration management
- `database.py` - Database models and session management
- `email_notifications.py` - Email and Graph API operations
- `sensitive_data.py` - Pattern detection for sensitive content
- `app/decision_engine.py` - Risk assessment logic

## Notes

- The system uses PostgreSQL in production (via Supabase) but falls back to SQLite for local development
- Email notifications require proper Graph API permissions (Mail.Send, User.Read.All, etc.)
- Account revocation features require User.ReadWrite.All permission
- The dashboard uses Chart.js for visualizations

## License

Proprietary - Internal Use Only
