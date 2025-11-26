"""
Configuration Management Module

Centralizes all application settings using Pydantic for validation.
Environment variables are loaded from .env file.

Usage:
    from config import settings

    if violation_count >= settings.CRITICAL_VIOLATION_THRESHOLD:
        revoke_account()
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import EmailStr, Field, field_validator, model_validator
from typing import List, Optional, Any
import os


class DLPSettings(BaseSettings):
    """
    DLP Remediation Engine Configuration

    All settings are loaded from environment variables.
    Missing required variables will cause startup failure.
    """

    # ========================================================================
    # VIOLATION THRESHOLDS
    # ========================================================================
    CRITICAL_VIOLATION_THRESHOLD: int = Field(
        default=3,
        description="Number of violations before account revocation"
    )
    WARNING_VIOLATION_THRESHOLD: int = Field(
        default=2,
        description="Number of violations before warning escalation"
    )
    SOCIALIZATION_THRESHOLDS: List[int] = Field(
        default=[3, 5],
        description="Violation counts that trigger mandatory training"
    )

    # ========================================================================
    # EMAIL SETTINGS
    # ========================================================================
    MAX_EMAILS_PER_HOUR: int = Field(
        default=10,
        description="Maximum emails to send per user per hour"
    )
    EMAIL_RATE_LIMIT_WINDOW_MINUTES: int = Field(
        default=60,
        description="Time window for email rate limiting"
    )

    # ========================================================================
    # AZURE AD / MICROSOFT GRAPH
    # ========================================================================
    TENANT_ID: str = Field(..., description="Azure AD Tenant ID")
    BOT_CLIENT_ID: str = Field(..., description="Azure AD Application (Client) ID")
    BOT_CLIENT_SECRET: str = Field(..., description="Azure AD Client Secret")

    @field_validator('TENANT_ID', 'BOT_CLIENT_ID', 'BOT_CLIENT_SECRET')
    @classmethod
    def azure_credentials_not_empty(cls, v, info):
        if not v or v.strip() == "":
            raise ValueError(f"{info.field_name} cannot be empty")
        return v.strip()

    # ========================================================================
    # EMAIL NOTIFICATION
    # ========================================================================
    SENDER_EMAIL: EmailStr = Field(..., description="Email address for DLP notifications")
    ADMIN_EMAIL: EmailStr = Field(..., description="Admin email for alerts")

    # ========================================================================
    # DATABASE
    # ========================================================================
    DATABASE_URL: Optional[str] = Field(
        default=None,
        description="PostgreSQL connection string"
    )

    # Fallback: individual Supabase components
    DB_USER: Optional[str] = Field(default=None, alias="user")
    DB_PASSWORD: Optional[str] = Field(default=None, alias="password")
    DB_HOST: Optional[str] = Field(default=None, alias="host")
    DB_PORT: str = Field(default="5432", alias="port")
    DB_NAME: Optional[str] = Field(default=None, alias="dbname")

    DATABASE_POOL_SIZE: int = Field(default=10, ge=1, le=50)
    DATABASE_MAX_OVERFLOW: int = Field(default=20, ge=0, le=100)
    DATABASE_POOL_TIMEOUT: int = Field(default=30, ge=5, le=300)

    @model_validator(mode='after')
    def build_database_url(self):
        """Build DATABASE_URL from components if not provided"""
        if self.DATABASE_URL:
            return self

        # Try to build from components
        user = self.DB_USER
        password = self.DB_PASSWORD
        host = self.DB_HOST
        port = self.DB_PORT or '5432'
        dbname = self.DB_NAME

        if all([user, password, host, dbname]):
            self.DATABASE_URL = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{dbname}?sslmode=require"
        else:
            # Fallback to SQLite for local development
            self.DATABASE_URL = "sqlite:///./dlp_offenses.db"

        return self

    # ========================================================================
    # CACHING
    # ========================================================================
    CACHE_ENABLED: bool = Field(default=True, description="Enable in-memory caching")
    USER_CACHE_TTL_MINUTES: int = Field(default=60, ge=5, le=1440)

    # ========================================================================
    # API SETTINGS
    # ========================================================================
    API_TITLE: str = Field(default="DLP Remediation Engine")
    API_VERSION: str = Field(default="2.0.0")
    API_DESCRIPTION: str = Field(
        default="Advanced DLP Decision Engine with Email Blocking & Compliance"
    )

    # CORS Settings
    CORS_ORIGINS: List[str] = Field(
        default=["*"],
        description="Allowed CORS origins (use specific domains in production)"
    )

    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = Field(default=True)
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, ge=1)

    # ========================================================================
    # LOGGING
    # ========================================================================
    LOG_LEVEL: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    LOG_FILE: str = Field(default="logs/dlp_engine.log")
    LOG_MAX_BYTES: int = Field(default=10_485_760, description="10MB")  # 10MB
    LOG_BACKUP_COUNT: int = Field(default=5, ge=1, le=20)
    LOG_JSON_FORMAT: bool = Field(default=True, description="Use JSON structured logging")

    # ========================================================================
    # FEATURE FLAGS
    # ========================================================================
    FEATURE_ACCOUNT_REVOCATION: bool = Field(default=True)
    FEATURE_EMAIL_NOTIFICATIONS: bool = Field(default=True)
    FEATURE_TEAMS_ALERTS: bool = Field(default=True)
    FEATURE_AUTO_REMEDIATION: bool = Field(default=True)

    # ========================================================================
    # PERFORMANCE
    # ========================================================================
    MAX_WORKERS: int = Field(default=4, ge=1, le=32)
    REQUEST_TIMEOUT_SECONDS: int = Field(default=120, ge=30, le=600)

    # Pydantic v2 configuration
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,  # Allow lowercase env vars
        populate_by_name=True,  # Allow alias names
        extra='ignore'  # Ignore extra fields
    )

    def get_database_config(self) -> dict:
        """Get database configuration for SQLAlchemy"""
        return {
            "pool_size": self.DATABASE_POOL_SIZE,
            "max_overflow": self.DATABASE_MAX_OVERFLOW,
            "pool_timeout": self.DATABASE_POOL_TIMEOUT,
            "pool_pre_ping": True
        }

    def is_production(self) -> bool:
        """Check if running in production environment"""
        return "sqlite" not in self.DATABASE_URL.lower()

    def validate_config(self) -> List[str]:
        """
        Validate configuration and return list of warnings

        Returns:
            List of warning messages (empty if all OK)
        """
        warnings = []

        if "*" in self.CORS_ORIGINS:
            warnings.append("CORS is set to allow all origins (*). This is insecure for production.")

        if not self.is_production() and self.FEATURE_ACCOUNT_REVOCATION:
            warnings.append("Account revocation is enabled with SQLite database (dev mode)")

        if self.MAX_EMAILS_PER_HOUR > 50:
            warnings.append(f"High email rate limit ({self.MAX_EMAILS_PER_HOUR}/hour) may trigger spam filters")

        return warnings


# Global settings instance
# This will be initialized on first import and cached
settings: DLPSettings = None

def get_settings() -> DLPSettings:
    """
    Get or create global settings instance

    Returns:
        DLPSettings: Validated application settings

    Raises:
        ValidationError: If required environment variables are missing
    """
    global settings
    if settings is None:
        settings = DLPSettings()
    return settings


# Initialize settings on import
try:
    settings = get_settings()
except Exception as e:
    # Allow module to be imported even if settings fail
    # (useful for testing or when .env is not yet configured)
    import sys
    print(f"WARNING: Failed to load settings: {e}", file=sys.stderr)
    print("Application may not function correctly until .env is configured", file=sys.stderr)


if __name__ == "__main__":
    """Test configuration loading"""
    print("="*60)
    print("DLP Engine Configuration Test")
    print("="*60)

    try:
        settings = get_settings()
        print("\n✅ Configuration loaded successfully!\n")

        print("Key Settings:")
        print(f"  - Environment: {'Production' if settings.is_production() else 'Development'}")
        print(f"  - Database: {settings.DATABASE_URL[:50]}...")
        print(f"  - Critical Threshold: {settings.CRITICAL_VIOLATION_THRESHOLD} violations")
        print(f"  - Email Rate Limit: {settings.MAX_EMAILS_PER_HOUR}/hour")
        print(f"  - Cache Enabled: {settings.CACHE_ENABLED}")
        print(f"  - Log Level: {settings.LOG_LEVEL}")

        # Check for warnings
        warnings = settings.validate_config()
        if warnings:
            print(f"\n⚠️  Configuration Warnings ({len(warnings)}):")
            for warning in warnings:
                print(f"  - {warning}")
        else:
            print("\n✅ No configuration warnings")

        print(f"\n{'='*60}")

    except Exception as e:
        print(f"\n❌ Configuration Error: {e}")
        print("\nMake sure .env file exists with all required variables:")
        print("  - TENANT_ID")
        print("  - BOT_CLIENT_ID")
        print("  - BOT_CLIENT_SECRET")
        print("  - SENDER_EMAIL")
        print("  - ADMIN_EMAIL")
        sys.exit(1)
