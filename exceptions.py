"""
Custom Exception Classes for DLP Engine

Provides consistent error handling across the application.

Usage:
    from exceptions import UserNotFoundException, DLPEngineException

    try:
        user = await get_user_details(upn)
        if not user:
            raise UserNotFoundException(f"User {upn} not found in Azure AD")
    except DLPEngineException as e:
        logger.error(f"DLP Error: {e}")
"""

from typing import Optional, Dict, Any


class DLPEngineException(Exception):
    """
    Base exception class for all DLP Engine errors

    All custom exceptions should inherit from this class.
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        original_exception: Optional[Exception] = None
    ):
        """
        Initialize DLP exception

        Args:
            message: Human-readable error message
            details: Additional context (optional)
            original_exception: Original exception if this is a wrapper (optional)
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.original_exception = original_exception

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses"""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "details": self.details
        }

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


# ============================================================================
# AZURE AD / GRAPH API EXCEPTIONS
# ============================================================================

class AzureADException(DLPEngineException):
    """Base exception for Azure AD related errors"""
    pass


class UserNotFoundException(AzureADException):
    """
    Raised when a user is not found in Azure AD

    Example:
        raise UserNotFoundException(
            f"User {upn} not found",
            details={"upn": upn, "tenant": tenant_id}
        )
    """
    pass


class GraphAPIException(AzureADException):
    """
    Raised when Microsoft Graph API call fails

    Example:
        raise GraphAPIException(
            "Failed to fetch user details",
            details={"upn": upn, "status_code": 500},
            original_exception=api_error
        )
    """
    pass


class AccountRevocationException(AzureADException):
    """
    Raised when account revocation fails

    Example:
        raise AccountRevocationException(
            f"Failed to revoke account for {upn}",
            details={"upn": upn, "step": "revoke_sessions"}
        )
    """
    pass


class AuthenticationException(AzureADException):
    """
    Raised when authentication to Azure AD fails

    Example:
        raise AuthenticationException(
            "Invalid credentials",
            details={"tenant_id": tenant_id}
        )
    """
    pass


# ============================================================================
# DATABASE EXCEPTIONS
# ============================================================================

class DatabaseException(DLPEngineException):
    """Base exception for database related errors"""
    pass


class DatabaseConnectionException(DatabaseException):
    """
    Raised when database connection fails

    Example:
        raise DatabaseConnectionException(
            "Cannot connect to PostgreSQL",
            details={"host": db_host, "port": db_port}
        )
    """
    pass


class OffenseLoggingException(DatabaseException):
    """
    Raised when logging an offense to database fails

    Example:
        raise OffenseLoggingException(
            f"Failed to log offense for {user_upn}",
            details={"user": user_upn, "incident": title},
            original_exception=db_error
        )
    """
    pass


class QueryException(DatabaseException):
    """
    Raised when a database query fails

    Example:
        raise QueryException(
            "Failed to fetch offense count",
            details={"query": "get_offense_count", "user": user_upn}
        )
    """
    pass


# ============================================================================
# EMAIL NOTIFICATION EXCEPTIONS
# ============================================================================

class EmailException(DLPEngineException):
    """Base exception for email related errors"""
    pass


class EmailSendException(EmailException):
    """
    Raised when sending email notification fails

    Example:
        raise EmailSendException(
            f"Failed to send email to {recipient}",
            details={"recipient": recipient, "error": "SMTP timeout"}
        )
    """
    pass


class EmailConfigurationException(EmailException):
    """
    Raised when email configuration is invalid

    Example:
        raise EmailConfigurationException(
            "Missing SENDER_EMAIL configuration",
            details={"missing_vars": ["SENDER_EMAIL", "ADMIN_EMAIL"]}
        )
    """
    pass


class EmailRateLimitException(EmailException):
    """
    Raised when email rate limit is exceeded

    Example:
        raise EmailRateLimitException(
            f"Rate limit exceeded for {user}",
            details={"user": user, "limit": 10, "window": "1 hour"}
        )
    """
    pass


# ============================================================================
# DATA VALIDATION EXCEPTIONS
# ============================================================================

class ValidationException(DLPEngineException):
    """Base exception for validation errors"""
    pass


class InvalidEmailFormatException(ValidationException):
    """
    Raised when email format is invalid

    Example:
        raise InvalidEmailFormatException(
            f"Invalid email: {email}",
            details={"email": email}
        )
    """
    pass


class InvalidPayloadException(ValidationException):
    """
    Raised when request payload is invalid

    Example:
        raise InvalidPayloadException(
            "Missing required field: user_upn",
            details={"missing_fields": ["user_upn"]}
        )
    """
    pass


class InvalidConfigurationException(ValidationException):
    """
    Raised when application configuration is invalid

    Example:
        raise InvalidConfigurationException(
            "CRITICAL_VIOLATION_THRESHOLD must be >= 1",
            details={"current_value": 0, "min_value": 1}
        )
    """
    pass


# ============================================================================
# BUSINESS LOGIC EXCEPTIONS
# ============================================================================

class BusinessLogicException(DLPEngineException):
    """Base exception for business logic errors"""
    pass


class SensitiveDataDetectedException(BusinessLogicException):
    """
    Raised when sensitive data is detected in content

    Example:
        raise SensitiveDataDetectedException(
            "KTP number found in email",
            details={"violation_types": ["KTP"], "count": 1}
        )
    """
    pass


class ViolationThresholdExceededException(BusinessLogicException):
    """
    Raised when violation threshold is exceeded

    Example:
        raise ViolationThresholdExceededException(
            f"User exceeded violation limit",
            details={"user": upn, "count": 5, "threshold": 3}
        )
    """
    pass


class IncidentParsingException(BusinessLogicException):
    """
    Raised when parsing Sentinel incident fails

    Example:
        raise IncidentParsingException(
            "Cannot extract user UPN from incident",
            details={"incident_id": incident_id}
        )
    """
    pass


# ============================================================================
# RISK ASSESSMENT EXCEPTIONS
# ============================================================================

class RiskAssessmentException(DLPEngineException):
    """Base exception for risk assessment errors"""
    pass


class InvalidRiskScoreException(RiskAssessmentException):
    """
    Raised when risk score calculation fails

    Example:
        raise InvalidRiskScoreException(
            "Risk score out of range",
            details={"score": 150, "valid_range": "0-100"}
        )
    """
    pass


class DecisionEngineException(RiskAssessmentException):
    """
    Raised when decision engine fails

    Example:
        raise DecisionEngineException(
            "Cannot determine remediation action",
            details={"score": score, "context": context}
        )
    """
    pass


# ============================================================================
# CACHE EXCEPTIONS
# ============================================================================

class CacheException(DLPEngineException):
    """Base exception for caching errors"""
    pass


class CacheConnectionException(CacheException):
    """
    Raised when cache connection fails

    Example:
        raise CacheConnectionException(
            "Cannot connect to Redis",
            details={"host": "localhost", "port": 6379}
        )
    """
    pass


class CacheKeyNotFoundException(CacheException):
    """
    Raised when cache key is not found

    Example:
        raise CacheKeyNotFoundException(
            f"Key not found: {key}",
            details={"key": key}
        )
    """
    pass


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def handle_exception(
    exception: Exception,
    logger,
    context: Optional[Dict[str, Any]] = None
) -> DLPEngineException:
    """
    Convert standard exceptions to DLPEngineException

    Args:
        exception: Original exception
        logger: Logger instance
        context: Additional context

    Returns:
        DLPEngineException: Wrapped exception

    Example:
        try:
            result = risky_operation()
        except Exception as e:
            dlp_exception = handle_exception(e, logger, {"operation": "risky_op"})
            raise dlp_exception
    """
    if isinstance(exception, DLPEngineException):
        return exception

    # Map common exceptions to DLP exceptions
    exception_map = {
        ValueError: ValidationException,
        KeyError: ValidationException,
        ConnectionError: DatabaseConnectionException,
        TimeoutError: DatabaseConnectionException,
    }

    exception_class = exception_map.get(type(exception), DLPEngineException)

    wrapped = exception_class(
        message=str(exception),
        details=context or {},
        original_exception=exception
    )

    logger.error(f"{wrapped.__class__.__name__}: {wrapped.message}", exc_info=True)

    return wrapped


if __name__ == "__main__":
    """Test exception handling"""
    import logging

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    print("="*60)
    print("Exception Handling - Test Cases")
    print("="*60)

    # Test 1: UserNotFoundException
    print("\n1. Testing UserNotFoundException...")
    try:
        raise UserNotFoundException(
            "User not found",
            details={"upn": "test@example.com", "tenant": "abc123"}
        )
    except DLPEngineException as e:
        print(f"   ✅ Caught: {e.__class__.__name__}")
        print(f"   Message: {e.message}")
        print(f"   Details: {e.details}")

    # Test 2: EmailSendException with original exception
    print("\n2. Testing EmailSendException with original...")
    try:
        try:
            raise ConnectionError("SMTP server unreachable")
        except ConnectionError as original:
            raise EmailSendException(
                "Failed to send notification",
                details={"recipient": "user@example.com"},
                original_exception=original
            )
    except DLPEngineException as e:
        print(f"   ✅ Caught: {e.__class__.__name__}")
        print(f"   Original: {e.original_exception}")

    # Test 3: to_dict() method
    print("\n3. Testing to_dict() serialization...")
    exc = DatabaseException(
        "Connection failed",
        details={"host": "localhost", "port": 5432}
    )
    exc_dict = exc.to_dict()
    print(f"   ✅ Serialized: {exc_dict}")

    # Test 4: handle_exception helper
    print("\n4. Testing handle_exception helper...")
    try:
        raise ValueError("Invalid input")
    except Exception as e:
        wrapped = handle_exception(e, logger, {"field": "user_upn"})
        print(f"   ✅ Wrapped as: {wrapped.__class__.__name__}")
        print(f"   Details: {wrapped.details}")

    print("\n" + "="*60)
    print("✅ All exception tests passed!")
    print("="*60)
