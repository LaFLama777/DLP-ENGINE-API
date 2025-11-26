"""
Custom Middleware for DLP Engine

Provides request tracking, logging, and error handling.

Usage:
    from middleware import RequestIDMiddleware, LoggingMiddleware

    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(LoggingMiddleware)
"""

import uuid
import time
import logging
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Add unique request ID to each request for tracking

    The request ID is:
    - Stored in request.state.request_id
    - Added to response headers as X-Request-ID
    - Useful for correlating logs and debugging
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable
    ) -> Response:
        """Process request and add request ID"""

        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # Process request
        response = await call_next(request)

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Log all HTTP requests and responses

    Logs:
    - Request method and path
    - Request ID
    - Response status code
    - Processing time
    - Client IP
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable
    ) -> Response:
        """Process and log request"""

        # Get request ID (if RequestIDMiddleware is installed)
        request_id = getattr(request.state, 'request_id', 'unknown')

        # Get client IP
        client_ip = request.client.host if request.client else "unknown"

        # Start timer
        start_time = time.time()

        # Log incoming request
        logger.info(
            f"[{request_id}] {request.method} {request.url.path} - Client: {client_ip}"
        )

        # Process request
        try:
            response = await call_next(request)

            # Calculate processing time
            process_time = time.time() - start_time

            # Log response
            logger.info(
                f"[{request_id}] {request.method} {request.url.path} - "
                f"Status: {response.status_code} - Time: {process_time:.3f}s"
            )

            # Add processing time to headers
            response.headers["X-Process-Time"] = f"{process_time:.3f}"

            return response

        except Exception as e:
            # Calculate processing time even on error
            process_time = time.time() - start_time

            # Log error
            logger.error(
                f"[{request_id}] {request.method} {request.url.path} - "
                f"Error: {type(e).__name__} - Time: {process_time:.3f}s",
                exc_info=True
            )

            # Re-raise to let FastAPI handle it
            raise


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Limit request body size to prevent memory exhaustion

    Args:
        max_size: Maximum request body size in bytes (default: 10MB)
    """

    def __init__(self, app: ASGIApp, max_size: int = 10 * 1024 * 1024):
        """
        Initialize middleware

        Args:
            app: ASGI application
            max_size: Maximum request size in bytes (default 10MB)
        """
        super().__init__(app)
        self.max_size = max_size

    async def dispatch(
        self,
        request: Request,
        call_next: Callable
    ) -> Response:
        """Check request size and process"""

        # Check Content-Length header
        content_length = request.headers.get("content-length")

        if content_length:
            content_length = int(content_length)
            if content_length > self.max_size:
                logger.warning(
                    f"Request body too large: {content_length} bytes "
                    f"(max: {self.max_size} bytes)"
                )
                return Response(
                    content=f"Request body too large (max: {self.max_size} bytes)",
                    status_code=413
                )

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses

    Adds:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Strict-Transport-Security (if HTTPS)
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable
    ) -> Response:
        """Add security headers to response"""

        response = await call_next(request)

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Add HSTS if using HTTPS
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response


class CORSHeadersMiddleware(BaseHTTPMiddleware):
    """
    Custom CORS middleware with more control

    Args:
        allowed_origins: List of allowed origins (use ["*"] to allow all)
        allow_credentials: Whether to allow credentials
        max_age: Maximum age for preflight cache
    """

    def __init__(
        self,
        app: ASGIApp,
        allowed_origins: list[str] = ["*"],
        allow_credentials: bool = True,
        max_age: int = 600
    ):
        super().__init__(app)
        self.allowed_origins = allowed_origins
        self.allow_credentials = allow_credentials
        self.max_age = max_age

    async def dispatch(
        self,
        request: Request,
        call_next: Callable
    ) -> Response:
        """Handle CORS"""

        origin = request.headers.get("origin")

        # Process request
        response = await call_next(request)

        # Add CORS headers
        if origin:
            if "*" in self.allowed_origins or origin in self.allowed_origins:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Methods"] = (
                    "GET, POST, PUT, DELETE, OPTIONS"
                )
                response.headers["Access-Control-Allow-Headers"] = "*"

                if self.allow_credentials:
                    response.headers["Access-Control-Allow-Credentials"] = "true"

                response.headers["Access-Control-Max-Age"] = str(self.max_age)

        return response


if __name__ == "__main__":
    """Test middleware"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    print("="*60)
    print("Middleware - Test Cases")
    print("="*60)

    # Create test app
    app = FastAPI()

    # Add middleware
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/test")
    async def test_endpoint(request: Request):
        return {
            "message": "Test endpoint",
            "request_id": getattr(request.state, 'request_id', None)
        }

    client = TestClient(app)

    # Test 1: Request ID
    print("\n1. Testing Request ID Middleware...")
    response = client.get("/test")
    assert "X-Request-ID" in response.headers
    print(f"   ✅ Request ID: {response.headers['X-Request-ID']}")

    # Test 2: Processing Time
    print("\n2. Testing Logging Middleware...")
    response = client.get("/test")
    assert "X-Process-Time" in response.headers
    print(f"   ✅ Process Time: {response.headers['X-Process-Time']}s")

    # Test 3: Security Headers
    print("\n3. Testing Security Headers Middleware...")
    response = client.get("/test")
    assert "X-Content-Type-Options" in response.headers
    assert "X-Frame-Options" in response.headers
    print(f"   ✅ Security headers: X-Content-Type-Options, X-Frame-Options")

    # Test 4: Request in response
    print("\n4. Testing Request State...")
    response = client.get("/test")
    data = response.json()
    assert data["request_id"] is not None
    print(f"   ✅ Request ID accessible in endpoint: {data['request_id']}")

    print("\n" + "="*60)
    print("✅ All middleware tests passed!")
    print("="*60)
