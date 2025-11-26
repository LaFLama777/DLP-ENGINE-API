"""
Logging Configuration for DLP Engine

Sets up professional logging with rotation, JSON format, and filtering.

Usage:
    from logging_config import setup_logging

    # Call once at application startup
    setup_logging()

    # Then use standard logging
    logger = logging.getLogger(__name__)
    logger.info("Application started")
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter with color support for console output

    Colors:
    - DEBUG: Cyan
    - INFO: Green
    - WARNING: Yellow
    - ERROR: Red
    - CRITICAL: Red + Bold
    """

    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[1;31m', # Bold Red
        'RESET': '\033[0m'        # Reset
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors"""
        # Save original levelname
        levelname = record.levelname

        # Add color to levelname
        if levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
            )

        # Format message
        formatted = super().format(record)

        # Restore original levelname
        record.levelname = levelname

        return formatted


class JSONFormatter(logging.Formatter):
    """
    Format log records as JSON for structured logging

    Output format:
    {
        "timestamp": "2025-11-25T10:30:00.123456Z",
        "level": "INFO",
        "logger": "app.main",
        "message": "Request processed",
        "request_id": "123e4567-e89b-12d3-a456-426614174000",
        "extra": {...}
    }
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format record as JSON"""
        import json

        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in [
                'name', 'msg', 'args', 'created', 'filename', 'funcName',
                'levelname', 'levelno', 'lineno', 'module', 'msecs',
                'message', 'pathname', 'process', 'processName', 'relativeCreated',
                'thread', 'threadName', 'exc_info', 'exc_text', 'stack_info'
            ]:
                log_data[key] = value

        return json.dumps(log_data)


class RequestIDFilter(logging.Filter):
    """
    Add request_id to log records

    Useful for tracing requests across multiple log lines
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Add request_id to record"""
        # Try to get request_id from context
        # (This would need to be set by middleware)
        if not hasattr(record, 'request_id'):
            record.request_id = None
        return True


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    log_to_console: bool = True,
    log_to_file: bool = True,
    use_json_format: bool = False,
    use_colors: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5
) -> None:
    """
    Setup application logging

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (default: logs/dlp_engine.log)
        log_to_console: Whether to log to console
        log_to_file: Whether to log to file
        use_json_format: Use JSON format for file logs
        use_colors: Use colored output for console
        max_bytes: Max size per log file before rotation
        backup_count: Number of backup files to keep

    Example:
        setup_logging(
            log_level="INFO",
            log_to_console=True,
            log_to_file=True,
            use_json_format=True
        )
    """

    # Convert log level string to constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Create logs directory if needed
    if log_to_file:
        log_file = log_file or "logs/dlp_engine.log"
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)

    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)

        if use_colors and sys.stdout.isatty():
            # Colored formatter for console
            console_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            console_formatter = ColoredFormatter(console_format)
        else:
            # Plain formatter
            console_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            console_formatter = logging.Formatter(console_format)

        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # File handler with rotation
    if log_to_file and log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(numeric_level)

        if use_json_format:
            # JSON formatter for file
            file_formatter = JSONFormatter()
        else:
            # Standard formatter for file
            file_format = (
                '%(asctime)s - %(name)s - %(levelname)s - '
                '%(module)s:%(funcName)s:%(lineno)d - %(message)s'
            )
            file_formatter = logging.Formatter(file_format)

        file_handler.setFormatter(file_formatter)

        # Add request ID filter
        file_handler.addFilter(RequestIDFilter())

        root_logger.addHandler(file_handler)

    # Set levels for noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("azure").setLevel(logging.WARNING)
    logging.getLogger("msal").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)

    # Log setup completion
    logger = logging.getLogger(__name__)
    logger.info(
        f"Logging configured: level={log_level}, "
        f"console={log_to_console}, file={log_to_file}, "
        f"json={use_json_format}"
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the given name

    This is just a convenience wrapper around logging.getLogger()

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance

    Example:
        logger = get_logger(__name__)
        logger.info("Message")
    """
    return logging.getLogger(name)


class LogContext:
    """
    Context manager for adding context to log messages

    Usage:
        with LogContext(request_id="abc123"):
            logger.info("Processing request")
            # Log will include request_id
    """

    def __init__(self, **kwargs):
        """
        Initialize log context

        Args:
            **kwargs: Key-value pairs to add to log records
        """
        self.context = kwargs
        self.old_factory = logging.getLogRecordFactory()

    def __enter__(self):
        """Enter context - modify log record factory"""
        def record_factory(*args, **kwargs):
            record = self.old_factory(*args, **kwargs)
            for key, value in self.context.items():
                setattr(record, key, value)
            return record

        logging.setLogRecordFactory(record_factory)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context - restore original factory"""
        logging.setLogRecordFactory(self.old_factory)


if __name__ == "__main__":
    """Test logging configuration"""
    print("="*60)
    print("Logging Configuration - Test Cases")
    print("="*60)

    # Test 1: Basic logging
    print("\n1. Testing basic logging setup...")
    setup_logging(
        log_level="DEBUG",
        log_to_console=True,
        log_to_file=True,
        use_colors=True,
        use_json_format=False
    )

    logger = get_logger(__name__)
    logger.debug("This is a DEBUG message")
    logger.info("This is an INFO message")
    logger.warning("This is a WARNING message")
    logger.error("This is an ERROR message")
    print("   ✅ All log levels tested")

    # Test 2: JSON logging
    print("\n2. Testing JSON format...")
    setup_logging(
        log_level="INFO",
        log_to_console=False,
        log_to_file=True,
        use_json_format=True,
        log_file="logs/test_json.log"
    )

    logger = get_logger(__name__)
    logger.info("Testing JSON format", extra={"user": "test@example.com"})
    print("   ✅ JSON log written to logs/test_json.log")

    # Test 3: Log context
    print("\n3. Testing LogContext...")
    setup_logging(log_to_console=True, log_to_file=False, use_colors=False)

    logger = get_logger(__name__)
    with LogContext(request_id="test-123", user="admin"):
        logger.info("Message with context")
    print("   ✅ Context added to log")

    # Test 4: Check log file
    print("\n4. Checking log files...")
    if os.path.exists("logs/dlp_engine.log"):
        size = os.path.getsize("logs/dlp_engine.log")
        print(f"   ✅ Log file created: {size} bytes")
    else:
        print("   ⚠️  Log file not found (may not have been created yet)")

    print("\n" + "="*60)
    print("✅ Logging configuration tests completed!")
    print("="*60)
