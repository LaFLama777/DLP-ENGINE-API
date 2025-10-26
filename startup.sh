#!/bin/bash

# Azure Web App Startup Script for DLP Remediation Engine
# This script is executed when the container starts

echo "=================================================="
echo "Starting DLP Remediation Engine"
echo "=================================================="

# Set Python path
export PYTHONPATH="${PYTHONPATH}:/home/site/wwwroot"
echo "PYTHONPATH set to: $PYTHONPATH"

# Create logs directory if it doesn't exist
mkdir -p /home/site/wwwroot/logs
echo "Logs directory created"

# Check Python version
python --version

# List installed packages (for debugging)
echo "Installed packages:"
pip list | head -20

# Start Gunicorn with Uvicorn workers
echo "Starting Gunicorn..."
gunicorn app.main:app \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --timeout 120 \
    --access-logfile /home/site/wwwroot/logs/access.log \
    --error-logfile /home/site/wwwroot/logs/error.log \
    --log-level info \
    --preload