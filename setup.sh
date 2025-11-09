#!/bin/bash

# PyTeal-Checker Setup Script
# Automates installation and configuration

set -e

echo "================================"
echo "PyTeal-Checker Setup"
echo "================================"
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $python_version"

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo ""
echo "Installing dependencies..."
cd PyTealChecker
pip install -r requirements.txt

# Run migrations
echo ""
echo "Running database migrations..."
python manage.py migrate

# Collect static files
echo ""
echo "Collecting static files..."
python manage.py collectstatic --noinput || true

# Run tests
echo ""
echo "Running tests..."
python manage.py test mainapp --verbosity=2

echo ""
echo "================================"
echo "Setup Complete!"
echo "================================"
echo ""
echo "To start the development server:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Navigate to project: cd PyTealChecker"
echo "  3. Run server: python manage.py runserver"
echo ""
echo "Then visit: http://localhost:8000"
echo ""
echo "API Endpoints:"
echo "  - POST /api/analyze - Analyze PyTeal contracts"
echo "  - GET  /api/health - Health check"
echo "  - GET  /api/features - List analyzed features"
echo ""
