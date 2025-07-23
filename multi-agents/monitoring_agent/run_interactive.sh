#!/bin/bash
# Interactive Monitoring Agent Runner Script

echo "🚀 Starting Interactive Monitoring Agent..."
echo "Setting up environment..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install requirements if they don't exist
echo "📋 Installing requirements..."
pip install -r requirements.txt

# Set environment variables if needed
export PYTHONPATH="$(pwd):$PYTHONPATH"

# Run the interactive agent
echo "🔍 Starting Interactive Monitoring Agent..."
python3 interactive_agent.py