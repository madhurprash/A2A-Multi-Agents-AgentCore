#!/usr/bin/env python3
"""
Quick launcher for the AgentCore Monitoring Demo
This script helps users easily launch the Streamlit demo application.
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s | %(name)s | %(message)s"
)
logger = logging.getLogger(__name__)

def check_requirements():
    """Check if required packages are installed"""
    required_packages = [
        'streamlit',
        'plotly', 
        'pandas',
        'numpy',
        'boto3',
        'pyyaml'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    return missing_packages

def install_requirements():
    """Install missing requirements"""
    requirements_file = Path(__file__).parent / "requirements_streamlit.txt"
    
    if requirements_file.exists():
        logger.info("Installing required packages...")
        try:
            subprocess.run([
                sys.executable, "-m", "pip", "install", 
                "-r", str(requirements_file)
            ], check=True)
            logger.info("✅ Requirements installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to install requirements: {e}")
            return False
    else:
        logger.warning(f"Requirements file not found: {requirements_file}")
        return False

def launch_streamlit():
    """Launch the Streamlit application"""
    app_file = Path(__file__).parent / "enhanced_streamlit_app.py"
    
    if not app_file.exists():
        logger.error(f"❌ Application file not found: {app_file}")
        return False
    
    try:
        logger.info("🚀 Launching AgentCore Monitoring Demo...")
        logger.info(f"📱 The app will open in your browser shortly...")
        logger.info(f"🌐 If it doesn't open automatically, visit: http://localhost:8501")
        
        # Launch streamlit with optimized settings
        subprocess.run([
            "streamlit", "run", str(app_file),
            "--server.port=8501",
            "--server.address=localhost",
            "--server.headless=false",
            "--browser.serverAddress=localhost",
            "--browser.gatherUsageStats=false",
            "--theme.primaryColor=#FF9900",
            "--theme.backgroundColor=#FFFFFF",
            "--theme.secondaryBackgroundColor=#F0F2F6"
        ])
        
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Failed to launch Streamlit: {e}")
        return False
    except KeyboardInterrupt:
        logger.info("\n👋 Demo stopped by user")
        return True

def main():
    """Main launcher function"""
    print("🔍 AgentCore AWS Monitoring Demo Launcher")
    print("=" * 50)
    
    # Check if we're in the right directory
    current_dir = Path.cwd()
    expected_files = ['enhanced_streamlit_app.py', 'monitoring_agent.py', 'agent_runtime.py']
    missing_files = [f for f in expected_files if not (current_dir / f).exists()]
    
    if missing_files:
        logger.warning(f"⚠️  Some files not found in current directory: {missing_files}")
        logger.info(f"Current directory: {current_dir}")
        logger.info("Make sure you're running this from the monitoring_agent directory")
    
    # Check requirements
    logger.info("📦 Checking required packages...")
    missing = check_requirements()
    
    if missing:
        logger.warning(f"⚠️  Missing packages: {', '.join(missing)}")
        
        # Ask user if they want to install
        try:
            response = input("📥 Would you like to install missing packages? (y/N): ").lower().strip()
            if response in ('y', 'yes'):
                if not install_requirements():
                    logger.error("❌ Failed to install requirements. Please install manually:")
                    logger.error(f"   pip install -r requirements_streamlit.txt")
                    return 1
            else:
                logger.info("📋 Please install requirements manually before running:")
                logger.info(f"   pip install -r requirements_streamlit.txt")
                return 1
        except KeyboardInterrupt:
            logger.info("\n👋 Setup cancelled by user")
            return 1
    else:
        logger.info("✅ All required packages are installed")
    
    # Launch the application
    logger.info("\n🎬 Starting AgentCore Monitoring Demo...")
    
    # Display helpful information
    print("\n" + "=" * 50)
    print("🤖 AGENTCORE MONITORING DEMO")
    print("=" * 50)
    print("📊 Features included:")
    print("  • Interactive AWS troubleshooting workflow")
    print("  • Real agent invocation with streaming responses")
    print("  • Pain point analysis and solution demonstration") 
    print("  • AgentCore primitives integration showcase")
    print("  • Live chat interface with intelligent responses")
    print("  • Performance monitoring dashboard")
    print("\n💡 Tips:")
    print("  • Select an agent from the sidebar to start")
    print("  • Try the suggested queries for best experience")
    print("  • Toggle between Demo and Live modes")
    print("  • Export your chat sessions for analysis")
    print("=" * 50)
    
    success = launch_streamlit()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())