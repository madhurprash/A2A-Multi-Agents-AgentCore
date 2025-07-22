#!/usr/bin/env python3
"""
AWS OpenTelemetry instrumented runner for monitoring agent
Based on AWS Bedrock AgentCore Strands observability patterns
"""

import os
import subprocess
import sys
import argparse
from pathlib import Path
from dotenv import load_dotenv

# Get the directory of this script
script_dir = Path(__file__).parent.absolute()

def setup_observability_env():
    """Load observability environment variables using dotenv"""
    env_file = script_dir / ".env.observability"
    
    if not env_file.exists():
        print(f"⚠️ Observability config file not found: {env_file}")
        print("Run without observability or create .env.observability file")
        return {}
    
    try:
        # Load environment variables using dotenv 
        load_dotenv(env_file)
        print(f"✅ Loaded observability configuration from {env_file}")
        
        # Display key OTEL configuration
        otel_vars = [
            "OTEL_PYTHON_DISTRO",
            "OTEL_PYTHON_CONFIGURATOR", 
            "OTEL_RESOURCE_ATTRIBUTES",
            "ENABLE_OBSERVABILITY"
        ]
        
        print("\\nOpenTelemetry Configuration:")
        for var in otel_vars:
            value = os.getenv(var)
            if value:
                print(f"  {var}={value}")
                
        return dict(os.environ)
        
    except Exception as e:
        print(f"❌ Error loading observability config: {e}")
        return {}

def run_with_observability(agent_file):
    """Run the specified agent with AWS OpenTelemetry auto-instrumentation"""
    
    # Setup environment variables  
    setup_observability_env()
    
    # Check if observability is enabled
    enable_obs = os.getenv('ENABLE_OBSERVABILITY', 'true').lower() == 'true'
    
    if not enable_obs:
        print(f"🔄 Observability disabled, running {agent_file} normally...")
        cmd = [sys.executable, agent_file]
    else:
        print(f"🚀 Running {agent_file} with AWS OpenTelemetry auto-instrumentation...")
        print("   This will automatically capture traces from Strands agent, Bedrock calls, and AWS SDK operations")
        cmd = [
            "opentelemetry-instrument", 
            sys.executable, 
            agent_file
        ]
    
    try:
        # Run the command in the monitoring agent directory
        print(f"\\nExecuting: {' '.join(cmd)}")
        print("-" * 60)
        
        result = subprocess.run(
            cmd,
            cwd=script_dir,
            check=False  # Don't raise exception on non-zero exit
        )
        return result.returncode
        
    except FileNotFoundError as e:
        if "opentelemetry-instrument" in str(e):
            print("❌ opentelemetry-instrument not found!")
            print("\\nInstall observability requirements:")
            print(f"  pip install -r {script_dir}/requirements-observability.txt")
            print("\\nOr run without observability:")
            print(f"  python {agent_file}")
            return 1
        else:
            print(f"❌ Error running command: {e}")
            return 1
    except KeyboardInterrupt:
        print("\\n👋 Interrupted by user")
        return 130

def main():
    parser = argparse.ArgumentParser(description="Run agent with AWS OpenTelemetry observability")
    parser.add_argument(
        "agent_file", 
        nargs="?", 
        default="monitoring_agent.py",
        help="Agent Python file to run (default: monitoring_agent.py)"
    )
    
    args = parser.parse_args()
    
    # Check if the agent file exists
    agent_path = script_dir / args.agent_file
    if not agent_path.exists():
        print(f"❌ Agent file not found: {agent_path}")
        return 1
    
    return run_with_observability(args.agent_file)

if __name__ == "__main__":
    sys.exit(main())