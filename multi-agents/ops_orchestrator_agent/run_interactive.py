#!/usr/bin/env python3
"""
Simple launcher script for the Ops Orchestrator Interactive CLI
"""

import os
import sys
import asyncio

# Disable OpenAI tracing to prevent errors
os.environ["OPENAI_ENABLE_TRACING"] = "false"
os.environ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] = ""

def main():
    """Launch the interactive ops orchestrator"""
    print("🚀 Starting Ops Orchestrator Interactive CLI...")
    
    try:
        # Import the main module
        from ops_orchestrator_multi_agent import interactive_cli
        
        # Run the interactive CLI
        asyncio.run(interactive_cli())
        
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure all dependencies are installed and you're in the correct directory.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error starting interactive CLI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()