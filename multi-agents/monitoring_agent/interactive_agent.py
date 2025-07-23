#!/usr/bin/env python3
"""
Interactive CLI for the Monitoring Agent
This provides a local interactive interface for the monitoring agent.
"""

import sys
import os
import json
import logging
from typing import Optional
from pathlib import Path

# Add current directory to path so we can import the monitoring agent
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the monitoring agent components
from monitoring_agent import agent, config_data, logger

def print_banner():
    """Print welcome banner"""
    print("\n" + "="*60)
    print("🔍 AWS Monitoring Agent - Interactive CLI")
    print("="*60)
    print("Type your monitoring questions or commands below.")
    print("Available commands:")
    print("  • /help    - Show this help message")
    print("  • /status  - Show agent status")
    print("  • /config  - Show current configuration")
    print("  • /quit    - Exit the interactive mode")
    print("  • /clear   - Clear the screen")
    print("-" * 60)
    print()

def show_agent_status():
    """Show current agent status"""
    print("\n📊 Agent Status:")
    print("-" * 30)
    
    # Show model info
    model_info = config_data['agent_information']['monitoring_agent_model_info']
    print(f"Model ID: {model_info['model_id']}")
    print(f"Temperature: {model_info['inference_parameters']['temperature']}")
    print(f"Max Tokens: {model_info['inference_parameters']['max_tokens']}")
    
    # Show gateway status
    gateway_config = model_info.get('gateway_config', {})
    print(f"Gateway Name: {gateway_config.get('name', 'N/A')}")
    
    # Show memory status
    if model_info.get('use_existing_memory'):
        memory_id = model_info.get('memory_credentials', {}).get('id', 'N/A')
        print(f"Memory ID: {memory_id}")
    else:
        print("Memory: Creating new memory")
    
    print(f"Agent Tools: {len(agent.tools) if hasattr(agent, 'tools') else 'Unknown'} available")
    print()

def show_config():
    """Show current configuration (sanitized)"""
    print("\n⚙️ Configuration:")
    print("-" * 30)
    
    # Show sanitized config (remove sensitive info)
    sanitized_config = {
        "name": config_data.get('general', {}).get('name'),
        "description": config_data.get('general', {}).get('description'),
        "model_id": config_data['agent_information']['monitoring_agent_model_info']['model_id'],
        "gateway_name": config_data['agent_information']['monitoring_agent_model_info']['gateway_config']['name']
    }
    
    print(json.dumps(sanitized_config, indent=2))
    print()

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def process_command(user_input: str) -> bool:
    """
    Process special commands. Returns True if command was processed, False if it's a regular query.
    """
    command = user_input.strip().lower()
    
    if command == '/help':
        print_banner()
        return True
    elif command == '/status':
        show_agent_status()
        return True
    elif command == '/config':
        show_config()
        return True
    elif command in ['/quit', '/exit', 'quit', 'exit']:
        print("\n👋 Goodbye! Thanks for using the Monitoring Agent.")
        return 'quit'
    elif command == '/clear':
        clear_screen()
        print_banner()
        return True
    
    return False

def query_agent(user_input: str) -> str:
    """
    Query the monitoring agent with user input
    """
    try:
        response = agent(user_input)
        if hasattr(response, 'message') and 'content' in response.message:
            return response.message['content'][0]['text']
        else:
            return str(response)
    except Exception as e:
        logger.error(f"Agent query error: {e}")
        return f"❌ Error: {str(e)}"

def main():
    """Main interactive loop"""
    print_banner()
    
    try:
        print("✅ Monitoring agent initialized successfully!")
        print("💡 Try asking: 'What CloudWatch metrics can you help me monitor?'")
        print()
        
        while True:
            try:
                # Get user input
                user_input = input("🔍 Monitor> ").strip()
                
                if not user_input:
                    continue
                
                # Process commands
                cmd_result = process_command(user_input)
                if cmd_result == 'quit':
                    break
                elif cmd_result:
                    continue
                
                # Query the agent
                print("\n🤖 Agent is thinking...")
                response = query_agent(user_input)
                print("\n" + "📝 Response:")
                print("-" * 40)
                print(response)
                print()
                
            except KeyboardInterrupt:
                print("\n\n👋 Interrupted by user. Goodbye!")
                break
            except EOFError:
                print("\n\n👋 End of input. Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ Unexpected error: {e}")
                print("Please try again or use /quit to exit.")
                
    except Exception as init_error:
        print(f"❌ Failed to initialize monitoring agent: {init_error}")
        print("Please check the configuration and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main()