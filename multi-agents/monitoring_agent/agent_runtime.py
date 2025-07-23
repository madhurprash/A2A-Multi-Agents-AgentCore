"""
AgentCore Runtime Configuration and Launch Module

This module handles the AgentCore Runtime setup separately from the main monitoring agent.
Use this when you want to deploy the monitoring agent as a containerized AgentCore runtime.
"""

import os
import sys
import json
import time
import logging
from boto3.session import Session
from bedrock_agentcore_starter_toolkit import Runtime
from bedrock_agentcore.runtime import BedrockAgentCoreApp

# Add parent directory to path for imports
sys.path.insert(0, ".")
sys.path.insert(1, "..")
from utils import load_config
from constants import REGION_NAME, CONFIG_FNAME

# Configure logging
logging.basicConfig(
    format="%(levelname)s | %(name)s | %(message)s", 
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class AgentCoreRuntimeManager:
    """Manages AgentCore Runtime configuration and deployment"""
    
    def __init__(self, config_file='config.yaml'):
        """Initialize with configuration"""
        self.config_data = load_config(config_file)
        self.agentcore_runtime = None
        self.region = REGION_NAME
        self.fresh_access_token = None  # Store fresh token in memory
        
        # Extract runtime configuration
        gateway_config = self.config_data.get('agent_information', {}).get(
            'monitoring_agent_model_info', {}
        ).get('gateway_config', {})
        
        self.runtime_exec_role = gateway_config.get('runtime_exec_role')
        self.launch_agentcore_runtime = gateway_config.get('launch_agentcore_runtime', False)
        self.agent_arn = gateway_config.get('agent_arn')
        
        # Import and use the refresh_access_token function from monitoring_agent
        from monitoring_agent import refresh_access_token
        self.fresh_access_token = refresh_access_token()
        
        logger.info(f"Runtime execution role: {self.runtime_exec_role}")
        logger.info(f"Launch AgentCore runtime: {self.launch_agentcore_runtime}")
        logger.info(f"Agent ARN: {self.agent_arn}")
        if self.fresh_access_token:
            logger.info(f"✅ Fresh access token created and stored in memory")
    
    def should_configure_runtime(self):
        """Check if runtime should be configured"""
        if self.agent_arn:
            logger.info("🌐 Agent ARN provided - runtime configuration not needed")
            return False
        
        if not self.runtime_exec_role or not self.launch_agentcore_runtime:
            logger.info("ℹ️  AgentCore runtime conditions not met - skipping runtime setup")
            return False
            
        return True
    
    def configure_runtime(self):
        """Configure the AgentCore Runtime"""
        if not self.should_configure_runtime():
            return False
            
        logger.info("✅ AgentCore runtime conditions met - initializing Runtime")
        
        try:
            boto_session = Session()
            self.region = boto_session.region_name or self.region
            self.agentcore_runtime = Runtime()
            
            logger.info("🔧 Configuring AgentCore Runtime...")
            configure_response = self.agentcore_runtime.configure(
                entrypoint="monitoring_agent.py",
                execution_role=self.runtime_exec_role,
                auto_create_ecr=True,
                requirements_file="requirements.txt",
                region=self.region
            )
            logger.info(f"✅ Runtime configured: {configure_response}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error configuring AgentCore Runtime: {e}")
            self.agentcore_runtime = None
            return False
    
    def launch_runtime(self):
        """Launch the AgentCore Runtime"""
        if not self.agentcore_runtime:
            logger.error("❌ Runtime not configured. Call configure_runtime() first.")
            return False
            
        try:
            logger.info("🚀 Launching AgentCore Runtime...")
            launch_result = self.agentcore_runtime.launch()
            logger.info(f"✅ Runtime launched: {launch_result}")
            
            logger.info("⏳ Waiting for runtime to be ready...")
            end_statuses = ['READY', 'CREATE_FAILED', 'DELETE_FAILED', 'UPDATE_FAILED']
            
            while True:
                status_response = self.agentcore_runtime.status()
                status = status_response.endpoint['status']
                logger.info(f"Runtime status: {status}")
                
                if status in end_statuses:
                    break
                time.sleep(10)
            
            if status == 'READY':
                logger.info("✅ AgentCore Runtime is ready for invocations")
                return True
            else:
                logger.error(f"❌ Runtime failed with status: {status}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error launching AgentCore Runtime: {e}")
            return False
    
    def invoke_runtime(self, user_message: str):
        """Invoke the AgentCore Runtime using boto3 client"""
        if not self.agentcore_runtime:
            logger.error("❌ Runtime not configured. Call configure_runtime() and launch_runtime() first.")
            return None
            
        try:
            # Get the agent ARN from the launch result
            status_response = self.agentcore_runtime.status()
            agent_arn = status_response.endpoint.get('agentRuntimeArn')
            
            if not agent_arn:
                logger.error("❌ Agent ARN not found in runtime status")
                return None
            
            # Create boto3 client for bedrock-agentcore
            import boto3
            agentcore_client = boto3.client(
                'bedrock-agentcore',
                region_name=self.region
            )
            
            # Prepare payload
            payload = json.dumps({"prompt": user_message})
            
            # Invoke the agent runtime
            boto3_response = agentcore_client.invoke_agent_runtime(
                agentRuntimeArn=agent_arn,
                qualifier="DEFAULT",
                payload=payload
            )
            
            logger.info(f"Response content type: {boto3_response.get('contentType', 'unknown')}")
            
            # Handle different response types
            if "text/event-stream" in boto3_response.get("contentType", ""):
                # Handle streaming response
                content = []
                try:
                    for line in boto3_response["response"].iter_lines(chunk_size=1024):
                        if line:
                            line_str = line.decode("utf-8").strip()
                            logger.debug(f"Raw line: {line_str}")
                            
                            if line_str.startswith("data: "):
                                data_content = line_str[6:].strip()
                                if data_content and data_content != "[DONE]":
                                    try:
                                        # Try to parse as JSON
                                        parsed_data = json.loads(data_content)
                                        if isinstance(parsed_data, dict):
                                            # Extract text content from the parsed data
                                            text_content = (
                                                parsed_data.get('text', '') or
                                                parsed_data.get('content', '') or
                                                parsed_data.get('message', '') or
                                                str(parsed_data)
                                            )
                                            content.append(text_content)
                                        else:
                                            content.append(str(parsed_data))
                                    except json.JSONDecodeError:
                                        # If not JSON, treat as plain text
                                        content.append(data_content)
                    
                    result = "\n".join(content) if content else "No content received"
                    
                except Exception as e:
                    logger.error(f"Error processing streaming response: {e}")
                    result = f"Error processing streaming response: {e}"
            
            else:
                # Handle non-streaming response
                try:
                    response_data = boto3_response.get("response", [])
                    
                    if hasattr(response_data, '__iter__') and not isinstance(response_data, (str, bytes)):
                        # Handle EventStream
                        events = []
                        for event in response_data:
                            try:
                                if hasattr(event, 'decode'):
                                    # If it's bytes, decode it
                                    event_str = event.decode("utf-8")
                                else:
                                    # If it's already a string or dict
                                    event_str = str(event)
                                
                                # Try to parse as JSON
                                if event_str.strip():
                                    try:
                                        parsed_event = json.loads(event_str)
                                        events.append(parsed_event)
                                    except json.JSONDecodeError:
                                        # If not valid JSON, store as string
                                        events.append(event_str)
                            except Exception as event_error:
                                logger.warning(f"Error processing event: {event_error}")
                                events.append(f"Error processing event: {event_error}")
                        
                        if events:
                            # Extract meaningful content from events
                            result_parts = []
                            for event in events:
                                if isinstance(event, dict):
                                    content = (
                                        event.get('text', '') or
                                        event.get('content', '') or
                                        event.get('message', '') or
                                        json.dumps(event, indent=2)
                                    )
                                    result_parts.append(content)
                                else:
                                    result_parts.append(str(event))
                            
                            result = "\n".join(result_parts)
                        else:
                            result = "No events received"
                    else:
                        # Handle direct response
                        if isinstance(response_data, (str, bytes)):
                            if isinstance(response_data, bytes):
                                response_data = response_data.decode("utf-8")
                            try:
                                parsed_response = json.loads(response_data)
                                result = str(parsed_response)
                            except json.JSONDecodeError:
                                result = response_data
                        else:
                            result = str(response_data)
                
                except Exception as e:
                    logger.error(f"Error processing non-streaming response: {e}")
                    result = f"Error processing response: {e}"
            
            # Return response object
            return type('Response', (), {'message': result})()
            
        except Exception as e:
            logger.error(f"❌ Error invoking AgentCore runtime: {e}")
            return None
    
    def get_status(self):
        """Get runtime status"""
        if not self.agentcore_runtime:
            return "Not configured"
            
        try:
            status_response = self.agentcore_runtime.status()
            return status_response.endpoint['status']
        except Exception as e:
            return f"Error getting status: {e}"

def main():
    """Main function for standalone runtime management"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AgentCore Runtime Manager')
    parser.add_argument('--configure', action='store_true', help='Configure runtime')
    parser.add_argument('--launch', action='store_true', help='Launch runtime')
    parser.add_argument('--status', action='store_true', help='Get runtime status')
    parser.add_argument('--config', default='config.yaml', help='Configuration file path')
    
    args = parser.parse_args()
    
    runtime_manager = AgentCoreRuntimeManager(args.config)
    
    if args.configure:
        success = runtime_manager.configure_runtime()
        if not success:
            sys.exit(1)
    
    if args.launch:
        if not runtime_manager.agentcore_runtime:
            print("Runtime not configured. Run with --configure first.")
            sys.exit(1)
        success = runtime_manager.launch_runtime()
        if not success:
            sys.exit(1)
    
    if args.status:
        status = runtime_manager.get_status()
        print(f"Runtime status: {status}")

if __name__ == "__main__":
    main()