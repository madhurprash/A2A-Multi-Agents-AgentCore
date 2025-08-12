#!/usr/bin/env python3

import os
import sys
import yaml
import json
import time
import boto3
import logging
import argparse
import subprocess
from typing import Dict, Any, Optional
from boto3.session import Session
from bedrock_agentcore_starter_toolkit import Runtime

from utils import *

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)
logger = logging.getLogger(__name__)

class AgentCoreRuntimeManager:
    """Manages AgentCore Runtime configuration and execution for the orchestrator agent"""
    
    def __init__(self, config_file: str = "config.yaml"):
        """Initialize the runtime manager with configuration"""
        self.config_file = config_file
        self.config_data = self._load_config()
        self.bedrock_config = self._load_bedrock_config()
        self.runtime = None
        self.agent_name = "monitoring_agent"
        self.boto_session = Session()
        self.region = self.boto_session.region_name
        # always set the auth flag to true so that the agent
        # configuration always happens when the authorization and inbound authentication information
        # is provided
        self.auth = True
        self.custom_jwt_authorizer = None
        
        logger.info(f"Set the authentication to True, going to be setting inbound authentication for the agent based on the IdP of choice...")
        logger.info(f"Initialized AgentCoreRuntimeManager for agent: {self.agent_name}")
        logger.info(f"Region: {self.region}")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from: {self.config_file}")
            return config
        except Exception as e:
            logger.error(f"Failed to load config from {self.config_file}: {e}")
            raise
    
    def _load_bedrock_config(self) -> Dict[str, Any]:
        """Load Bedrock AgentCore configuration from .bedrock_agentcore.yaml"""
        bedrock_config_file = ".bedrock_agentcore.yaml"
        try:
            with open(bedrock_config_file, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Bedrock AgentCore configuration loaded from: {bedrock_config_file}")
            return config
        except Exception as e:
            logger.warning(f"Could not load Bedrock config from {bedrock_config_file}: {e}")
            return {}
    
    def should_configure_runtime(self) -> bool:
        """Check if runtime needs to be configured"""
        if not self.runtime:
            return True
        
        try:
            status_response = self.runtime.status()
            if hasattr(status_response, 'endpoint'):
                status = status_response.endpoint.get('status', 'UNKNOWN')
                logger.info(f"Current runtime status: {status}")
                return status not in ['READY', 'CREATING', 'UPDATING']
            return True
        except Exception as e:
            logger.warning(f"Could not check runtime status: {e}")
            return True
    
    def configure_runtime(self) -> Dict[str, Any]:
        """Configure the AgentCore Runtime"""
        try:
            logger.info("Configuring AgentCore Runtime...")

            # ------------------------------------------
            # SET UP INBOUND AUTHENTICATION FOR THE AGENT
            # ------------------------------------------
            # Initialize runtime
            self.runtime = Runtime()
            # Configure runtime with proper parameters
            response = self.runtime.configure(
                entrypoint="monitoring_agent.py",
                execution_role='arn:aws:iam::218208277580:role/service-role/Amazon-Bedrock-IAM-Role-20240102T112809', 
                auto_create_ecr=True,
                requirements_file="requirements.txt",
                region=self.region,
                agent_name=self.agent_name
            )
            logger.info(f"Runtime configured successfully: {response}")
            return response
            
        except Exception as e:
            logger.error(f"Failed to configure runtime: {e}")
            raise
    
    def launch_runtime(self) -> Dict[str, Any]:
        """Launch the AgentCore Runtime and wait for it to be ready"""
        try:
            if not self.runtime:
                raise ValueError("Runtime not configured. Call configure_runtime() first.")
            
            logger.info("Launching AgentCore Runtime...")
            start_time = time.time()
            
            # Launch the runtime
            launch_result = self.runtime.launch()
            logger.info("Launch initiated successfully")
            
            # Wait for runtime to be ready
            status = self._wait_for_ready_status(start_time)
            
            if status == 'READY':
                logger.info("🎉 Agent runtime launched successfully!")
                return self._get_runtime_info()
            else:
                raise RuntimeError(f"Runtime launch failed with status: {status}")
                
        except Exception as e:
            logger.error(f"Failed to launch runtime: {e}")
            raise
    
    def launch_runtime_with_codebuild(self) -> Dict[str, Any]:
        """Launch the AgentCore Runtime using CodeBuild approach"""
        try:
            logger.info("Launching AgentCore Runtime with CodeBuild...")
            # Get default agent from configuration
            default_agent = self.bedrock_config.get('default_agent', 'monitoring_agent')
            logger.info(f"Using default agent: {default_agent}")
            
            # Run agentcore launch --push-ecr command
            # this will build and push to ECR
            cmd = ['agentcore', 'launch', '--push-ecr']
            logger.info(f"Executing command: {' '.join(cmd)}")
            
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            elapsed_time = time.time() - start_time
            logger.info(f"CodeBuild launch completed in {elapsed_time:.1f} seconds")
            logger.info(f"Command output: {result.stdout}")
            
            if result.stderr:
                logger.warning(f"Command stderr: {result.stderr}")
            
            # Extract runtime information from the bedrock config
            runtime_info = self._get_codebuild_runtime_info()
            
            logger.info("🎉 Agent runtime launched successfully with CodeBuild!")
            return runtime_info
            
        except subprocess.CalledProcessError as e:
            logger.error(f"CodeBuild launch failed: {e}")
            logger.error(f"Command stdout: {e.stdout}")
            logger.error(f"Command stderr: {e.stderr}")
            raise RuntimeError(f"CodeBuild launch failed with exit code {e.returncode}")
        except Exception as e:
            logger.error(f"Failed to launch runtime with CodeBuild: {e}")
            raise
    
    def _get_codebuild_runtime_info(self) -> Dict[str, Any]:
        """Get runtime information from Bedrock AgentCore configuration"""
        try:
            default_agent = self.bedrock_config.get('default_agent', 'monitoring_agent')
            agents_config = self.bedrock_config.get('agents', {})
            agent_config = agents_config.get(default_agent, {})
            
            bedrock_agentcore = agent_config.get('bedrock_agentcore', {})
            codebuild_config = agent_config.get('codebuild', {})
            
            return {
                'agent_name': default_agent,
                'agent_id': bedrock_agentcore.get('agent_id'),
                'agent_arn': bedrock_agentcore.get('agent_arn'),
                'codebuild_project': codebuild_config.get('project_name'),
                'source_bucket': codebuild_config.get('source_bucket'),
                'launch_method': 'codebuild'
            }
        except Exception as e:
            logger.error(f"Failed to get CodeBuild runtime info: {e}")
            return {'launch_method': 'codebuild', 'error': str(e)}
    
    def _wait_for_ready_status(self, start_time: float, max_wait_minutes: int = 30) -> str:
        """Wait for runtime to reach READY status"""
        end_statuses = ['READY', 'CREATE_FAILED', 'DELETE_FAILED', 'UPDATE_FAILED']
        check_count = 0
        max_checks = max_wait_minutes * 6  # 10-second intervals
        
        while check_count < max_checks:
            try:
                status_response = self.runtime.status()
                status = status_response.endpoint.get('status', 'UNKNOWN')
                
                elapsed = time.time() - start_time
                logger.info(f"Status check #{check_count + 1} (elapsed: {elapsed:.1f}s): {status}")
                
                if status in end_statuses:
                    return status
                
                check_count += 1
                time.sleep(10)
                
            except Exception as e:
                logger.warning(f"Status check failed: {e}")
                check_count += 1
                time.sleep(10)
        
        logger.warning(f"Timeout waiting for runtime (max {max_wait_minutes} minutes)")
        return 'TIMEOUT'
    
    def _get_runtime_info(self) -> Dict[str, Any]:
        """Get runtime information including ARN"""
        try:
            status_response = self.runtime.status()
            if hasattr(status_response, 'endpoint'):
                endpoint_info = status_response.endpoint
                return {
                    'status': endpoint_info.get('status'),
                    'arn': endpoint_info.get('arn'),
                    'last_updated': endpoint_info.get('last_updated_time')
                }
            return {}
        except Exception as e:
            logger.error(f"Failed to get runtime info: {e}")
            return {}
    
    def get_status(self) -> Dict[str, Any]:
        """Get current runtime status"""
        try:
            if not self.runtime:
                return {'status': 'NOT_CONFIGURED'}
            
            status_response = self.runtime.status()
            if hasattr(status_response, 'endpoint'):
                return status_response.endpoint
            return {'status': 'UNKNOWN'}
            
        except Exception as e:
            logger.error(f"Failed to get status: {e}")
            return {'status': 'ERROR', 'error': str(e)}
    
    def invoke_runtime(self, user_message: str) -> str:
        """Invoke the runtime with a user message"""
        try:
            if not self.runtime:
                raise ValueError("Runtime not configured")
            
            logger.info(f"Invoking runtime with message: {user_message[:100]}...")
            
            # Invoke the runtime
            response = self.runtime.invoke(
                payload={"prompt": user_message}
            )
            
            # Extract response content
            if hasattr(response, 'output') and response.output:
                return response.output
            elif isinstance(response, dict) and 'output' in response:
                return response['output']
            else:
                return str(response)
                
        except Exception as e:
            logger.error(f"Failed to invoke runtime: {e}")
            return f"Error invoking runtime: {str(e)}"

def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description="Orchestrator Agent Runtime Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Configure and launch runtime
    python agent_runtime.py --configure --launch
    
    # Launch runtime using CodeBuild
    python agent_runtime.py --launch-codebuild
    
    # Check runtime status
    python agent_runtime.py --status
    
    # Invoke runtime with a message
    python agent_runtime.py --invoke "What Autodesk products are available?"
"""
    )
    
    parser.add_argument("--configure", action="store_true", 
                       help="Configure the AgentCore Runtime")
    parser.add_argument("--launch", action="store_true",
                       help="Launch the AgentCore Runtime")
    parser.add_argument("--launch-codebuild", action="store_true",
                       help="Launch the AgentCore Runtime using CodeBuild")
    parser.add_argument("--status", action="store_true",
                       help="Get runtime status")
    parser.add_argument("--invoke", type=str,
                       help="Invoke runtime with a message")
    parser.add_argument("--config", type=str, default="config.yaml",
                       help="Configuration file path")
    
    args = parser.parse_args()
    
    # Initialize runtime manager
    try:
        manager = AgentCoreRuntimeManager(config_file=args.config)
    except Exception as e:
        logger.error(f"Failed to initialize runtime manager: {e}")
        sys.exit(1)
    
    try:
        # Handle configuration
        if args.configure:
            logger.info("Configuring runtime...")
            result = manager.configure_runtime()
            logger.info(f"Configuration result: {result}")
        
        # Handle launch
        if args.launch:
            logger.info("Launching runtime...")
            result = manager.launch_runtime()
            logger.info(f"Launch result: {result}")
        
        # Handle CodeBuild launch
        if args.launch_codebuild:
            logger.info("Launching runtime with CodeBuild...")
            result = manager.launch_runtime_with_codebuild()
            logger.info(f"CodeBuild launch result: {result}")
        
        # Handle status check
        if args.status:
            status = manager.get_status()
            logger.info(f"Runtime status: {json.dumps(status, indent=2, default=str)}")
        
        # Handle invocation
        if args.invoke:
            response = manager.invoke_runtime(args.invoke)
            logger.info(f"Runtime response: {response}")
        
        if not any([args.configure, args.launch, args.launch_codebuild, args.status, args.invoke]):
            parser.print_help()
            
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()