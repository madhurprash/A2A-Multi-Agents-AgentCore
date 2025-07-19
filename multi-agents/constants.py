import os
import boto3

# This is the path of the config file that contains information about the 
# agents and the respective primitives
CONFIG_FNAME: str = "config.yaml"

# These are the tool use IDs that are initialized for the strands based
# callback handler functions
TOOL_USE_IDS = []

# These are the memory prompts that are used for extraction and consolidation
# MONITORING AGENT MEMORY PROMPTS
MEMORY_PROMPTS_FPATH: str = 'custom_memory_prompts'
MONITORING_AGENT_MEMORY_PROMPT_FPATH: str = os.path.join(MEMORY_PROMPTS_FPATH, 'monitoring_agent_memory')
MONITORING_CUSTOM_EXTRACTION_PROMPT_FPATH: str = os.path.join(MONITORING_AGENT_MEMORY_PROMPT_FPATH, 'custom_extraction_prompt.txt')
MONITORING_CONSOLIDATION_EXTRACTION_PROMPT_FPATH: str = os.path.join(MONITORING_AGENT_MEMORY_PROMPT_FPATH, 'custom_consolidation_prompt.txt')
# Gateway configuration constants
# This is the gateway information for the monitoring agent
MONITORING_GATEWAY_NAME = "MonitoringAgentGWNew"
MONITORING_GATEWAY_DESC: str = "Gateway for the monitoring agent"
MONITORING_GATEWAY_CREDENTIALS_PATH = "mcp_credentials.json"
REGION_NAME = "us-west-2"
ACCOUNT_ID = boto3.client("sts").get_caller_identity()["Account"]
EXECUTION_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/GenesisGatewayExecutionRole"
LAMBDA_ARN = f"arn:aws:lambda:{REGION_NAME}:{ACCOUNT_ID}:function:AgentGatewayFunction"