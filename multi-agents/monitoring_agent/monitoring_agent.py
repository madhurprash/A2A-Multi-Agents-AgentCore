# This is a monitoring agent. This agent is built using Strands agent SDK 
# This agent is responsible for the following: monitoring cloudwatch logs, metrics, 
# dashboards, and also other aws services through the local prebuilt strands tool (use_aws tool)

# This agent is the first agent that will be invoked which will use the local MCP server which will access
# the cloudwatch related tools. For the purpose of this, we will be using the new primitives for each agent
# This includes gateway, identity, toolbox, runtime and observability. Each agent is in itself a modular component
# that will interact with other agents using A2A and then will be using other agents available through the gateway

# NOTE: AgentCore Runtime configuration has been moved to agent_runtime.py for better separation of concerns.
# This file focuses on the agent logic and MCP gateway interaction only.
# import logging and set a logger for strands
# install other requirements
import os
import sys
import json
import uuid
import time
import glob
import boto3
import shutil
import logging
import base64
import argparse
import re
from botocore.exceptions import ClientError
# import the strands agents and strands tools that we will be using
from strands import Agent
from datetime import datetime
from dotenv import load_dotenv
from strands_tools import swarm
from typing import Dict, Any, Optional
from strands.models import BedrockModel
# import the memory client 
# This is the hook to retrieve, list and 
# create memories added to the agent
from memory_hook import MonitoringMemoryHooks
from bedrock_agentcore.memory import MemoryClient
# To correlate traces across multiple agent runs, 
# we will associate a session ID with our telemetry data using the 
# Open Telemetry baggage
from opentelemetry import context, baggage
# This will help set up for strategies that can then be used 
# across the code - user preferences, semantic memory or even
# summarizations across the sessions along with custom strategies
# for this monitoring agent
from bedrock_agentcore.memory.constants import StrategyType
# This is for the strands prebuilt tool
from strands_tools.agent_core_memory import AgentCoreMemoryToolProvider
# Configure loggers - suppress debug output for cleaner UI
logging.getLogger("strands").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("strands.tools.mcp").setLevel(logging.WARNING)
logging.getLogger("mcp.client").setLevel(logging.WARNING)
logging.getLogger("bedrock_agentcore").setLevel(logging.WARNING)
# First, begin by creating the authorizer and a gateway, in this example, 
# we will attach a single MCP server and locally defined tools to the gateway
from bedrock_agentcore_starter_toolkit.operations.gateway import GatewayClient
from strands.hooks import AfterInvocationEvent, HookProvider, HookRegistry, MessageAddedEvent

# Clean logging configuration for interactive mode
if len(sys.argv) > 1 and "--interactive" in sys.argv:
    # Minimal logging for interactive CLI
    logging.basicConfig(
        format="%(message)s", 
        level=logging.ERROR,
        handlers=[logging.StreamHandler()]
    )
else:
    # Standard logging for non-interactive mode
    logging.basicConfig(
        format="%(levelname)s | %(name)s | %(message)s", 
        handlers=[logging.StreamHandler()]
    )
sys.path.insert(0, ".")
sys.path.insert(1, "..")
from utils import *
from constants import *

# load the environment variables
load_dotenv()

# This is a parse argument function which will take in arguments for example the session id 
# in this case. A session is a complete interaction consisting of traces and spans within a 
# user interaction with an agent
def parse_arguments():
    try:
        logger.info("Parsing CLI args")
        parser = argparse.ArgumentParser(description="Monitoring agent with session tracking")
        parser.add_argument("--session_id", type=str, default=str(uuid.uuid4()),
                            help="Session ID for the agent")
        parser.add_argument("--interactive", action="store_true",
                            help="Run an interactive CLI chat instead of the HTTP server")
        args = parser.parse_args()
        if not args.session_id:
            args.session_id = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
            print(f"Session ID not provided, generating a new one: {args.session_id}")
        return args
    except Exception as e:
        logger.error(f"Error while parsing arguments: {e}")
        raise

# Now, assuming that this agent is running in agentcore runtime or in compute or containers outside of 
# agentcore, we will need to enable observability for adding baggage for OTEL compatible tracing and logging
def set_session_context(session_id: str):
    """
    This sets the session ID in OpenTelemetry baggage for trace correlation.
    This function is used to set the baggage for the context session id that is provided as an 
    OTEL metric for tracking agents that are hosted outside of Bedrock Agentcore runtime
    """
    try:
        # create the context session id
        ctx = baggage.set_baggage("session_id", session_id)
        token = context.attach(ctx)
        logger.info(f"Session ID set in baggage: {session_id}")
    except Exception as e:
        logger.error(f"Error while setting session context: {e}")
        raise e
    return token

# We will now initialize the OTEL variables that will be used from the 
# environment variables to enable python distro, python configurator, 
# protocol over which the telemetry data will be sent, 
# the headers (session id, trace id, etc), etc.
# Only show OTEL config in non-interactive mode
if "--interactive" not in sys.argv:
    otel_vars = [
        "OTEL_PYTHON_DISTRO",
        "OTEL_PYTHON_CONFIGURATOR",
        "OTEL_EXPORTER_OTLP_PROTOCOL",
        "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
        "OTEL_RESOURCE_ATTRIBUTES",
        "AGENT_OBSERVABILITY_ENABLED",
        "OTEL_TRACES_EXPORTER"
    ]
    print("Open telemetry configuration:")
    for var in otel_vars:
        value = os.getenv(var)
        if value:
            print(f"{var}: {value}")


# Set logger with appropriate level based on mode
if "--interactive" in sys.argv:
    logging.basicConfig(format='%(levelname)s - %(message)s', level=logging.WARNING)
else:
    logging.basicConfig(format='[%(asctime)s] p%(process)s {%(filename)s:%(lineno)d} %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Load the config file. 
config_data = load_config('config.yaml')
logger.info(f"Configuration loaded successfully")
from typing import Dict, List

# Initialize observability for this agent
cloudwatch_agent_info: Dict = config_data['cloudwatch_agent_resources']
print(f"Going to use cloudwatch agent info: {cloudwatch_agent_info}")

# initialize the cloudwatch client
cloudwatch_logs_client = boto3.client("logs")
print(f"Initialized the cloudwatch logs client: {cloudwatch_logs_client}")

# Now, let's create the cloudwatch log group, if this log group is already provided
# as an environment variable, it will be used
try:
    response = cloudwatch_logs_client.create_log_group(logGroupName=cloudwatch_agent_info.get('log_group_name'))
    print(f"Created the log group: {response}")
except ClientError as e:
    if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
        print(f"Log group already exists: {e}")
        # This is expected behavior, continue without error
        pass
    else:
        print(f"Error while creating log group: {e}")
        raise e

# Next, we will create a log stream for the same
try:
    response = cloudwatch_logs_client.create_log_stream(
        logGroupName=cloudwatch_agent_info.get('log_group_name'), 
        logStreamName=cloudwatch_agent_info.get('log_stream_name')  
    )
    print(f"Created the log stream: {response}")
except ClientError as e:
    if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
        print(f"Log stream '{cloudwatch_agent_info.get('log_stream_name')}' already exists, continuing...")
        # This is expected behavior, continue without error
        pass
    else:
        print(f"Error while creating log stream: {e}")
        raise e

def _refresh_access_token() -> str:
    """
    Refresh the access token using stored credentials and config
    """
    try:
        # Get config values
        gateway_config_info = config_data['agent_information']['monitoring_agent_model_info'].get('gateway_config')
        inbound_auth_config = gateway_config_info.get('inbound_auth')
        cognito_config = inbound_auth_config.get('cognito')
        
        RESOURCE_SERVER_ID = cognito_config.get('resource_server_id', "monitoring_agent")
        CLIENT_NAME = cognito_config.get('client_name', "agentcore-client")
        
        # Get auth info to extract pool details
        auth_info = gateway_config_info.get('auth_info', {})
        discovery_url = auth_info.get('discovery_url')
        
        if discovery_url:
            # Extract pool_id from discovery URL
            match = re.search(r'/([^/]+)/\.well-known', discovery_url)
            if match:
                user_pool_id = match.group(1)
                
                # Get client credentials
                cognito = boto3.client("cognito-idp", region_name=REGION_NAME)
                _, client_secret = get_or_create_m2m_client(cognito, user_pool_id, CLIENT_NAME, RESOURCE_SERVER_ID)
                
                # Get new token
                scope_string = f"{RESOURCE_SERVER_ID}/gateway:read {RESOURCE_SERVER_ID}/gateway:write"
                token_response = get_token(user_pool_id, auth_info.get('client_id'), client_secret, scope_string, REGION_NAME)
                
                if "error" not in token_response:
                    return token_response["access_token"]
                    
        logger.error("Failed to refresh access token")
        return None
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        return None
    
# ────────────────────────────────────────────────────────────────────────────────────
# AGENTCORE MEMORY PRIMITIVE INITIALIZATION
# ────────────────────────────────────────────────────────────────────────────────────

# initialize the memory client
client = MemoryClient(region_name=REGION_NAME)

# Read the custom extraction prompt
with open(f'{MONITORING_CUSTOM_EXTRACTION_PROMPT_FPATH}', 'r') as f:
    CUSTOM_EXTRACTION_PROMPT = f.read()

# Read the custom consolidation prompt  
with open(f'{MONITORING_CONSOLIDATION_EXTRACTION_PROMPT_FPATH}', 'r') as f:
    CUSTOM_CONSOLIDATION_PROMPT = f.read()
print(f"Going to use a custom extraction prompt: {CUSTOM_EXTRACTION_PROMPT}")
print(f"Going to use a custom consolidation prompt: {CUSTOM_CONSOLIDATION_PROMPT}")

# Check if we should use existing memory from config
use_existing_memory = config_data['agent_information']['monitoring_agent_model_info'].get('use_existing_memory', False)
existing_memory_id = config_data['agent_information']['monitoring_agent_model_info'].get('memory_credentials').get('id')
# set the memory and the memory id for initialization
memory_id = None
memory = None

if use_existing_memory and existing_memory_id:
    print(f"Using existing memory from config with ID: {existing_memory_id}")
    memory = {"id": existing_memory_id}
    memory_id = existing_memory_id
else:
    # Create new memory if none exists
    if not memory:
        print("Creating new memory...")
        # Define memory strategies for monitoring agent
        # we will define a user preference, semantic memory
        # and summary strategy, along with two prompts - extraction
        # and consolidation that will be used with them
        strategies = [
            {
                "userPreferenceMemoryStrategy": {
                    "name": "UserPreference",
                    "namespaces": ["/users/{actorId}"]
                }
            },
            {
                "semanticMemoryStrategy": {
                    "name": "SemanticMemory",
                    "namespaces": ["/knowledge/{actorId}"]
                }
            },
            {
                "customMemoryStrategy": {
                    "name": "MonitoringIssueTracker",
                    "namespaces": ["/technical-issues/{actorId}"],
                    "configuration": {
                        "semanticOverride": {
                            "extraction": {
                                "modelId": "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
                                "appendToPrompt": CUSTOM_EXTRACTION_PROMPT
                            },
                            "consolidation": {
                                "modelId": "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
                                "appendToPrompt": CUSTOM_CONSOLIDATION_PROMPT
                            }
                        }
                    }
                }
            }
        ]
        
        try:
            memory = client.create_memory_and_wait(
                name=f"{MONITORING_GATEWAY_NAME}_memory_{int(time.time())}",
                memory_execution_role_arn=EXECUTION_ROLE_ARN,
                strategies=strategies,
                description="Memory for monitoring agent with custom issue tracking",
                event_expiry_days=7, # short term conversation expires after 7 days
                max_wait = 300, 
                poll_interval=10
            )
            # create and get the memory id
            memory_id = memory.get("id")
            logger.info(f"✅ Created memory: {memory_id}")
        except Exception as e:
            logger.error(f"❌ ERROR creating memory: {e}")
            import traceback
            traceback.print_exc()
            # Cleanup on error - delete the memory if it was partially created
            if memory_id:
                try:
                    client.delete_memory_and_wait(memoryId=memory_id, max_wait=300)
                    logger.info(f"Cleaned up memory: {memory_id}")
                except Exception as cleanup_error:
                    logger.error(f"Failed to clean up memory: {cleanup_error}")
            raise
logger.info(f"Using memory with ID: {memory_id}")

# Initialize the arguments
args = parse_arguments()
logger.info(f"Arguments: {args}")

# Create memory hooks instance - use observability session/actor IDs if available
session_id = args.session_id
actor_id = f'monitoring-actor-{int(time.time())}'
logger.info(f"Using the following session id: {session_id} and actor id: {actor_id}")

monitoring_hooks = MonitoringMemoryHooks(
    memory_id=memory_id,
    client=client,
    actor_id=config_data['agent_information']['monitoring_agent_model_info'].get('memory_allocation').get('actor_id', actor_id),
    session_id=session_id
)
print(f"created the memory hook: {monitoring_hooks}")

# We will be using this hook in the agent creation process
logger.info(f"Going to create the agentcore gateway for this agent containing monitoring tools....")

# Create gateway using the enhanced AgentCore Gateway setup
monitoring_agent_config = config_data['agent_information']['monitoring_agent_model_info']
gateway_config_info = monitoring_agent_config.get('gateway_config')
# if there are any pre configured gateway credentials, they will be used here
gateway_credentials = gateway_config_info.get('credentials')

print("Setting up AgentCore Gateway from configuration...")

# Function to validate credentials
def validate_credentials(credentials_dict):
    """
    Validate that credentials dict contains all required fields
    """
    required_fields = ['gateway_id', 'mcp_url', 'access_token']
    return all(field in credentials_dict and credentials_dict[field] for field in required_fields)

# Check for existing credentials in multiple sources
mcp_url = None
access_token = None
gateway_id = None

# Priority 1: Check JSON credentials file (local directory first, then root directory)
# This json file will contain contains information about the gateway such as the access
# token fetched from connecting to Cognito to connect to the gateway
local_credentials_path = MONITORING_GATEWAY_CREDENTIALS_PATH
root_credentials_path = f"../{MONITORING_GATEWAY_CREDENTIALS_PATH}"

# Try local path first, then root path
credentials_path = None
if os.path.exists(local_credentials_path):
    credentials_path = local_credentials_path
elif os.path.exists(root_credentials_path):
    credentials_path = root_credentials_path

if credentials_path:
    try:
        with open(credentials_path, 'r') as cred_file:
            json_credentials = json.load(cred_file)
            if validate_credentials(json_credentials):
                mcp_url = json_credentials['mcp_url']
                access_token = json_credentials['access_token']
                gateway_id = json_credentials['gateway_id']
                print(f"Using existing gateway credentials from {credentials_path}")
                
                # Check if token should be refreshed
                if gateway_config_info['credentials'].get('create_new_access_token'):
                    print("⚠️ Attempting refresh of the token...")
                    new_token = _refresh_access_token()
                    if new_token:
                        access_token = new_token
                        # Update the credentials file
                        json_credentials['access_token'] = new_token
                        json_credentials['updated_at'] = time.time()
                        with open(credentials_path, 'w') as cred_file:
                            json.dump(json_credentials, cred_file, indent=4)
                        print("✅ Updated credentials with new access token")
    except Exception as e:
        print(f"Error reading JSON credentials file: {e}")

if mcp_url and access_token and gateway_id:
    print(f"Gateway ID: {gateway_id}")
    print(f"MCP Server URL: {mcp_url}")
    print(f"Access token: {access_token}")
else:
    # Add validation to ensure we have all required values before proceeding
    missing_values = []
    if not mcp_url:
        missing_values.append("mcp_url")
    if not access_token:
        missing_values.append("access_token")
    if not gateway_id:
        missing_values.append("gateway_id")
    
    if missing_values:
        print(f"⚠️  Missing required values: {', '.join(missing_values)}")
        print("Attempting to create new gateway and credentials...")

if not mcp_url or not access_token or not gateway_id:
    try:
        # Gateway configuration
        gateway_name = gateway_config_info.get('name', 'MonitoringGateway')
        # Step 1: Create IAM role using utils.py function
        print("Creating IAM role...")
        role_name = f"{gateway_name}Role"
        # Create the AgentCore gateway role with S3 and Smithy permissions
        agentcore_gateway_iam_role = create_agentcore_gateway_role_s3_smithy(role_name)
        role_arn = agentcore_gateway_iam_role['Role']['Arn']
        print(f"IAM role created: {role_arn}")
        # Step 2: Use existing Cognito setup
        print("Using existing Cognito setup...")
        
        # Get configuration values from config file
        inbound_auth_config: Dict = gateway_config_info.get('inbound_auth')
        cognito_config: Dict = inbound_auth_config.get('cognito')
        logger.info(f"Going to use the inbound auth mechanism through cognito: {cognito_config}")
        
        # Get values from config with defaults based on config.yaml
        RESOURCE_SERVER_ID = cognito_config.get('resource_server_id', "monitoring_agent")
        RESOURCE_SERVER_NAME = cognito_config.get('resource_server_name', "agentcore-gateway")
        CLIENT_NAME = cognito_config.get('client_name', "agentcore-client")
        SCOPES = cognito_config.get('scopes')
        logger.info(f"Going to use the following scopes from the config file: {SCOPES} for the monitoring agent.")
        
        # Initialize Cognito client for user pool management
        cognito = boto3.client("cognito-idp", region_name=REGION_NAME)
        
        # Determine if we should create new user pool or use existing
        create_user_pool = cognito_config.get('create_user_pool', False)
        user_pool_name = cognito_config.get('user_pool_name', 'MCPServerPool')
        
        if create_user_pool:
            # Create or get user pool using utils function
            print(f"Creating/getting user pool: {user_pool_name}")
            user_pool_id = get_or_create_user_pool(cognito, user_pool_name)
        else:
            # Use existing user pool from config
            auth_info = gateway_config_info.get('auth_info', {})
            discovery_url = auth_info.get('discovery_url')
            if discovery_url:
                # Extract pool_id from discovery URL
                import re
                match = re.search(r'/([^/]+)/\.well-known', discovery_url)
                if match:
                    user_pool_id = match.group(1)
                    print(f"Using existing User Pool ID: {user_pool_id}")
                else:
                    raise ValueError(f"Could not extract pool_id from discovery_url: {discovery_url}")
            else:
                raise ValueError("No discovery_url found in config auth_info")
        
        # Create or get resource server and M2M client using utils functions
        get_or_create_resource_server(cognito, user_pool_id, RESOURCE_SERVER_ID, RESOURCE_SERVER_NAME, SCOPES)
        print("Resource server ensured.")
        
        client_id, client_secret = get_or_create_m2m_client(cognito, user_pool_id, CLIENT_NAME, RESOURCE_SERVER_ID)
        
        # Create scope string needed for token generation
        scope_string = f"{RESOURCE_SERVER_ID}/gateway:read {RESOURCE_SERVER_ID}/gateway:write"
        
        # Set discovery URL based on user pool
        pool_region = user_pool_id.split('_')[0] if '_' in user_pool_id else REGION_NAME
        cognito_discovery_url = f"https://cognito-idp.{pool_region}.amazonaws.com/{user_pool_id}/.well-known/openid-configuration"
        
        print(f"Using Client ID: {client_id}")
        logger.info(f"Using Cognito discovery URL: {cognito_discovery_url}")
        # Step 3: Check if Gateway exists, then create if needed
        print("Checking if gateway exists...")
        gateway_client = boto3.client('bedrock-agentcore-control', region_name=REGION_NAME)
        auth_config = {
            "customJWTAuthorizer": { 
                "allowedClients": [client_id],
                "discoveryUrl": cognito_discovery_url
            }
        }
        
        # First check if gateway already exists (with pagination)
        gateway_id = None
        try:
            next_token = None
            found_gateway = False
            
            while not found_gateway:
                if next_token:
                    list_response = gateway_client.list_gateways(nextToken=next_token)
                else:
                    list_response = gateway_client.list_gateways()
                
                for gateway in list_response.get('items', []):
                    if gateway['name'] == gateway_name:
                        gateway_id = gateway['gatewayId']
                        # Get the full gateway details to retrieve URL
                        get_response = gateway_client.get_gateway(gatewayIdentifier=gateway_id)
                        mcp_url = get_response.get('gatewayUrl')
                        print(f"Gateway '{gateway_name}' already exists: {gateway_id}")
                        print(f"Gateway URL: {mcp_url}")
                        found_gateway = True
                        break
                
                # Check if there are more pages
                next_token = list_response.get('nextToken')
                if not next_token:
                    break
                    
        except Exception as e:
            print(f"Error checking existing gateways: {e}")
        
        # Create gateway only if it doesn't exist
        if not gateway_id or not mcp_url:
            try:
                print("Creating new gateway...")
                create_response = gateway_client.create_gateway(
                    name=gateway_name,
                    roleArn=role_arn,
                    protocolType=MCP_PROTOCOL,
                    authorizerType=AUTH_TYPE_CUSTOM_JWT,
                    authorizerConfiguration=auth_config, 
                    description='AgentCore Gateway with target for monitoring tools'
                )
                gateway_id = create_response.get("gatewayId")
                mcp_url = create_response.get("gatewayUrl")
                if not mcp_url:
                    print(f"❌ Warning: Gateway URL is None in create response")
                    print(f"Full create response: {create_response}")
                    # Try to get the gateway URL using the gateway ID
                    if gateway_id:
                        try:
                            get_response = gateway_client.get_gateway(gatewayIdentifier=gateway_id)
                            mcp_url = get_response.get('gatewayUrl')
                            print(f"Retrieved gateway URL via get_gateway: {mcp_url}")
                        except Exception as get_error:
                            print(f"Error getting gateway URL: {get_error}")
                print(f"Gateway created: {gateway_id}")
                print(f"Gateway URL: {mcp_url}")
            except Exception as e:
                if "ConflictException" in str(e) and "already exists" in str(e):
                    print(f"Gateway '{gateway_name}' already exists. Attempting to use existing gateway...")
                    # Extract gateway name from error message if possible
                    gateway_name_from_error = None
                    try:
                        # Try to extract the actual gateway name from the error message
                        error_str = str(e)
                        if "name '" in error_str and "' already exists" in error_str:
                            start = error_str.find("name '") + 6
                            end = error_str.find("' already exists")
                            gateway_name_from_error = error_str[start:end]
                            print(f"Extracted gateway name from error: {gateway_name_from_error}")
                    except Exception:
                        pass
                    
                    # List existing gateways to find the one with our name (with pagination)
                    try:
                        existing_gateway = None
                        search_names = [gateway_name]
                        if gateway_name_from_error and gateway_name_from_error != gateway_name:
                            search_names.append(gateway_name_from_error)
                        print(f"Searching for gateways with names: {search_names}")
                        
                        next_token = None
                        all_gateways = []
                        
                        # Paginate through all gateways
                        while True:
                            if next_token:
                                list_response = gateway_client.list_gateways(nextToken=next_token)
                            else:
                                list_response = gateway_client.list_gateways()
                            
                            logger.info(f"The gateways that are available in {REGION_NAME} (page): {list_response}")
                            current_items = list_response.get('items', [])
                            all_gateways.extend(current_items)
                            
                            # Search through current page items
                            for gateway in current_items:
                                if gateway['name'] in search_names:
                                    existing_gateway = gateway
                                    break
                            
                            if existing_gateway:
                                break
                                
                            # Check if there are more pages
                            next_token = list_response.get('nextToken')
                            if not next_token:
                                break
                        
                        if existing_gateway:
                            gateway_id = existing_gateway['gatewayId']
                            # Get the gateway URL using the gateway ID
                            try:
                                get_response = gateway_client.get_gateway(gatewayIdentifier=gateway_id)
                                mcp_url = get_response.get('gatewayUrl')
                                if not mcp_url:
                                    print(f"❌ Warning: Gateway URL is None for gateway {gateway_id}")
                                    print(f"Full gateway response: {get_response}")
                                print(f"✅ Using existing gateway: {gateway_id}")
                                print(f"Gateway URL: {mcp_url}")
                            except Exception as get_error:
                                print(f"Error getting gateway details: {get_error}")
                                raise e
                        else:
                            print(f"Could not find existing gateway with any of these names: {search_names}")
                            print("Available gateways:")
                            for gw in all_gateways:
                                print(f"  - Name: '{gw.get('name')}' (ID: {gw.get('gatewayId')})")
                            raise e
                    except Exception as list_error:
                        print(f"Error retrieving existing gateway: {list_error}")
                        raise e
                else:
                    raise e

        # Step 4: Create gateway targets from configuration
        print("Creating gateway targets...")
        if gateway_config_info.get('existing_target') and gateway_config_info.get('target_name'):
            print(f"Using existing target: {gateway_config_info.get('target_name')}")
        else:
            created_targets = create_targets_from_config(gateway_id, gateway_config_info, gateway_config_info.get('bucket_name'))
            print(f"✅ Successfully created {len(created_targets)} targets")
        # Step 5: Get access token using utils function
        print("Getting access token...")
        token_response = get_token(user_pool_id, client_id, client_secret, scope_string, REGION_NAME)
        print(f"Token response: {token_response}")
        if "error" in token_response:
            raise RuntimeError(f"Failed to get access token: {token_response['error']}")
        access_token = token_response["access_token"]
        print(f"✅ OpenAPI Gateway created successfully!")
        print(f"Gateway ID: {gateway_id}")
        print(f"MCP Server URL: {mcp_url}")
        print(f"Access Token: {access_token[:20]}...")
        # Create a dictionary with the credentials
        credentials = {
            "mcp_url": mcp_url,
            "access_token": access_token,
            "gateway_id": gateway_id,
            "created_at": time.time()
        }
        # Write the credentials to a JSON file
        with open(MONITORING_GATEWAY_CREDENTIALS_PATH, 'w') as cred_file:
            json.dump(credentials, cred_file, indent=4)
        print(f"Credentials saved to {os.path.abspath(MONITORING_GATEWAY_CREDENTIALS_PATH)}")
        
    except Exception as e:
        import traceback
        traceback.print_exc()

# Final validation to ensure mcp_url is not None
if not mcp_url:
    print("❌ ERROR: mcp_url is None. Gateway creation or retrieval failed.")
    print("Please check the gateway creation logs above for errors.")
    
    # Try one more time to get the gateway URL if we have a gateway_id
    if gateway_id:
        print(f"🔄 Attempting to retrieve gateway URL using gateway_id: {gateway_id}")
        try:
            gateway_client = boto3.client('bedrock-agentcore-control', region_name=REGION_NAME)
            get_response = gateway_client.get_gateway(gatewayIdentifier=gateway_id)
            mcp_url = get_response.get('gatewayUrl')
            if mcp_url:
                print(f"✅ Successfully retrieved gateway URL: {mcp_url}")
            else:
                print(f"❌ Gateway URL is still None in get_gateway response: {get_response}")
        except Exception as retry_error:
            print(f"❌ Failed to retrieve gateway URL: {retry_error}")
    
    # If still no mcp_url, raise error
    if not mcp_url:
        raise ValueError("mcp_url cannot be None - gateway setup failed")
        
prompt_template_path: str = f'{PROMPT_TEMPLATE_DIR}/{config_data["agent_information"]["prompt_templates"].get("monitoring_agent", "monitoring_agent_prompt_template.txt")}'
logger.info(f"Going to read the monitoring agent prompt template from: {prompt_template_path}")
with open(prompt_template_path, 'r', encoding='utf-8') as f:
    MONITORING_AGENT_SYSTEM_PROMPT = f.read().strip()
    logger.info(f"✅ Successfully loaded monitoring agent system prompt from: {prompt_template_path}")

# Create a bedrock model using the BedrockModel interface
monitoring_agent_info: str = config_data['agent_information']['monitoring_agent_model_info']
bedrock_model = BedrockModel(
    model_id=monitoring_agent_info.get('model_id'),
    region_name=REGION_NAME,
    temperature=monitoring_agent_info['inference_parameters'].get('temperature'),
    max_tokens=monitoring_agent_info['inference_parameters'].get('max_tokens')
)
print(f"Initialized the bedrock model for the monitoring agent: {bedrock_model}")

# Import only what's needed for the AgentCore app entrypoint
from bedrock_agentcore.runtime import BedrockAgentCoreApp

# Create app instance for entrypoint decorator
app = BedrockAgentCoreApp()

# Print hardcoded parameters for config.yaml reference
print("\n" + "="*60)
print("📋 HARDCODED PARAMETERS FOR CONFIG.YAML:")
print("="*60)
print(f"REGION_NAME: {REGION_NAME}")
print(f"EXECUTION_ROLE_ARN: {EXECUTION_ROLE_ARN}")
print(f"MONITORING_GATEWAY_NAME: {MONITORING_GATEWAY_NAME}")
print(f"CONFIG_FNAME: {CONFIG_FNAME}")
print(f"MONITORING_CUSTOM_EXTRACTION_PROMPT_FPATH: {MONITORING_CUSTOM_EXTRACTION_PROMPT_FPATH}")
print(f"MONITORING_CONSOLIDATION_EXTRACTION_PROMPT_FPATH: {MONITORING_CONSOLIDATION_EXTRACTION_PROMPT_FPATH}")
print(f"MONITORING_GATEWAY_CREDENTIALS_PATH: {MONITORING_GATEWAY_CREDENTIALS_PATH}")
print(f"MCP_PROTOCOL: {MCP_PROTOCOL}")
print(f"AUTH_TYPE_CUSTOM_JWT: {AUTH_TYPE_CUSTOM_JWT}")
print("="*60)

# Create MCP client and agent at module level for reuse
from strands.tools.mcp.mcp_client import MCPClient
from mcp.client.streamable_http import streamablehttp_client 

def create_streamable_http_transport():
    """
    This is the client to return a streamablehttp access token
    Automatically refreshes token if connection fails
    """
    try:
        # Read credentials from file to get current token
        with open(MONITORING_GATEWAY_CREDENTIALS_PATH, 'r') as cred_file:
            json_credentials = json.load(cred_file)
            current_access_token = json_credentials['access_token']
            current_mcp_url = json_credentials['mcp_url']
        
        try:
            response = streamablehttp_client(current_mcp_url, headers={"Authorization": f"Bearer {current_access_token}"})
            return response
        except Exception as auth_error:
            logger.warning(f"Authentication failed, attempting to refresh token: {auth_error}")
            
            # Try to refresh the token
            new_token = _refresh_access_token()
            if new_token:
                # Update credentials file with new token
                json_credentials['access_token'] = new_token
                json_credentials['updated_at'] = time.time()
                with open(MONITORING_GATEWAY_CREDENTIALS_PATH, 'w') as cred_file:
                    json.dump(json_credentials, cred_file, indent=4)
                
                # Retry connection with new token
                response = streamablehttp_client(current_mcp_url, headers={"Authorization": f"Bearer {new_token}"})
                logger.info("✅ Successfully connected with refreshed token")
                return response
            else:
                logger.error("❌ Failed to refresh access token")
                raise auth_error
                
    except Exception as e:
        logger.error(f"An error occurred while connecting to the MCP server: {e}")
        raise e

# Initialize MCP client
print(f"Going to start the MCP session...")

# Debug: Test if we can read credentials
try:
    with open(MONITORING_GATEWAY_CREDENTIALS_PATH, 'r') as debug_file:
        debug_creds = json.load(debug_file)
        print(f"DEBUG: Credentials available: URL={debug_creds.get('mcp_url')}, Token={debug_creds.get('access_token')[:20]}...")
except Exception as e:
    print(f"DEBUG: Error reading credentials: {e}")

mcp_client = MCPClient(create_streamable_http_transport)
print(f"Started the MCP session client...")

def invoke_agent_with_mcp_session(user_message):
    """
    Invoke the agent within an MCP client session context.
    This ensures the MCP client is properly initialized before agent execution.
    """
    # Initialize gateway tools
    print(f"Going to list tools from the MCP client")
    try:
        with mcp_client:
            gateway_tools = mcp_client.list_tools_sync()
            print(f"Loaded {len(gateway_tools)} tools from Gateway...")
            # Create agent with Gateway MCP tools + memory hooks + observability hooks
            hooks = [monitoring_hooks]
            # Initialize agent at module level
            agent = Agent(
                system_prompt=MONITORING_AGENT_SYSTEM_PROMPT,
                model=bedrock_model,
                hooks=hooks,
                tools=gateway_tools
            )
            response = agent(user_message)
            return response.message['content'][0]['text']
    except Exception as tools_error:
        print(f"❌ Error listing tools from Gateway MCP server: {tools_error}")
        raise

print(f"✅ Created monitoring agent with Gateway MCP tools!")

def ask_agent(prompt_text: str, session_id: str) -> str:
    token = None
    try:
        token = set_session_context(session_id)
        return invoke_agent_with_mcp_session(prompt_text)
    finally:
        if token is not None:
            try:
                context.detach(token)
            except Exception:
                pass

def filter_agent_output(output: str) -> str:
    """
    Filter agent output to show only relevant information for users.
    Remove debug logs, technical details, and focus on:
    - Tool calls
    - Memory operations 
    - Actual agent responses
    """
    if not output:
        return output
    
    lines = output.split('\n')
    filtered_lines = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Skip debug logs and technical output
        skip_patterns = [
            'DEBUG', 'INFO:', 'WARNING:', 'ERROR:',
            'protocol version:', 'Request: POST', 'HTTP/1.1',
            'streaming response', 'tool configurations',
            'loaded tool config', 'tools configured',
            'waiting for close signal', 'session initialized',
            'received tool result', 'mapping MCP text content',
            'tool execution completed', 'streaming messages'
        ]
        
        if any(pattern in line for pattern in skip_patterns):
            continue
            
        # Keep useful information - tool calls, memory operations, analysis
        keep_patterns = [
            'Tool #', '___',  # Any tool with ___ pattern
            'memory', 'Memory', 'MEMORY',
            'analysis', 'Analysis', 'ANALYSIS',
            'result', 'Result', 'RESULT',
            'error', 'Error', 'ERROR',
            'alarm', 'Alarm', 'ALARM',
            'dashboard', 'Dashboard', 'DASHBOARD',
            'log', 'Log', 'LOG'
        ]
        
        if any(pattern in line for pattern in keep_patterns) or len(line) > 50:
            filtered_lines.append(line)
    
    return '\n'.join(filtered_lines) if filtered_lines else output

# --- add the interactive loop ---
def interactive_cli(session_id: str):
    print("\n🧪 Monitoring Agent CLI (type 'exit' to quit)")
    print(f"session_id: {session_id}\n")
    while True:
        try:
            q = input("you> ").strip()
            if not q:
                continue
            if q.lower() in {"exit", "quit", "q"}:
                print("bye 👋")
                break
            if q.lower() in {"help", "/help"}:
                print("Commands: exit | help")
                continue

            resp = ask_agent(q, session_id)
            # Filter and display clean response
            clean_resp = filter_agent_output(resp)
            print(f"agent> {clean_resp}\n")
        except KeyboardInterrupt:
            print("\nbye 👋")
            break
        except Exception as e:
            print(f"error: {e}\n")

@app.entrypoint
def invoke(payload):
    '''
    This is the entrypoint function to invoke the monitoring agent.
    This agent is created with tools from the MCP Gateway and can be
    invoked both locally and via agent ARN using boto3 bedrock-agentcore client.
    '''
    # First, we will set the OTEL session baggage which will be used to emit traces, logs and metrics for
    # each session, trace and span
    try:
        # initialize the response
        response = None
        context_token = set_session_context(args.session_id)
        user_message = payload.get("prompt", "You are a monitoring agent to help with AWS monitoring related queries.")
        print(f"Going to invoke the agent with the following prompt: {user_message}")
        response = invoke_agent_with_mcp_session(user_message)
        context.detach(context_token)
    except Exception as e:
        print(f"An error occurred while invoking the monitoring agent: {e}")
        raise e
    return response

if __name__ == "__main__":
    args = parse_arguments()
    logger.info(f"Arguments: {args}")
    session_id = args.session_id

    if args.interactive:
        interactive_cli(session_id)
    else:
        app.run()