# This is a monitoring agent. This agent is built using Strands agent SDK 
# This agent is responsible for the following: monitoring cloudwatch logs, metrics, 
# dashboards, and also other aws services through the local prebuilt strands tool (use_aws tool)

# This agent is the first agent that will be invoked which will use the local MCP server which will access
# the cloudwatch related tools. For the purpose of this, we will be using the new primitives for each agent
# This includes gateway, identity, toolbox, runtime and observability. Each agent is in itself a modular component
# that will interact with other agents using A2A and then will be using other agents available through the gateway
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
import zipfile
import subprocess
from botocore.exceptions import ClientError
# import the strands agents and strands tools that we will be using
from strands import Agent
from datetime import datetime
from dotenv import load_dotenv
from strands_tools import swarm
from typing import Dict, Any, Optional
from strands.models import BedrockModel
# import the memory client 
from bedrock_agentcore.memory import MemoryClient
# This will help set up for strategies that can then be used 
# across the code - user preferences, semantic memory or even
# summarizations across the sessions along with custom strategies
# for this monitoring agent
from bedrock_agentcore.memory.constants import StrategyType
# This is for the strands prebuilt tool
from strands_tools.agent_core_memory import AgentCoreMemoryToolProvider
# Configure the root strands logger
logging.getLogger("strands").setLevel(logging.DEBUG)
# ────────── ENABLE DEBUG LOGGING ──────────
# logging.basicConfig(level=logging.DEBUG)                             
# boto3.set_stream_logger('', logging.DEBUG)                          
# logging.getLogger('botocore').setLevel(logging.DEBUG)               
# logging.getLogger('urllib3').setLevel(logging.DEBUG)               
# import httpx      # or just import httpcore if you prefer
# logging.getLogger('httpx').setLevel(logging.DEBUG)
# logging.getLogger('httpcore').setLevel(logging.DEBUG)
# logging.getLogger('strands').setLevel(logging.DEBUG)
# logging.getLogger('strands.tools.mcp').setLevel(logging.DEBUG)
# logging.getLogger('mcp.client').setLevel(logging.DEBUG)
# First, begin by creating the authorizer and a gateway, in this example, 
# we will attach a single MCP server and locally defined tools to the gateway
from bedrock_agentcore_starter_toolkit.operations.gateway import GatewayClient
from strands.hooks import AfterInvocationEvent, HookProvider, HookRegistry, MessageAddedEvent

# Add a handler to see the logs
logging.basicConfig(
    format="%(levelname)s | %(name)s | %(message)s", 
    handlers=[logging.StreamHandler()]
)
sys.path.insert(0, ".")
sys.path.insert(1, "..")
from utils import *
from constants import *
# This is the hook to retrieve, list and 
# create memories added to the agent
from memory_hook import MonitoringMemoryHooks
# Simple observability based on AWS Bedrock AgentCore Strands reference
import uuid
try:
    from opentelemetry import baggage, context
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    logger.warning("OpenTelemetry not available. Install aws-opentelemetry-distro for observability.")

class SimpleObservability:
    """Simple observability using OpenTelemetry baggage for session tracking"""
    
    def __init__(self, service_name="monitoring-agent"):
        self.service_name = service_name
        self.enabled = os.getenv("ENABLE_OBSERVABILITY", "true").lower() == "true"
        self.session_id = f"monitoring_session_{int(time.time())}_{str(uuid.uuid4())[:8]}"
        self.actor_id = f"actor_{int(time.time())}"
        
        if self.enabled and OTEL_AVAILABLE:
            self._setup_session_context()
    
    def _setup_session_context(self):
        """Set up OpenTelemetry baggage for session tracking"""
        try:
            ctx = baggage.set_baggage("session.id", self.session_id)
            ctx = baggage.set_baggage("user.id", self.actor_id) 
            ctx = baggage.set_baggage("service.name", self.service_name)
            context.attach(ctx)
            logger.info(f"Session context set: {self.session_id}")
        except Exception as e:
            logger.warning(f"Failed to set session context: {e}")
    
    def get_observability_status(self):
        if not self.enabled:
            return "Disabled"
        if not OTEL_AVAILABLE:
            return "OpenTelemetry not available - install aws-opentelemetry-distro"
        return f"Enabled with session: {self.session_id}"
    
    def get_session_id(self):
        return self.session_id
    
    def get_actor_id(self):
        return self.actor_id

class AgentObservabilityHooks:
    def __init__(self, agent_name):
        self.agent_name = agent_name
    
    def register_hooks(self, hook_registry):
        """Register hooks with the hook registry"""
        pass
    
    def get_hook_status(self):
        return f"Simple hooks for {self.agent_name}"

def init_observability(service_name, region_name, log_group_name):
    return SimpleObservability(service_name)

def get_observability():
    return _observability_instance

def shutdown_observability():
    pass

def create_cloudwatch_log_group(log_group_name="/aws/monitoring-agent/traces", region_name=REGION_NAME):
    """Create CloudWatch log group if it doesn't exist"""
    try:
        logs_client = boto3.client('logs', region_name=region_name)
        
        # Check if log group exists
        try:
            existing_groups = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)['logGroups']
            if any(group['logGroupName'] == log_group_name for group in existing_groups):
                logger.info(f"✅ Log group {log_group_name} already exists")
                return True
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                raise
        
        # Create log group
        logger.info(f"📝 Creating CloudWatch log group: {log_group_name}")
        logs_client.create_log_group(
            logGroupName=log_group_name
        )
        logger.info(f"✅ Successfully created log group: {log_group_name}")
        return True
        
    except ClientError as e:
        logger.error(f"❌ Error creating log group: {e}")
        return False
    except Exception as e:
        logger.error(f"❌ Unexpected error creating log group: {e}")
        return False

def configure_agentcore():
    """Configure agentcore with the monitoring agent entrypoint"""
    try:
        logger.info("🔧 Configuring agentcore with monitoring_agent.py entrypoint...")
        
        # Run agentcore configure command
        cmd = ['agentcore', 'configure', '--entrypoint', 'monitoring_agent.py', '-er', EXECUTION_ROLE_ARN]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        logger.info("✅ AgentCore configuration successful:")
        logger.info(result.stdout)
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ AgentCore configuration failed: {e}")
        if e.stderr:
            logger.error(f"Stderr: {e.stderr}")
        if e.stdout:
            logger.error(f"Stdout: {e.stdout}")
        return False
    except FileNotFoundError:
        logger.error("❌ 'agentcore' command not found. Please ensure AgentCore CLI is installed.")
        return False

# set a logger
logging.basicConfig(format='[%(asctime)s] p%(process)s {%(filename)s:%(lineno)d} %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Load the config file. 
config_data = load_config(f'../{CONFIG_FNAME}')
logger.info(f"Loaded config from local file system: {json.dumps(config_data, indent=2)}")
from typing import Dict, List

# ────────────────────────────────────────────────────────────────────────────────────
# OBSERVABILITY INITIALIZATION
# ────────────────────────────────────────────────────────────────────────────────────

# Initialize simple observability system
_observability_instance = None
try:
    _observability_instance = init_observability(
        service_name="monitoring-agent",
        region_name=REGION_NAME,
        log_group_name="/aws/monitoring-agent/traces"
    )
    logger.info(f"✅ Observability initialized: {_observability_instance.get_observability_status()}")
except Exception as e:
    logger.warning(f"⚠️ Failed to initialize observability: {e}")
    logger.info("Continuing without observability features...")

# ────────────────────────────────────────────────────────────────────────────────────
# AGENTCORE MEMORY PRIMITIVE INITIALIZATION
# ────────────────────────────────────────────────────────────────────────────────────

# initialize the memory client
client = MemoryClient(region_name=REGION_NAME)

# Read the custom extraction prompt
with open(f'../{MONITORING_CUSTOM_EXTRACTION_PROMPT_FPATH}', 'r') as f:
    CUSTOM_EXTRACTION_PROMPT = f.read()

# Read the custom consolidation prompt  
with open(f'../{MONITORING_CONSOLIDATION_EXTRACTION_PROMPT_FPATH}', 'r') as f:
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
                "summaryMemoryStrategy": {
                    "name": "SessionSummarizer",
                    "namespaces": ["/summaries/{actorId}/"]
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
                event_expiry_days=90
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

# Create memory hooks instance - use observability session/actor IDs if available
session_id = _observability_instance.get_session_id() if _observability_instance else f"monitoring_session_{int(time.time())}"
actor_id = _observability_instance.get_actor_id() if _observability_instance else f'default_actor_{int(time.time())}'

monitoring_hooks = MonitoringMemoryHooks(
    memory_id=memory_id,
    client=client,
    actor_id=config_data['agent_information']['monitoring_agent_model_info'].get('memory_allocation').get('actor_id', actor_id),
    session_id=session_id
)
print(f"created the memory hook: {monitoring_hooks}")

# Create observability hooks instance
try:
    observability_hooks = AgentObservabilityHooks(agent_name="monitoring-agent")
    logger.info(f"✅ Observability hooks initialized: {observability_hooks.get_hook_status()}")
except Exception as e:
    logger.warning(f"⚠️ Failed to initialize observability hooks: {e}")
    observability_hooks = None

# We will be using this hook in the agent creation process
logger.info(f"Going to create the memory gateway for this agent....")

# Create gateway using the enhanced AgentCore Gateway setup
monitoring_agent_config = config_data['agent_information']['monitoring_agent_model_info']
gateway_config_info = monitoring_agent_config.get('gateway_config', {})
# if there are any pre configured gateway credentials, they will be used here
gateway_credentials = gateway_config_info.get('credentials', {})

print("Setting up AgentCore Gateway from configuration...")

# Function to validate credentials
def validate_credentials(credentials_dict):
    """Validate that credentials dict contains all required fields"""
    required_fields = ['gateway_id', 'mcp_url', 'access_token']
    return all(field in credentials_dict and credentials_dict[field] for field in required_fields)

def refresh_access_token():
    """
    Find existing Cognito setup and create a new access token
    """
    print("🔍 Searching for existing Cognito user pools to refresh token...")
    
    cognito = boto3.client("cognito-idp", region_name=REGION_NAME)
    # Expected names based on the code patterns
    expected_pool_names = [
        "monitoring-agentcore-gateway-pool",
        "sample-agentcore-gateway-pool", 
        "MCPServerPool"
    ]
    user_pool_id = None
    client_id = None
    client_secret = None
    resource_server_id = None
    
    # Check for existing user pools
    try:
        pools_response = cognito.list_user_pools(MaxResults=60)
        for pool in pools_response.get('UserPools', []):
            pool_name = pool['Name']
            if any(expected_name in pool_name for expected_name in expected_pool_names):
                user_pool_id = pool['Id']
                print(f"✅ Found user pool: {pool_name} (ID: {user_pool_id})")
                break
                
        if not user_pool_id:
            print("❌ No matching user pools found. Cannot refresh token.")
            return None
            
        # Find resource server and client
        try:
            # Try different resource server IDs
            expected_resource_ids = [
                "monitoring-agentcore-gateway-id",
                "sample-agentcore-gateway-id"
            ]
            
            for resource_id in expected_resource_ids:
                try:
                    resource_response = cognito.describe_resource_server(
                        UserPoolId=user_pool_id,
                        Identifier=resource_id
                    )
                    resource_server_id = resource_id
                    print(f"✅ Found resource server: {resource_server_id}")
                    break
                except cognito.exceptions.ResourceNotFoundException:
                    continue
                    
            if not resource_server_id:
                print("❌ No resource server found")
                return None
                
            # Find client
            clients_response = cognito.list_user_pool_clients(UserPoolId=user_pool_id, MaxResults=60)
            expected_client_names = [
                "monitoring-agentcore-gateway-client",
                "sample-agentcore-gateway-client",
                "MCPServerPoolClient"
            ]
            
            for client in clients_response.get('UserPoolClients', []):
                client_name = client['ClientName']
                if any(expected_name in client_name for expected_name in expected_client_names):
                    client_details = cognito.describe_user_pool_client(
                        UserPoolId=user_pool_id, 
                        ClientId=client['ClientId']
                    )
                    client_id = client['ClientId']
                    client_secret = client_details['UserPoolClient'].get('ClientSecret')
                    print(f"✅ Found client: {client_name} (ID: {client_id})")
                    break
                    
            if not client_id:
                print("❌ No matching client found")
                return None
                
        except Exception as e:
            print(f"❌ Error finding resource server or client: {e}")
            return None
            
    except Exception as e:
        print(f"❌ Error listing user pools: {e}")
        return None
    
    # Generate new token
    if user_pool_id and client_id and client_secret and resource_server_id:
        print("🔄 Generating new access token...")
        scope_string = f"{resource_server_id}/gateway:read {resource_server_id}/gateway:write"
        
        try:
            token_response = get_token(user_pool_id, client_id, client_secret, scope_string, REGION_NAME)
            
            if "access_token" in token_response:
                print("✅ Successfully generated new access token!")
                return token_response["access_token"]
            else:
                print(f"❌ Failed to generate token: {token_response}")
                return None
                
        except Exception as e:
            print(f"❌ Error generating token: {e}")
            return None
    else:
        print("❌ Missing required Cognito credentials")
        return None

# Check for existing credentials in multiple sources
mcp_url = None
access_token = None
gateway_id = None

# Priority 1: Check JSON credentials file (now in root directory)
# This json file will contain contains information about the gateway such as the access
# token fetched from connecting to Cognito to connect to the gateway
root_credentials_path = f"../{MONITORING_GATEWAY_CREDENTIALS_PATH}"
if os.path.exists(root_credentials_path) and gateway_credentials.get('use_existing'):
    try:
        with open(root_credentials_path, 'r') as cred_file:
            json_credentials = json.load(cred_file)
            if validate_credentials(json_credentials):
                mcp_url = json_credentials['mcp_url']
                access_token = json_credentials['access_token']
                gateway_id = json_credentials['gateway_id']
                print(f"Using existing gateway credentials from {root_credentials_path}")
                
                # Check if token might be expired (created more than 1 hour ago)
                created_at = json_credentials.get('created_at', 0)
                current_time = time.time()
                if current_time - created_at > 3600:  # 1 hour
                    print("⚠️ Access token is older than 1 hour, attempting refresh...")
                    # In this case, we refresh to get a new token to connect to the 
                    # MCP gateway if the token is expired
                    new_token = refresh_access_token()
                    if new_token:
                        access_token = new_token
                        # Update the credentials file
                        json_credentials['access_token'] = new_token
                        json_credentials['updated_at'] = current_time
                        with open(root_credentials_path, 'w') as cred_file:
                            json.dump(json_credentials, cred_file, indent=4)
                        print("✅ Updated credentials with new access token")
    except Exception as e:
        print(f"Error reading JSON credentials file: {e}")

# Priority 2: Check config file credentials (if JSON file didn't work)
if not mcp_url:
    use_existing_credentials = gateway_credentials.get('use_existing', False)
    existing_gateway_id = gateway_credentials.get('gateway_id')
    existing_mcp_url = gateway_credentials.get('mcp_url')
    existing_access_token = gateway_credentials.get('access_token')
    
    if use_existing_credentials and existing_gateway_id and existing_mcp_url and existing_access_token:
        mcp_url = existing_mcp_url
        access_token = existing_access_token
        gateway_id = existing_gateway_id
        print("Using existing gateway credentials from config file...")

if mcp_url and access_token and gateway_id:
    print(f"Gateway ID: {gateway_id}")
    print(f"MCP Server URL: {mcp_url}")
else:
    try:
        # Gateway configuration
        gateway_name = gateway_config_info.get('name', 'MonitoringGateway')
        # Step 1: Create IAM role using utils.py function
        print("Creating IAM role...")
        role_name = f"{gateway_name}Role"
        # First, create the agentcore role for smithy models, this will contain permissions to 
        # allow all access to bedrock bedrockcore, bedrock, agent credential provider, pass role, 
        # secrets manager, lambda functions and s3.
        agentcore_gateway_iam_role = create_agentcore_gateway_role_s3_smithy(role_name)
        role_arn = agentcore_gateway_iam_role['Role']['Arn']
        print(f"IAM role created: {role_arn}")
        # Step 2: Setup Cognito
        print("Setting up Cognito...")
        inbound_auth_config: Dict = gateway_config_info.get('inbound_auth')
        cognito_config: Dict = inbound_auth_config.get('cognito')
        logger.info(f"Going to use the inbound auth mechanism through cognito: {cognito_config}")
        USER_POOL_NAME = cognito_config.get('user_pool_name', "monitoring-agentcore-gateway-pool")
        RESOURCE_SERVER_ID = cognito_config.get('resource_server_id', "monitoring_agent2039")
        RESOURCE_SERVER_NAME = cognito_config.get('resource_server_name', "agentcore-gateway2039")
        # Flag to check for if a user pool needs to be created or not
        CREATE_USER_POOL: bool = cognito_config.get('create_user_pool', False)
        logger.info(f"Going to create the user pool: {CREATE_USER_POOL}")
        CLIENT_NAME = cognito_config.get('client_name', "agentcore-gateway-client")
        SCOPES = cognito_config.get('scopes')
        logger.info(f"Going to use the following scopes from the config file: {SCOPES} for the monitoring agent.")
        scope_string = f"{RESOURCE_SERVER_ID}/gateway:read {RESOURCE_SERVER_ID}/gateway:write"
        cognito = boto3.client("cognito-idp", region_name=REGION_NAME)
        # This fetches the user pool id if the given name exists or not, and if not then it creates a user
        # pool with the name
        user_pool_id = get_or_create_user_pool(cognito, USER_POOL_NAME, CREATE_USER_POOL)
        print(f"User Pool ID: {user_pool_id}")
        # This function gets or creates a cognito resource server within an existing user pool, ensuring that
        # it has the specified scopes that are mentioned here from the config file.
        get_or_create_resource_server(cognito, user_pool_id, RESOURCE_SERVER_ID, RESOURCE_SERVER_NAME, SCOPES)
        print("Resource server ensured.")
        # This is machine to machine authentication, where this function first lists the user pools, and then
        # if it is found then describes it and returns the auth client ID and secret id, else it creates one and 
        # then returns it.
        client_id, client_secret = get_or_create_m2m_client(cognito, user_pool_id, CLIENT_NAME, RESOURCE_SERVER_ID)
        print(f"Client ID: {client_id}")
        cognito_discovery_url = COGNITO_DISCOVERY_URL.format(region=REGION_NAME, 
                                                             user_pool_id=user_pool_id)
        logger.info(f"Going to use the cognito discovery URL: {cognito_discovery_url}")
        # Step 3: Create Gateway
        print("Creating gateway...")
        gateway_client = boto3.client('bedrock-agentcore-control', region_name=REGION_NAME)
        auth_config = {
            "customJWTAuthorizer": { 
                "allowedClients": [client_id],
                "discoveryUrl": cognito_discovery_url
            }
        }
        try:
            # The first step is to create the gateway with the gateway name, role, protocol type is 
            # MCP and authorizer is CUSTOM_JWT and then we pass in our auth as inbound auth for the
            # agent to access the gateway first
            create_response = gateway_client.create_gateway(
                name=gateway_name,
                roleArn=role_arn,
                protocolType=MCP_PROTOCOL,
                authorizerType=AUTH_TYPE_CUSTOM_JWT,
                authorizerConfiguration=auth_config, 
                description='AgentCore Gateway with target for monitoring tools'
                # Add observability to the gateway
                # observability_config={        
                #     "cloudwatch_metrics_enabled": True,
                #     "xray_enabled": True
                # }
            )
            gateway_id = create_response["gatewayId"]
            mcp_url = create_response["gatewayUrl"]
            print(f"Gateway created: {gateway_id}")
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
                
                # List existing gateways to find the one with our name
                try:
                    list_response = gateway_client.list_gateways()
                    logger.info(f"The gateways that are available in {REGION_NAME} are: {list_response}")
                    existing_gateway = None
                    # Search for gateway by name (try both config name and error name)
                    search_names = [gateway_name]
                    if gateway_name_from_error and gateway_name_from_error != gateway_name:
                        search_names.append(gateway_name_from_error)
                    print(f"Searching for gateways with names: {search_names}")
                    paginator = gateway_client.get_paginator('list_gateways')
                    existing_gateway = None

                    for page in paginator.paginate():
                        for g in page.get('items', []):
                            if g['name'] == gateway_name:
                                existing_gateway = g
                                break
                        if existing_gateway:
                            break
                    
                    if existing_gateway:
                        gateway_id = existing_gateway['gatewayId']
                        # Get the gateway URL using the gateway ID
                        try:
                            get_response = gateway_client.get_gateway(gatewayIdentifier=gateway_id)
                            mcp_url = get_response['gatewayUrl']
                            print(f"✅ Using existing gateway: {gateway_id}")
                            print(f"Gateway URL: {mcp_url}")
                        except Exception as get_error:
                            print(f"Error getting gateway details: {get_error}")
                            raise e
                    else:
                        print(f"Could not find existing gateway with any of these names: {search_names}")
                        print("Available gateways:")
                        for gw in list_response.get('items', []):
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
        # Step 5: Get access token
        print("Getting access token...")
        token_response = get_token(user_pool_id, client_id, client_secret, scope_string, REGION_NAME)
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

MONITORING_AGENT_SYSTEM_PROMPT: str = """
You are the monitoring agent responsible for analyzing AWS resources, including CloudWatch logs, alarms, and dashboards. Your tasks include:
    IMPORTANT:
        Follow the instructions carefully and use the tools as needed:
        - Your first question should be to ask the user for which account they want to monitor: their own or a cross-account.
        - If the user says "my account", use the default account.
        - If the user says "cross account", ask for the account_id and role_name to assume the role in that account.
        - If the user doesn't provide an account, always ask for this.
        - use the account id and role_name parameters in the tools you call as strings if provided.
        
    1. **List Available CloudWatch Dashboards:**
       - Utilize the `list_cloudwatch_dashboards` tool to retrieve a list of all CloudWatch dashboards in the AWS account.
       - Provide the user with the names and descriptions of these dashboards, offering a brief overview of their purpose and contents.

    2. **Fetch Recent CloudWatch Logs for Requested Services:**
       - When a user specifies a service (e.g., EC2, Lambda, RDS), use the `fetch_cloudwatch_logs_for_service` tool to retrieve the most recent logs for that service.
       - Analyze these logs to identify any errors, warnings, or anomalies.
       - Summarize your findings, highlighting any patterns or recurring issues, and suggest potential actions or resolutions.

    3. **Retrieve and Summarize CloudWatch Alarms:**
       - If the user inquires about alarms or if log analysis indicates potential issues, use the `get_cloudwatch_alarms_for_service` tool to fetch relevant alarms.
       - Provide details about active alarms, including their state, associated metrics, and any triggered thresholds.
       - Offer recommendations based on the alarm statuses and suggest possible remediation steps.

    4. **Analyze Specific CloudWatch Dashboards:**
       - When a user requests information about a particular dashboard, use the `get_dashboard_summary` tool to retrieve and summarize its configuration.
       - Detail the widgets present on the dashboard, their types, and the metrics or logs they display.
       - Provide insights into the dashboard's focus areas and how it can be utilized for monitoring specific aspects of the AWS environment.
    
    5. **List and Explore CloudWatch Log Groups:**
       - Use the `list_log_groups` tool to retrieve all available CloudWatch log groups in the AWS account.
       - Help the user navigate through these log groups and understand their purpose.
       - When a user is interested in a specific log group, explain its contents and how to extract relevant information.
   
    6. **Analyze Specific Log Groups in Detail:**
       - When a user wants to gain insights about a specific log group, use the `analyze_log_group` tool.
       - Summarize key metrics like event count, error rates, and time distribution.
       - Identify common patterns and potential issues based on log content.
       - Provide actionable recommendations based on the observed patterns and error trends.

    7. **Cross-Account Access:**
       - Support monitoring of resources across multiple AWS accounts
       - When users mention a specific account or ask for cross-account monitoring, ask them for:
           * The AWS account ID (12-digit number)
           * The IAM role name with necessary CloudWatch permissions 
       - Use the `setup_cross_account_access` tool to verify access before proceeding
       - Pass the account_id and role_name parameters to the appropriate tools
       - Always include account context information in your analysis and reports
       - If there are issues with cross-account access, explain them clearly to the user

    **Guidelines:**

    - Always begin by asking the USER FOR WHICH ACCOUNT THEY WANT TO MONITOR: THEIR OWN ACCOUNT OR A CROSS-ACCOUNT.
    - If the user wants to monitor their own account, use the default AWS credentials.
    - If the user wants to monitor a cross-account, ask for the account ID and role name ALWAYS. 
    - When analyzing logs or alarms, be thorough yet concise, ensuring clarity in your reporting.
    - Avoid making assumptions; base your analysis strictly on the data retrieved from AWS tools.
    - Clearly explain the available AWS services and their monitoring capabilities when prompted by the user.
    - For cross-account access, if the user mentions another account but doesn't provide the account ID or role name, ask for these details before proceeding.

    **Available AWS Services for Monitoring:**

    - **EC2/Compute Instances** [ec2]
    - **Lambda Functions** [lambda]
    - **RDS Databases** [rds]
    - **EKS Kubernetes** [eks]
    - **API Gateway** [apigateway]
    - **CloudTrail** [cloudtrail]
    - **S3 Storage** [s3]
    - **VPC Networking** [vpc]
    - **WAF Web Security** [waf]
    - **Bedrock** [bedrock/generative AI]
    - **IAM Logs** [iam] (Use this option when users inquire about security logs or events.)
    - Any other AWS service the user requests - the system will attempt to create a dynamic mapping

    **Cross-Account Monitoring Instructions:**
    
    When a user wants to monitor resources in a different AWS account:
    1. Ask for the AWS account ID (12-digit number)
    2. Ask for the IAM role name with necessary permissions
    3. Use the `setup_cross_account_access` tool to verify the access works
    4. If successful, use the account_id and role_name parameters with the monitoring tools
    5. Always specify which account you're reporting on in your analysis
    6. If cross-account access fails, provide the error message and suggest checking:
       - That the role exists in the target account
       - That the role has the necessary permissions
       - That the role's trust policy allows your account to assume it

    Your role is to assist users in monitoring and analyzing their AWS resources effectively, providing actionable insights based on the data available.
"""

# Create a bedrock model using the BedrockModel interface
monitoring_agent_info: str = config_data['agent_information']['monitoring_agent_model_info']
bedrock_model = BedrockModel(
    model_id=monitoring_agent_info.get('model_id'),
    region_name=REGION_NAME,
    temperature=monitoring_agent_info['inference_parameters'].get('temperature'),
    max_tokens=monitoring_agent_info['inference_parameters'].get('max_tokens')
)
print(f"Initialized the bedrock model for the finance agent: {bedrock_model}")

# Add imports for the agentcore runtime
from bedrock_agentcore.runtime import BedrockAgentCoreApp
import httpx

def basic_genesis_strands_agent(user_message: str):
    """
    Basic agent implementation using Strands framework
    This function creates and runs the monitoring agent
    """
    # Create agent with MCP tools from Gateway
    # Set up MCP client to connect to the AgentCore Gateway
    from strands.tools.mcp.mcp_client import MCPClient
    from mcp.client.streamable_http import streamablehttp_client 

    def create_streamable_http_transport():
        """
        This is the client to return a streamablehttp access token
        """
        return streamablehttp_client(mcp_url, headers={"Authorization": f"Bearer {access_token}"})

    # Create MCP client
    mcp_client = MCPClient(create_streamable_http_transport)

    # Use the MCP client in context manager to get tools
    print(f"Starting the MCP session for the monitoring agent...")
    with mcp_client:
        # Get tools from the Gateway (these are the OpenAPI tools converted to MCP)
        print(f"Going to list tools from the MCP client")
        try:
            gateway_tools = mcp_client.list_tools_sync()
            print(f"Loaded {len(gateway_tools)} tools from Gateway: {[tool for tool in gateway_tools]}")
        except Exception as tools_error:
            print(f"❌ Error listing tools from Gateway MCP server: {tools_error}")
            print(f"   This usually means the Gateway server returned an invalid response")
            print(f"   Expected format: {{'tools': [...]}}, but got empty result: {{}}")
            print(f"   Falling back to no Gateway tools - agent will run without MCP tools")
            gateway_tools = []
        
        # Create agent with Gateway MCP tools + memory hooks + observability hooks
        hooks = [monitoring_hooks]
        if observability_hooks:
            hooks.append(observability_hooks)
        
        agent = Agent(
            system_prompt=MONITORING_AGENT_SYSTEM_PROMPT,
            model=bedrock_model,
            hooks=hooks,
            tools=gateway_tools
        )
        
        print(f"✅ Created monitoring agent with Gateway MCP tools!")
        
        # Process the user input through the agent
        try:
            response = agent(user_message)
            return response
        except Exception as agent_error:
            logger.error(f"Agent error: {agent_error}")
            raise agent_error

def invoke_remote_agent(endpoint_url: str, user_message: str):
    """
    Invoke a remote agent via HTTP endpoint
    """
    try:
        payload = {"prompt": user_message}
        with httpx.Client() as client:
            response = client.post(
                f"{endpoint_url}/invocations",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=300.0
            )
            response.raise_for_status()
            result = response.json()
            return type('Response', (), {'message': result.get('result', 'No response')})()
    except Exception as e:
        logger.error(f"Error invoking remote agent: {e}")
        raise

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

# Check for remote agent endpoint in config
remote_agent_url = config_data.get('agent_information').get('monitoring_agent_model_info').get('remote_endpoint_url')
logger.info(f"Going to use the remote agent runtime for the monitoring: {remote_agent_url}")

# Check for AgentCore runtime configuration
gateway_config = config_data.get('agent_information', {}).get('monitoring_agent_model_info', {}).get('gateway_config', {})
runtime_exec_role = gateway_config.get('runtime_exec_role')
launch_agentcore_runtime = gateway_config.get('launch_agentcore_runtime', False)

logger.info(f"Runtime execution role: {runtime_exec_role}")
logger.info(f"Launch AgentCore runtime: {launch_agentcore_runtime}")

# Initialize app for agentcore runtime only if conditions are met
app = None
if runtime_exec_role and launch_agentcore_runtime:
    logger.info("✅ AgentCore runtime conditions met - initializing RuntimeClient")
    app = BedrockAgentCoreApp()
else:
    logger.info("ℹ️  AgentCore runtime conditions not met - running in local mode only")

def invoke(payload):
    '''
    This is the function that is used as an entrypoint function
    to invoke the agent. This agent can be built using LangGraph, 
    Strands or Bedrock agents, or any other framework for that matter.
    This runtime is agent framework agnostic.
    '''
    user_message = payload.get("prompt", "You are a monitoring agent to help with AWS monitoring related queries.")
    print(f"Going to invoke the agent with the following prompt: {user_message}")
    
    # Check if remote endpoint is configured
    if remote_agent_url:
        print(f"Using remote agent endpoint: {remote_agent_url}")
        response = invoke_remote_agent(remote_agent_url, user_message)
    else:
        print("Using local agent implementation")
        response = basic_genesis_strands_agent(user_message)
    
    return {"result": response.message}

# Register entrypoint only if app is initialized
if app:
    app.entrypoint(invoke)

# Running this starts a service 
# The server starts at http://localhost:8080
# Test with curl:
# curl -X POST http://localhost:8080/invocations \
# -H "Content-Type: application/json" \
# -d '{"prompt": "Hello world!"}'

# Next steps for AgentCore deployment:
# 
# 1. Ensure this agent code is in a repository with:
#    - monitoring_agent.py (this file)
#    - requirements.txt (with all dependencies)
#    - __init__.py (empty file)
#
# 2. Create an IAM execution role with permissions for:
#    - Amazon Bedrock access
#    - CloudWatch logs/metrics access
#    - Any other AWS services the agent needs
#
# 3. Configure the agent using agentcore CLI:
#    agentcore configure --entrypoint monitoring_agent.py -er <YOUR_IAM_ROLE_ARN>
#    
#    Example:
#    agentcore configure --entrypoint monitoring_agent.py \
#        -er arn:aws:iam::123456789012:role/service-role/Amazon-Bedrock-IAM-Role
#
# 4. Deploy options:
#    
#    OPTION A - Launch locally:
#    agentcore launch -l
#    # This builds a docker image and runs it locally at localhost:8080
#    
#    OPTION B - Launch to AWS cloud:
#    agentcore launch
#    # This builds docker image, pushes to ECR, creates agentcore runtime, and deploys
#
# 5. Make sure your requirements.txt contains all packages needed:
#    - strands
#    - boto3
#    - bedrock-agentcore-starter-toolkit
#    - python-dotenv
#    - httpx
#    - opentelemetry-distro[otlp] (if using observability)
#
# 6. IMPORTANT - Trust Policy for IAM Role:
#    Your IAM execution role must have a trust policy that allows:
#    - bedrock.amazonaws.com
#    - bedrock-agentcore.amazonaws.com
#    
#    Example trust policy:
#    {
#      "Version": "2012-10-17",
#      "Statement": [
#        {
#          "Effect": "Allow",
#          "Principal": {
#            "Service": [
#              "bedrock.amazonaws.com",
#              "bedrock-agentcore.amazonaws.com"
#            ]
#          },
#          "Action": "sts:AssumeRole"
#        }
#      ]
#    }

if __name__ == "__main__":
    # Check if AgentCore runtime should be launched
    if runtime_exec_role and launch_agentcore_runtime and app:
        print(f"\n🚀 Setting up AgentCore runtime with execution role: {runtime_exec_role}")
        
        # Step 1: Create CloudWatch log group
        print("Step 1: Creating CloudWatch log group...")
        create_cloudwatch_log_group()
        
        # Step 2: Configure agentcore
        print("Step 2: Configuring agentcore...")
        if not configure_agentcore():
            print("❌ AgentCore configuration failed. Cannot proceed with launch.")
            sys.exit(1)
        
        # Step 3: Launch agentcore
        print("Step 3: Launching agentcore...")
        print("Running: agentcore launch")
        print("# This builds docker image, pushes to ECR, creates agentcore runtime, and deploys")
        
        # Run the agentcore launch command
        try:
            result = subprocess.run(['agentcore', 'launch'], 
                                  capture_output=True, text=True, check=True)
            print(f"✅ AgentCore launch successful:")
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"❌ AgentCore launch failed:")
            print(f"Error: {e}")
            print(f"Stderr: {e.stderr}")
            print(f"Stdout: {e.stdout}")
        except FileNotFoundError:
            print("❌ 'agentcore' command not found. Please ensure AgentCore CLI is installed.")
    
    elif remote_agent_url:
        print(f"\n🌐 Remote agent endpoint configured: {remote_agent_url}")
        print("Starting agentcore runtime server...")
        if app:
            app.run()
    else:
        print("\n🏠 No remote endpoint configured, running local interactive mode...")
        # Interactive terminal chat loop
        print("\n" + "="*60)
        print("🤖 AWS Monitoring Agent - Interactive Terminal Chat")
        print("="*60)
        print("Type 'exit', 'quit', or 'q' to end the session")
        print("Type 'help' for available commands")
        print("-"*60)
        
        while True:
            try:
                # Get user input
                user_input = input("\n👤 You: ").strip()
                
                # Check for exit commands
                if user_input.lower() in ['exit', 'quit', 'q']:
                    print("\n👋 Goodbye! Monitoring session ended.")
                    break
                
                # Check for help command
                if user_input.lower() == 'help':
                    print("\n📚 Available commands:")
                    print("• Ask about CloudWatch logs, alarms, or dashboards")
                    print("• Request monitoring for specific AWS services")
                    print("• Ask for cross-account monitoring (provide account ID and role)")
                    print("• Type 'exit', 'quit', or 'q' to end the session")
                    continue
                
                # Skip empty input
                if not user_input:
                    continue
                
                # Process the user input through the agent
                print("\n🤖 Agent: ", end="", flush=True)
                
                # Process agent request - automatic tracing via opentelemetry-instrument
                try:
                    response = basic_genesis_strands_agent(user_input)
                    
                except Exception as agent_error:
                    logger.error(f"Agent error: {agent_error}")
                    raise agent_error
                
                print(f"\n{response}")
                
            except KeyboardInterrupt:
                print("\n\n👋 Session interrupted. Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ Error: {e}")
                print("Please try again or type 'exit' to end the session.")
        
        # Cleanup observability on exit
        try:
            shutdown_observability()
            logger.info("✅ Observability shutdown complete")
        except Exception as e:
            logger.warning(f"⚠️ Error during observability shutdown: {e}")
