# This is the second agent in this solution. This agent is a stand alone agent that can work
# in itself and through communication with the "monitoring agent through A2A". This agent is called
# the ops orchestrator agent. This agent, based on the prior logs, metrics, alarms and errors rely on
# three main tasks: 

# 1. Automated incident triaging: This agent directly logs with Pager Duty and JIRA. This agent is responsible
# for creating user tickets on incidents, tasks and reports on both pager duty and JIRA. We will see how this is possible
# with agent identity and security in place using agentcore.

# 2. Chat Ops collaboration: This agent deeply integrates with teams, slack and gmail, to help communicate the live status of any
# reports, incident and logs that are logged in these services up above, or as directly coordinated by the admin through the agent

# 3. Reports creation: This agent also finally creates github where it stores the code for the live and changing status of the reports
# through the changes in the aws account, JIRA, pager duty or any other service that the agent uses.
# NOTE: AgentCore Runtime configuration has been moved to agent_runtime.py for better separation of concerns.
# This file focuses on the agent logic and MCP gateway interaction only.
# import logging and set a logger for strands
# install other requirements

# In this example, we will build a multi agent collaboration system where there will be three openAI agents:
# 1. One of the agents will be responsible for automated incident triaging, 
# 2. Another agent will be the chatops agent and the 
# 3. Third agent will be responsible for writing and maintaining reports.
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
import asyncio
from datetime import datetime
from dotenv import load_dotenv
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
# Load environment variables first
load_dotenv()

# Disable OpenAI tracing to prevent span_data.result errors
import os
os.environ["OPENAI_ENABLE_TRACING"] = "false"

from bedrock_agentcore.memory import MemoryClient
# This will help set up for strategies that can then be used 
# across the code - user preferences, semantic memory or even
# summarizations across the sessions along with custom strategies
# for this monitoring agent
from bedrock_agentcore.memory.constants import StrategyType
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
# Import Cognito authentication setup from utils
from bedrock_agentcore_starter_toolkit.operations.gateway import GatewayClient
# These are openAI tools created to extract from, retrieve, store and manage memory through
# the amazon bedrock agentcore service
from openAI_memory_tools import create_memory_tools

# define openAI specific import statements
from agents import Agent, Runner

# Add a handler to see the logs
logging.basicConfig(
    format="%(levelname)s | %(name)s | %(message)s", 
    handlers=[logging.StreamHandler()]
)
sys.path.insert(0, ".")
sys.path.insert(1, "..")
from utils import *
from constants import *
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
        self.session_id = f"ops_operating_session_{int(time.time())}_{str(uuid.uuid4())[:8]}"
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

def create_cloudwatch_log_group(log_group_name="/aws/bedrock-log-group", region_name=REGION_NAME):
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


# set a logger
logging.basicConfig(format='[%(asctime)s] p%(process)s {%(filename)s:%(lineno)d} %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Load the config file. 
config_data = load_config('config.yaml')
print(f"Loaded config from local file system: {json.dumps(config_data, indent=2)}")
from typing import Dict, List

# ────────────────────────────────────────────────────────────────────────────────────
# OBSERVABILITY INITIALIZATION
# ────────────────────────────────────────────────────────────────────────────────────

# Initialize simple observability system
_observability_instance = None
try:
    # Create the CloudWatch log group first
    log_group_name = "/aws/bedrock-log-group"
    create_cloudwatch_log_group(log_group_name, REGION_NAME)
    
    _observability_instance = init_observability(
        service_name="ops_orchestrator-agent",
        region_name=REGION_NAME,
        log_group_name=log_group_name
    )
    print(f"✅ Observability initialized: {_observability_instance.get_observability_status()}")
except Exception as e:
    print(f"⚠️ Failed to initialize observability: {e}")
    print("Continuing without observability features...")

# ────────────────────────────────────────────────────────────────────────────────────
# AGENTCORE MEMORY PRIMITIVE INITIALIZATION
# ────────────────────────────────────────────────────────────────────────────────────

# first, initialize the memory client
openai_mem_client = MemoryClient(region_name=REGION_NAME)
print(f"Initialized the OpenAI memory client using the bedrock AgentCore memory primitive: {openai_mem_client}")

# Next, we will have to configure a couple of common memories for our agent. These are namely
# the user preferences, semantic memory, summarize memory and also incident response
# triaging memory for the lead agent. We will configure memory for the lead memory to be used
# and stored in bedrock agentcore

def read_prompt_file(filepath: str) -> str:
    with open(filepath, 'r') as f:
        return f.read()

# Usage
CUSTOM_EXTRACTION_PROMPT_LEAD_AGENT = read_prompt_file(OPS_ORCHESTRATOR_CUSTOM_EXTRACTION_PROMPT_FPATH)
TICKET_CREATOR_MEMORY_PROMPT = read_prompt_file(OPS_TICKET_CREATOR_MEMORY_PROMPT_FPATH)
CHAT_REPORT_MEMORY_PROMPT = read_prompt_file(OPS_CHAT_REPORT_MEMORY_PROMPT_FPATH)
print(f"Going to be using the customer extraction prompt for user preferences: {CUSTOM_EXTRACTION_PROMPT_LEAD_AGENT}")
print(f"Going to be using the ticket creator memory prompt: {TICKET_CREATOR_MEMORY_PROMPT}")
print(f"Going to be using the chat ops memory creator prompt: {CHAT_REPORT_MEMORY_PROMPT}")

# this is the flag to check if the existing memory needs to be used or not
# if there is a memory that is already created and existing, you can flag this in the config file as true
create_memories: bool = config_data['agent_information']['ops_orchestrator_agent_model_info'].get('use_existing_memory')
existing_memory_id: bool = config_data['agent_information']['ops_orchestrator_agent_model_info'].get('existing_memory_id')
# set the memory id and memory to none for now
memory_id = None
memory = None

# if the use existing memory or the existing memory id is provided, then use it
# in the agent configuration
if create_memories:
    print(f"Going to be using the existing memory from the configuration file with id: {existing_memory_id}")
    memory = {'id': existing_memory_id}
    memory_id = existing_memory_id
# if these are not provided then we will create a new memory that we will be able to 
# use with our openAI agents
lead_agent_strategy = [
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
            "namespaces": ["/summaries/{actorId}/{sessionId}"]
        }
    },
    {
        "customMemoryStrategy": {
            "name": "IssueTriagingMemStrategy",
            "namespaces": ["/technical-issues/{actorId}"],
            "configuration": {
                "semanticOverride": {
                    "extraction": {
                        "modelId": "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
                        "appendToPrompt": CUSTOM_EXTRACTION_PROMPT_LEAD_AGENT
                    }
                }
            }
        }
    }
]
# THIS IS FOR THE CHAT OPS AND REPORTING AGENT MEMORY
chat_ops_strategy = [
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
            "namespaces": ["/summaries/{actorId}/{sessionId}"]
        }
    },
    {
        "customMemoryStrategy": {
            "name": "ChatOpsMemoryStrategy",
            "namespaces": ["/technical-issues/{actorId}"],
            "configuration": {
                "semanticOverride": {
                    "extraction": {
                        "modelId": "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
                        "appendToPrompt": OPS_ORCHESTRATOR_CUSTOM_EXTRACTION_PROMPT_FPATH
                    }
                }
            }
        }
    }
]
# MEMORY CREATION FOR THE TICKET CREATOR AGENT
ticket_creation_memory = [
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
            "namespaces": ["/summaries/{actorId}/{sessionId}"]
        }
    },
    {
        "customMemoryStrategy": {
            "name": "TicketCreatorMemoryId",
            "namespaces": ["/technical-issues/{actorId}"],
            "configuration": {
                "semanticOverride": {
                    "extraction": {
                        "modelId": "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
                        "appendToPrompt": TICKET_CREATOR_MEMORY_PROMPT
                    }
                }
            }
        }
    }
]
agent_cfg = config_data['agent_information']['ops_orchestrator_agent_model_info']
memory_cfg = agent_cfg.get('memories')
print(f"Found relevant memory configurations: {memory_cfg}")

# Storage for memory details
memories_data: Dict[str, Dict[str, Any]] = {}
created_memories: Dict[str, str] = {}

# Helper: mapping agent names to their strategies & descriptions
strategy_map = {
    'lead_agent': (lead_agent_strategy, "Memory for lead issue triaging OpenAI agent with custom issue tracking"),
    'chat_ops_agent': (chat_ops_strategy, "Memory for chatops agent OpenAI agent with custom issue tracking"),
    'ticket_agent': (ticket_creation_memory, "Memory for ticket creator OpenAI agent with custom issue tracking")
}

for agent_name, cfg in memory_cfg.items():
    use_existing = cfg.get('use_existing', False)
    existing_id = cfg.get('memory_id')

    if use_existing and existing_id:
        # Reuse existing memory
        print(f"🔄 Reusing memory for {agent_name}: {existing_id}")
        memories_data[agent_name] = {'id': existing_id}
    else:
        # Create new memory
        if agent_name not in strategy_map:
            raise ValueError(f"Unknown agent: {agent_name}")

        strategies, description = strategy_map[agent_name]
        print(f"✨ Creating memory for {agent_name}...")
        mem = openai_mem_client.create_memory_and_wait(
            name=f"{agent_name}_{int(time.time())}",
            memory_execution_role_arn=EXECUTION_ROLE_ARN,
            strategies=strategies,
            description=description,
            event_expiry_days=90
        )
        mem_id = mem.get("id")
        print(f"✅ Created memory for {agent_name}: {mem_id}")
        memories_data[agent_name] = {'id': mem_id}
        created_memories[agent_name] = mem_id

# Now, we will create some tools that will help retrieve memory, 
# save the memory, list the most recent messages. These are tools that
# all of the agents will have access to based on their memory being used
# Create observability hooks instance
try:
    observability_hooks = AgentObservabilityHooks(agent_name="monitoring-agent")
    print(f"✅ Observability hooks initialized: {observability_hooks.get_hook_status()}")
except Exception as e:
    print(f"⚠️ Failed to initialize observability hooks: {e}")
    observability_hooks = None

# We will be using this hook in the agent creation process
print(f"Going to create the memory gateway for this the lead agent that will use the agent as a tool and this agent will have its own memory and will be on the same gateway and runtime....")
ops_agent_info: Dict = config_data['agent_information']['ops_orchestrator_agent_model_info']
gateway_config_info: Dict = ops_agent_info.get('gateway_config')
# if there are any pre configured gateway credentials, they will be used here
gateway_credentials = gateway_config_info.get('credentials')

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
    # Get the expected pool name from config
    ops_agent_info = config_data['agent_information']['ops_orchestrator_agent_model_info']
    gateway_config_info = ops_agent_info.get('gateway_config', {})
    cognito_config = gateway_config_info.get('inbound_auth', {}).get('cognito', {})
    expected_pool_name = cognito_config.get('user_pool_name', 'ops-agentcore-gateway-pool')
    expected_resource_server_id = cognito_config.get('resource_server_id', 'ops_orchestrator_agent2039')
    
    print(f"Looking for user pool: {expected_pool_name}")
    print(f"Looking for resource server: {expected_resource_server_id}")
    
    # Expected names based on the code patterns
    expected_pool_names = [
        expected_pool_name,
        "ops-agentcore-gateway-pool",
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
            # Try different resource server IDs, prioritizing the config one
            expected_resource_ids = [
                expected_resource_server_id,
                "ops-agentcore-gateway-id",
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
            expected_client_name = ops_agent_info.get('gateway_config', {}).get('inbound_auth', {}).get('cognito', {}).get('client_name', 'agentcore-client')
            
            for client in clients_response.get('UserPoolClients', []):
                client_name = client['ClientName']
                if expected_client_name in client_name:
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

# Priority 1: Check JSON credentials file (local directory first, then root directory)
# This json file will contain contains information about the gateway such as the access
# token fetched from connecting to Cognito to connect to the gateway
local_credentials_path = OPS_ORCHESTRATOR_GATEWAY_CREDENTIALS_PATH
root_credentials_path = f"../{OPS_ORCHESTRATOR_GATEWAY_CREDENTIALS_PATH}"

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
                
                # Check if token is expired by parsing JWT payload
                if gateway_config_info['credentials'].get('create_new_access_token'):
                    print("⚠️ attempting refresh of the token...")
                    # In this case, we refresh to get a new token to connect to the 
                    # MCP gateway if the token is expired
                    new_token = refresh_access_token()
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
        gateway_name = gateway_config_info.get('name', 'ops-orchestrator-gateway')
        print(f"Going to create a gateway named: {gateway_name}...")
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
        USER_POOL_NAME = cognito_config.get('user_pool_name', "ops-agentcore-gateway-pool")
        RESOURCE_SERVER_ID = cognito_config.get('resource_server_id', "ops_orchestrator_agent2039")
        RESOURCE_SERVER_NAME = cognito_config.get('resource_server_name', "ops-agentcore-gateway2039")
        # Flag to check for if a user pool needs to be created or not
        CREATE_USER_POOL: bool = cognito_config.get('create_user_pool', False)
        logger.info(f"Going to create the user pool: {CREATE_USER_POOL}")
        CLIENT_NAME = cognito_config.get('client_name', "agentcore-client")
        SCOPES = cognito_config.get('scopes')
        logger.info(f"Going to use the following scopes from the config file: {SCOPES} for the ops orchestrator agent.")
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
                    description='AgentCore Gateway with target for ops orchestrator tools'
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
        # Step 5: Get access token
        print("Getting access token...")
        token_response = get_token(user_pool_id, client_id, client_secret, scope_string, REGION_NAME)
        print(f"Token response fetched: {token_response}")
        
        if "error" in token_response:
            print(f"❌ Failed to get access token: {token_response['error']}")
            print("⚠️  Continuing without access token - gateway may not be fully functional")
            access_token = None
        else:
            access_token = token_response["access_token"]
        print(f"✅ OpenAPI Gateway created successfully!")
        print(f"Gateway ID: {gateway_id}")
        print(f"MCP Server URL: {mcp_url}")
        if access_token:
            print(f"Access Token: {access_token[:20]}...")
        else:
            print("Access Token: Not available")
        # Create a dictionary with the credentials
        credentials = {
            "mcp_url": mcp_url,
            "access_token": access_token,
            "gateway_id": gateway_id,
            "created_at": time.time()
        }
        # Write the credentials to a JSON file
        with open(OPS_ORCHESTRATOR_GATEWAY_CREDENTIALS_PATH, 'w') as cred_file:
            json.dump(credentials, cred_file, indent=4)
        print(f"Credentials saved to {os.path.abspath(OPS_ORCHESTRATOR_GATEWAY_CREDENTIALS_PATH)}")
        
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
        
print(f"✅ Gateway setup completed with URL: {mcp_url}")
print(f"Gateway ID: {gateway_id}")
print(f"Access token configured: {'Yes' if access_token else 'No'}")

# Continue with the rest of your agent initialization...
print("🚀 Continuing with ops orchestrator multi-agent setup...")

# Load prompt templates
prompt_template_path_lead_agent: str = "prompt_template/ops_orchestrator_agent_prompt.txt"
prompt_template_path_jira_agent: str = "prompt_template/jira_agent_prompt.txt"
prompt_template_path_github_agent: str = "prompt_template/github_agent_prompt.txt"
logger.info(f"Going to read the ops orchestrator agent prompt template from: {prompt_template_path_lead_agent}")
logger.info(f"Going to read the github agent prompt template from: {prompt_template_path_github_agent}")
logger.info(f"Going to read the jira agent prompt template from: {prompt_template_path_jira_agent}")
OPS_ORCHESTRATOR_AGENT_SYSTEM_PROMPT = read_prompt_file(prompt_template_path_lead_agent)
JIRA_AGENT_PROMPT = read_prompt_file(prompt_template_path_jira_agent)
GITHUB_AGENT_PROMPT = read_prompt_file(prompt_template_path_github_agent)
print(f"Going to read the ops orchestrator agent prompt template from: {OPS_ORCHESTRATOR_AGENT_SYSTEM_PROMPT}")
print(f"Going to read the github agent prompt template from: {GITHUB_AGENT_PROMPT}")
print(f"Going to read the jira agent prompt template from: {JIRA_AGENT_PROMPT}")

# ────────────────────────────────────────────────────────────────────────────────────
# SPECIALIZED AGENT CLASSES FOR OPENAI AGENTS SDK - USING ONLY GATEWAY TOOLS
# ────────────────────────────────────────────────────────────────────────────────────
"""
OpenAI Agents SDK implementation with MCP servers
Agents get tools directly from MCP servers - no custom tools added
"""

from agents import Agent, Runner, function_tool
from agents.mcp import MCPServerStreamableHttp

# ────────────────────────────────────────────────────────────────────────────────────
# SPECIALIST AGENTS USING MCP SERVERS DIRECTLY
# ────────────────────────────────────────────────────────────────────────────────────

def create_jira_agent(gateway_url: str, access_token: str, memory_tools: list):
    """Create JIRA specialist agent that gets tools from MCP server"""
    
    # Create MCP server connection to the gateway
    mcp_server = MCPServerStreamableHttp(
        # this is the MCP server for JIRA
        name="AgentCore_Gateway_JIRA",
        params={
            "url": gateway_url,
            "headers": {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        },
        # cache tools for better performance so there is no additional latency
        cache_tools_list=True 
    )
    
    # Disable OpenAI tracing to prevent span_data.result errors
    import os
    os.environ["OPENAI_ENABLE_TRACING"] = "false"
    
    # Create agent with MCP server - it will automatically get all tools from the server
    return Agent(
        name="JIRA_Specialist",
        instructions=JIRA_AGENT_PROMPT,  # Use your existing prompt
        model="gpt-4o",
        mcp_servers=[mcp_server],  # Agent gets tools from MCP server
        tools=memory_tools  # Only add memory tools
    )

def create_github_agent(gateway_url: str, access_token: str, memory_tools: list):
    """Create GitHub specialist agent that gets tools from MCP server"""
    
    # Create MCP server connection to the gateway  
    mcp_server = MCPServerStreamableHttp(
        name="AgentCore_Gateway_GitHub",
        params={
            "url": gateway_url,
            "headers": {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        },
        cache_tools_list=True  # Cache tools for performance
    )
    
    # Disable OpenAI tracing to prevent span_data.result errors
    import os
    os.environ["OPENAI_ENABLE_TRACING"] = "false"
    
    # Create agent with MCP server - it will automatically get all tools from the server
    return Agent(
        name="GitHub_Specialist",
        instructions=GITHUB_AGENT_PROMPT,  # Use your existing prompt
        model="gpt-4o", 
        mcp_servers=[mcp_server],  # Agent gets tools from MCP server
        tools=memory_tools  # Only add memory tools
    )

def create_lead_orchestrator_agent(jira_agent: Agent, github_agent: Agent, memory_tools: list):
    """Create lead orchestrator agent with specialist agents as tools"""
    
    # Create delegation tools using the specialist agents
    @function_tool
    async def delegate_to_jira_specialist(task_description: str) -> str:
        """
        Delegate JIRA-related tasks to the JIRA specialist agent.
        Use for creating tickets, updating issues, querying JIRA data, managing workflows.
        
        Args:
            task_description: Detailed description of the JIRA task
        """
        try:
            result = await Runner.run(jira_agent, task_description)
            return f"🎫 JIRA Specialist Result: {result.final_output}"
        except Exception as e:
            return f"❌ JIRA delegation error: {str(e)}"
    
    @function_tool
    async def delegate_to_github_specialist(task_description: str) -> str:
        """
        Delegate GitHub-related tasks to the GitHub specialist agent.
        Use for creating repos, issues, gists, managing code, documentation.
        
        Args:
            task_description: Detailed description of the GitHub task
        """
        try:
            result = await Runner.run(github_agent, task_description)
            return f"🐙 GitHub Specialist Result: {result.final_output}"
        except Exception as e:
            return f"❌ GitHub delegation error: {str(e)}"
    
    # Alternative: Use the .as_tool() method for simpler delegation
    jira_tool = jira_agent.as_tool(
        tool_name="jira_specialist_agent",
        tool_description="JIRA specialist agent for all ticket management, issue tracking, and project workflow tasks."
    )
    
    github_tool = github_agent.as_tool(
        tool_name="github_specialist_agent", 
        tool_description="GitHub specialist agent for all code repository, issue tracking, and development workflow tasks."
    )
    
    # Disable OpenAI tracing to prevent span_data.result errors
    import os
    os.environ["OPENAI_ENABLE_TRACING"] = "false"
    
    # Create the orchestrator agent
    return Agent(
        name="Ops_Orchestrator",
        instructions=OPS_ORCHESTRATOR_AGENT_SYSTEM_PROMPT,  # Use your existing prompt
        model="gpt-4o",
        tools=[
            # Specialist agent delegation tools (choose one approach)
            delegate_to_jira_specialist,
            delegate_to_github_specialist,
            
            # Alternative: Direct agent tools
            # jira_tool,
            # github_tool,
            
            # Memory tools for orchestrator
            *memory_tools
        ]
    )

# ────────────────────────────────────────────────────────────────────────────────────
# ORCHESTRATOR SYSTEM USING YOUR EXISTING SETUP
# ────────────────────────────────────────────────────────────────────────────────────

class OpsOrchestratorSystem:
    """Complete ops orchestrator system using OpenAI Agents SDK with MCP servers"""
    
    def __init__(self, gateway_credentials: Dict, memories_data: Dict, observability_instance):
        self.gateway_credentials = gateway_credentials
        self.memories_data = memories_data
        self.observability = observability_instance
        
        # Session context from your observability setup
        self.actor_id = observability_instance.get_actor_id() if observability_instance else f"ops_actor_{int(time.time())}"
        self.session_id = observability_instance.get_session_id() if observability_instance else f"ops_session_{str(uuid.uuid4())}"
        
        # Agent instances
        self.jira_agent = None
        self.github_agent = None
        self.orchestrator_agent = None
    
    def get_existing_memory_tools(self, agent_type: str):
        """Get existing memory tools from your imported memory tools"""
        
        if agent_type == 'lead_agent':
            return create_memory_tools(
                self.memories_data['lead_agent']['id'],
                openai_mem_client,  # Your existing memory client
                actor_id=self.actor_id,
                session_id=self.session_id
            )
        elif agent_type == 'chat_ops_agent':
            return create_memory_tools(
                self.memories_data['chat_ops_agent']['id'],
                openai_mem_client,  # Your existing memory client
                actor_id=self.actor_id,
                session_id=self.session_id
            )
        elif agent_type == 'ticket_agent':
            # Use lead agent tools for ticket agent
            return create_memory_tools(
                self.memories_data['ticket_agent']['id'],
                openai_mem_client,  # Your existing memory client
                actor_id=self.actor_id,
                session_id=self.session_id
            )
        else:
            return []
    
    async def initialize(self):
        """Initialize all agents"""
        
        # Get memory tools for each agent
        jira_memory_tools = self.get_existing_memory_tools('ticket_agent')
        github_memory_tools = self.get_existing_memory_tools('chat_ops_agent')
        orchestrator_memory_tools = self.get_existing_memory_tools('lead_agent')
        
        # Create specialist agents with MCP server connections
        self.jira_agent = create_jira_agent(
            gateway_url=self.gateway_credentials['mcp_url'],
            access_token=self.gateway_credentials['access_token'],
            memory_tools=jira_memory_tools
        )
        
        self.github_agent = create_github_agent(
            gateway_url=self.gateway_credentials['mcp_url'],
            access_token=self.gateway_credentials['access_token'],
            memory_tools=github_memory_tools
        )
        
        # Create orchestrator agent with specialist agents as tools
        self.orchestrator_agent = create_lead_orchestrator_agent(
            jira_agent=self.jira_agent,
            github_agent=self.github_agent,
            memory_tools=orchestrator_memory_tools
        )
        
        print(f"✅ All agents initialized:")
        print(f"   - JIRA Agent: Connected to MCP gateway")
        print(f"   - GitHub Agent: Connected to MCP gateway")
        print(f"   - Orchestrator Agent: Using specialist agents as tools")
    
    async def execute_orchestration(self, user_input: str) -> str:
        """Execute orchestration using the lead agent"""
        try:
            if not self.orchestrator_agent:
                await self.initialize()
            
            # Add error handling for tracing issues
            import os
            os.environ.setdefault("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
            
            result = await Runner.run(
                self.orchestrator_agent,
                user_input,
                max_turns=15  # Allow multiple tool calls
            )
            
            return result.final_output
        except Exception as e:
            error_msg = str(e)
            # Filter out known OpenAI tracing errors that don't affect functionality
            if "span_data.result" in error_msg and "expected an array of strings" in error_msg:
                print(f"⚠️  Non-fatal tracing error (continuing): {error_msg}")
                # Try to extract actual result if available
                if hasattr(e, 'args') and len(e.args) > 1:
                    return str(e.args[1]) if e.args[1] else "Operation completed with tracing warnings"
                return "Operation completed with tracing warnings"
            return f"❌ Error in ops orchestration: {error_msg}"

# ────────────────────────────────────────────────────────────────────────────────────
# INITIALIZE THE ORCHESTRATOR SYSTEM WITH YOUR EXISTING SETUP
# ────────────────────────────────────────────────────────────────────────────────────

print("🚀 Initializing OpenAI Agents SDK Orchestrator System with MCP servers...")

# Create the orchestrator system using your existing components
ops_orchestrator_system = OpsOrchestratorSystem(
    gateway_credentials={
        'mcp_url': mcp_url,
        'access_token': access_token,
        'gateway_id': gateway_id
    },
    memories_data=memories_data,  # Your existing memory data
    observability_instance=_observability_instance  # Your existing observability
)

print(f"✅ Ops Orchestrator System initialized with:")
print(f"   - Gateway URL: {mcp_url}")
print(f"   - Memories: {list(memories_data.keys())}")
print(f"   - Actor ID: {ops_orchestrator_system.actor_id}")
print(f"   - Session ID: {ops_orchestrator_system.session_id}")

# ────────────────────────────────────────────────────────────────────────────────────
# AGENTCORE APP ENTRYPOINT
# ────────────────────────────────────────────────────────────────────────────────────

from bedrock_agentcore.runtime import BedrockAgentCoreApp

app = BedrockAgentCoreApp()

@app.entrypoint
async def invoke(payload):
    """AgentCore entrypoint for the ops orchestrator system"""
    user_message = payload.get("prompt", "Help me with AWS operations and incident management.")
    print(f"🎯 Invoking ops orchestrator with: {user_message}")
    
    try:
        result = await ops_orchestrator_system.execute_orchestration(user_message)
        return result
    except Exception as e:
        error_msg = f"❌ Error in ops orchestrator: {str(e)}"
        print(error_msg)
        return error_msg

# ────────────────────────────────────────────────────────────────────────────────────
# TESTING FUNCTIONS
# ────────────────────────────────────────────────────────────────────────────────────

async def test_orchestrator_system():
    """Test the orchestrator system with sample scenarios"""
    
    test_scenarios = [
        "Create a high-priority JIRA ticket for the API gateway timeout errors we've been seeing in production.",
        "Generate a GitHub issue for the memory leak in our Lambda function and create a gist with debugging steps.",
        "I need to track this production incident - create tickets in both JIRA and GitHub with proper cross-references.",
        "Review our recent CloudWatch alarms and create appropriate tracking tickets for any critical issues."
    ]
    
    print("🧪 Testing Ops Orchestrator System...")
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n{'='*80}")
        print(f"🎯 Test Scenario {i}: {scenario}")
        print(f"{'='*80}")
        
        try:
            result = await ops_orchestrator_system.execute_orchestration(scenario)
            print(f"✅ Result: {result}")
        except Exception as e:
            print(f"❌ Error: {e}")
        
        await asyncio.sleep(2)

def run_local_test():
    """Run local test of the orchestrator system"""
    import asyncio
    asyncio.run(test_orchestrator_system())

# ────────────────────────────────────────────────────────────────────────────────────
# USAGE INSTRUCTIONS
# ────────────────────────────────────────────────────────────────────────────────────

print("""
🎉 OpenAI Agents SDK Ops Orchestrator Setup Complete!

📋 KEY FEATURES:
   ✅ JIRA Agent: Gets tools directly from MCP gateway
   ✅ GitHub Agent: Gets tools directly from MCP gateway  
   ✅ Lead Orchestrator: Uses specialist agents as tools
   ✅ No custom tools - only MCP server tools + existing memory tools
   ✅ Proper authentication with AgentCore Gateway
   ✅ Integrated with your existing memory and observability setup

🔧 USAGE:
   1. For AgentCore Runtime: app.run()
   2. For Local Testing: run_local_test()
   3. For Direct Usage: await ops_orchestrator_system.execute_orchestration("your task")

🚀 Ready to orchestrate operations with MCP tools!
""")

async def interactive_cli():
    """Interactive CLI for the Ops Orchestrator System"""
    print("\n🚀 Ops Orchestrator Interactive CLI")
    print("=" * 50)
    print("Available commands:")
    print("  - Type your request to orchestrate operations")
    print("  - Type 'quit' or 'exit' to quit")
    print("  - Type 'test' to run predefined test scenarios")
    print("  - Type 'help' for this message")
    print("=" * 50)
    
    # Initialize the system once
    await ops_orchestrator_system.initialize()
    
    while True:
        try:
            user_input = input("\n🎯 Enter your request: ").strip()
            
            if not user_input:
                continue
                
            if user_input.lower() in ['quit', 'exit']:
                print("👋 Goodbye!")
                break
                
            if user_input.lower() == 'help':
                print("\n📋 Available commands:")
                print("  - Type your request to orchestrate operations")
                print("  - Type 'quit' or 'exit' to quit")
                print("  - Type 'test' to run predefined test scenarios")
                print("  - Type 'help' for this message")
                continue
                
            if user_input.lower() == 'test':
                await test_orchestrator_system()
                continue
            
            print(f"\n🔄 Processing: {user_input}")
            print("-" * 50)
            
            # Execute the orchestration
            result = await ops_orchestrator_system.execute_orchestration(user_input)
            
            print(f"\n✅ Result:")
            print(result)
            print("-" * 50)
            
        except KeyboardInterrupt:
            print("\n\n👋 Interrupted by user. Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")
            continue

def main():
    """Main function to choose between interactive CLI, testing, or AgentCore runtime"""
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'test':
            print("🧪 Running test scenarios...")
            run_local_test()
        elif command == 'runtime':
            print("🚀 Starting AgentCore runtime...")
            app.run()
        elif command == 'interactive':
            print("🖥️  Starting interactive CLI...")
            asyncio.run(interactive_cli())
        else:
            print(f"❌ Unknown command: {command}")
            print("Available commands: interactive, test, runtime")
    else:
        # Default to interactive mode
        print("🖥️  Starting interactive CLI (default mode)...")
        asyncio.run(interactive_cli())

if __name__ == "__main__":
    main()


# # Create a bedrock model using the BedrockModel interface
# ops_agent_info: str = config_data['agent_information']['ops_orchestrator_agent_model_info']
# bedrock_model = BedrockModel(
#     model_id=ops_agent_info.get('model_id'),
#     region_name=REGION_NAME,
#     temperature=ops_agent_info['inference_parameters'].get('temperature'),
#     max_tokens=ops_agent_info['inference_parameters'].get('max_tokens')
# )
# print(f"Initialized the bedrock model for the ops orchestrator agent: {bedrock_model}")

# # Import only what's needed for the AgentCore app entrypoint
# from bedrock_agentcore.runtime import BedrockAgentCoreApp

# # Create app instance for entrypoint decorator
# app = BedrockAgentCoreApp()

# # Create MCP client and agent at module level for reuse
# from strands.tools.mcp.mcp_client import MCPClient
# from mcp.client.streamable_http import streamablehttp_client 

# def create_streamable_http_transport():
#     """
#     This is the client to return a streamablehttp access token
#     """
#     try:
#         # Read credentials from file to get current token
#         with open(OPS_ORCHESTRATOR_GATEWAY_CREDENTIALS_PATH, 'r') as cred_file:
#             json_credentials = json.load(cred_file)
#             current_access_token = json_credentials['access_token']
#             current_mcp_url = json_credentials['mcp_url']
        
#         response = streamablehttp_client(current_mcp_url, headers={"Authorization": f"Bearer {current_access_token}"})
#         return response
#     except Exception as e:
#         logger.error(f"An error occurred while connecting to the MCP server: {e}")
#         raise e

# # Initialize MCP client
# print(f"Going to start the MCP session...")

# # Debug: Test if we can read credentials
# try:
#     with open(OPS_ORCHESTRATOR_GATEWAY_CREDENTIALS_PATH, 'r') as debug_file:
#         debug_creds = json.load(debug_file)
#         print(f"DEBUG: Credentials available: URL={debug_creds.get('mcp_url')}, Token={debug_creds.get('access_token')[:20]}...")
# except Exception as e:
#     print(f"DEBUG: Error reading credentials: {e}")

# mcp_client = MCPClient(create_streamable_http_transport)
# print(f"Started the MCP session client...")

# # Create memory tools for the OpenAI agents
# print("Creating memory tools for OpenAI agents...")

# # Create memory tools for all agents with their respective memory IDs
# all_memory_tools = []

# # Memory tools for lead agent (issue triaging)
# if memories_data.get('lead_agent'):
#     # generate a unique session ID
#     lead_session_id = str(uuid.uuid4())
#     lead_agent_memory_tools = create_lead_agent_memory_tools(
#         memories_data['lead_agent']['id'],
#         openai_mem_client, 
#         actor_id=(
#             _observability_instance.get_actor_id()
#             if _observability_instance
#             else f'lead_actor_{int(time.time())}'
#         ),
#         session_id=lead_session_id
#     )
#     all_memory_tools.extend(lead_agent_memory_tools)
#     print(f"✅ Created {len(lead_agent_memory_tools)} memory tools for lead agent (session {lead_session_id})")

# # Memory tools for chat‑ops agent
# if memories_data.get('chat_ops_agent'):
#     # generate a unique session ID
#     chatops_session_id = str(uuid.uuid4())
#     chatops_memory_tools = create_chatops_agent_memory_tools(
#         memories_data['chat_ops_agent']['id'], 
#         openai_mem_client,
#         actor_id=(
#             _observability_instance.get_actor_id()
#             if _observability_instance
#             else f'chatops_actor_{int(time.time())}'
#         ),
#         session_id=chatops_session_id
#     )
#     all_memory_tools.extend(chatops_memory_tools)
#     print(f"✅ Created {len(chatops_memory_tools)} memory tools for chat‑ops agent (session {chatops_session_id})")

# def invoke_agent_with_mcp_session(user_message):
#     """
#     Invoke the agent within an MCP client session context.
#     This ensures the MCP client is properly initialized before agent execution.
#     """
#     # Initialize gateway tools
#     print(f"Going to list tools from the MCP client")
#     try:
#         with mcp_client:
#             gateway_tools = mcp_client.list_tools_sync()
#             print(f"Loaded {len(gateway_tools)} tools from Gateway...")
#             # Create agent with Gateway MCP tools + memory hooks + observability hooks
#             hooks = []
#             if observability_hooks:
#                 hooks.append(observability_hooks)

#             # Combine all memory tools with gateway tools
#             all_tools = gateway_tools + all_memory_tools

#             # Initialize agent at module level
#             agent = Agent(
#                 system_prompt=OPS_ORCHESTRATOR_AGENT_SYSTEM_PROMPT,
#                 model=bedrock_model,
#                 hooks=hooks,
#                 tools=all_tools
#             )
#             response = agent(user_message)
#             return response.message['content'][0]['text']
#     except Exception as tools_error:
#         print(f"❌ Error listing tools from Gateway MCP server: {tools_error}")
#         raise

# print(f"✅ Created ops orchestrator agent with Gateway MCP tools and memory tools!")

# @app.entrypoint
# def invoke(payload):
#     '''
#     This is the entrypoint function to invoke the ops orchestrator agent.
#     This agent is created with tools from the MCP Gateway and can be
#     invoked both locally and via agent ARN using boto3 bedrock-agentcore client.
#     '''
#     user_message = payload.get("prompt", "You are an ops orchestrator agent to help with AWS operations, issue triaging, and incident management.")
#     print(f"Going to invoke the agent with the following prompt: {user_message}")
    
#     # Process the user input through the agent within MCP session
#     return invoke_agent_with_mcp_session(user_message)

# if __name__ == "__main__":
#     app.run()