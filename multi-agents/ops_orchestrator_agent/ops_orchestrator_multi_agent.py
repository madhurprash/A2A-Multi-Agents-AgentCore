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
from botocore.exceptions import ClientError
# import the strands agents and strands tools that we will be using
from strands import Agent
from datetime import datetime
from dotenv import load_dotenv
from typing import Dict, Any, Optional
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
from bedrock_agentcore_starter_toolkit.operations.gateway import GatewayClient
# These are openAI tools created to extract from, retrieve, store and manage memory through
# the amazon bedrock agentcore service
from openAI_memory_tools import create_chatops_agent_memory_tools, create_lead_agent_memory_tools

# define openAI specific import statements
from agents import Agent

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
logger.info(f"Loaded config from local file system: {json.dumps(config_data, indent=2)}")
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
    logger.info(f"✅ Observability initialized: {_observability_instance.get_observability_status()}")
except Exception as e:
    logger.warning(f"⚠️ Failed to initialize observability: {e}")
    logger.info("Continuing without observability features...")

# ────────────────────────────────────────────────────────────────────────────────────
# AGENTCORE MEMORY PRIMITIVE INITIALIZATION
# ────────────────────────────────────────────────────────────────────────────────────

# first, initialize the memory client
openai_mem_client = MemoryClient(region_name=REGION_NAME)
logger.info(f"Initialized the OpenAI memory client using the bedrock AgentCore memory primitive: {openai_mem_client}")

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
    logger.info(f"Going to be using the existing memory from the configuration file with id: {existing_memory_id}")
    memory = {'id': existing_memory_id}
    memory_id = existing_memory_id
# if these are not provided then we will create a new memory that we will be able to 
# use with our openAI agents
else:
    # create new memory if none exists
    if not memory:
        logger.info(f"Going to be creating some memory strategies for our three agents...")
        logger.info(f"Going to first make the memory for the lead orchestrator agent...")
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
        print(f"Going to create memory for the issue triaging agent....")
        memory_lead_agent = openai_mem_client.create_memory_and_wait(
                name=f"OpsAgent_mem_{int(time.time())}",
                memory_execution_role_arn=EXECUTION_ROLE_ARN,
                strategies=lead_agent_strategy,
                description="Memory for lead issue triaging OpenAI agent with custom issue tracking",
                event_expiry_days=90
            )
        # create and get the memory id
        memory_id_lead_agent = memory_lead_agent.get("id")
        logger.info(f"✅ Created memory for the lead openAI memory agent for issue triaging: {memory_id_lead_agent}")
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
        print(f"Going to create memory for the ops agent......")
        memory_chatops = openai_mem_client.create_memory_and_wait(
                name=f"OpsAgent_chat_{int(time.time())}",
                memory_execution_role_arn=EXECUTION_ROLE_ARN,
                strategies=chat_ops_strategy,
                description="Memory for chatops agent OpenAI agent with custom issue tracking",
                event_expiry_days=90
            )
        # create and get the memory id
        memory_id_chatops = memory_chatops.get("id")
        logger.info(f"✅ Created memory for the operations openAI memory agent for chat operations: {memory_id_chatops}")
        # Now, we will create some tools that will help retrieve memory, 
        # save the memory, list the most recent messages. These are tools that
        # all of the agents will have access to based on their memory being used
        # Create observability hooks instance
try:
    observability_hooks = AgentObservabilityHooks(agent_name="monitoring-agent")
    logger.info(f"✅ Observability hooks initialized: {observability_hooks.get_hook_status()}")
except Exception as e:
    logger.warning(f"⚠️ Failed to initialize observability hooks: {e}")
    observability_hooks = None

# We will be using this hook in the agent creation process
logger.info(f"Going to create the memory gateway for this the lead agent that will use the agent as a tool and this agent will have its own memory and will be on the same gateway and runtime....")
ops_agent_info: Dict = config_data['agent_information']['ops_orchestrator_agent_model_info']
gateway_config_info: Dict = ops_agent_info.get('gateway_config')
# if there are any pre configured gateway credentials, they will be used here
gateway_credentials = gateway_config_info.get('credentials')

print("Setting up AgentCore Gateway from configuration...")

# Check for existing credentials in multiple sources
mcp_url = None
access_token = None
gateway_id = None

# Import Keycloak authentication setup
from setup_keycloack_auth import setup_keycloak_auth, refresh_keycloak_token

def setup_keycloak_gateway_for_ops_agent():
    """
    Setup gateway with Keycloak authentication for ops orchestrator agent
    """
    try:
        # Check if we should use Keycloak instead of Cognito
        setup_keycloak = gateway_config_info.get('credentials', {}).get('use_keycloak', False)
        
        if setup_keycloak:
            print("🔑 Setting up Keycloak authentication for ops orchestrator agent...")
            
            # Setup Keycloak authentication
            keycloak_result = setup_keycloak_auth(gateway_config_info)
            
            # Extract credentials
            client_id = keycloak_result['client_id']
            client_secret = keycloak_result['client_secret']
            access_token = keycloak_result['access_token']
            discovery_url = keycloak_result['discovery_url']
            auth_config = keycloak_result['auth_config']
            
            print(f"✅ Keycloak setup complete:")
            print(f"- Client ID: {client_id}")
            print(f"- Discovery URL: {discovery_url}")
            print(f"- Access Token: {access_token[:20]}...")
            
            return client_id, client_secret, access_token, discovery_url, auth_config
        else:
            print("ℹ️ Keycloak authentication not enabled, falling back to existing auth method")
            return None
            
    except Exception as e:
        print(f"❌ Error setting up Keycloak: {e}")
        import traceback
        traceback.print_exc()
        return None

# Check if we should use Keycloak authentication
keycloak_setup_result = setup_keycloak_gateway_for_ops_agent()

if keycloak_setup_result:
    # Use Keycloak authentication
    client_id, client_secret, access_token, discovery_url, auth_config = keycloak_setup_result
    
    # Gateway configuration with Keycloak
    gateway_name = gateway_config_info.get('name', 'OpsOrchestratorGateway')
    
    # Step 1: Create IAM role using utils.py function
    print("Creating IAM role...")
    role_name = f"{gateway_name}Role"
    
    try:
        from utils import create_agentcore_gateway_role_s3_smithy
        agentcore_gateway_iam_role = create_agentcore_gateway_role_s3_smithy(role_name)
        role_arn = agentcore_gateway_iam_role['Role']['Arn']
        print(f"IAM role created: {role_arn}")
    except Exception as e:
        print(f"❌ Error creating IAM role: {e}")
        # Fallback role ARN if function not available
        role_arn = f"arn:aws:iam::{os.getenv('AWS_ACCOUNT_ID')}:role/{role_name}"
    
    # Step 2: Setup Gateway with Keycloak auth
    print("Setting up Gateway with Keycloak authentication...")
    import boto3
    gateway_client = boto3.client('bedrock-agentcore-control', region_name=REGION_NAME)
    
    # Check if gateway already exists
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
            print("Creating new gateway with Keycloak authentication...")
            create_response = gateway_client.create_gateway(
                name=gateway_name,
                roleArn=role_arn,
                protocolType="MCP",
                authorizerType="CUSTOM_JWT",
                authorizerConfiguration=auth_config['customJWTAuthorizer'],
                description='Ops Orchestrator Gateway with Keycloak authentication'
            )
            gateway_id = create_response.get("gatewayId")
            mcp_url = create_response.get("gatewayUrl")
            
            if not mcp_url:
                print(f"❌ Warning: Gateway URL is None in create response")
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
                # Handle existing gateway case
                raise e
            else:
                raise e
    
    # Step 3: Create gateway targets from configuration
    print("Creating gateway targets...")
    if gateway_config_info.get('existing_target') and gateway_config_info.get('target_name'):
        print(f"Using existing target: {gateway_config_info.get('target_name')}")
    else:
        try:
            from utils import create_targets_from_config
            created_targets = create_targets_from_config(
                gateway_id, gateway_config_info, gateway_config_info.get('bucket_name')
            )
            print(f"✅ Successfully created {len(created_targets)} targets")
        except Exception as e:
            print(f"❌ Error creating targets: {e}")
    
    # Step 4: Save credentials with Keycloak information
    print("Saving Keycloak gateway credentials...")
    credentials = {
        "gateway_id": gateway_id,
        "mcp_url": mcp_url,
        "access_token": access_token,
        "auth_type": "keycloak",
        "keycloak": {
            "url": keycloak_result['keycloak_url'],
            "realm_name": keycloak_result['realm_name'],
            "client_id": client_id,
            "client_secret": client_secret,
            "discovery_url": discovery_url,
            "scopes": keycloak_result['scopes']
        },
        "created_at": time.time()
    }
    
    # Save to credentials file
    OPS_GATEWAY_CREDENTIALS_PATH = "ops_orchestrator_gateway_keycloak_credentials.json"
    with open(OPS_GATEWAY_CREDENTIALS_PATH, 'w') as cred_file:
        json.dump(credentials, cred_file, indent=4)
    print(f"Keycloak credentials saved to {os.path.abspath(OPS_GATEWAY_CREDENTIALS_PATH)}")
    
    print(f"✅ Ops Orchestrator Gateway with Keycloak setup completed!")
    print(f"Gateway ID: {gateway_id}")
    print(f"MCP Server URL: {mcp_url}")
    print(f"Access Token: {access_token[:20]}...")

else:
    print("⚠️ Keycloak setup not enabled or failed. Please check configuration.")
    print("To enable Keycloak authentication, set 'use_keycloak: true' in gateway_config.credentials")
    
    # You can add fallback logic here for other authentication methods
    # or exit gracefully
    print("Exiting without gateway setup...")

# Final validation to ensure mcp_url is not None
if not mcp_url:
    print("❌ ERROR: mcp_url is None. Gateway creation or retrieval failed.")
    print("Please check the gateway creation logs above for errors.")
else:
    print(f"✅ Gateway setup completed with URL: {mcp_url}")

# Continue with the rest of your agent initialization...
print("🚀 Continuing with ops orchestrator multi-agent setup...")

# Create memory tools for the OpenAI agents
print("Creating memory tools for OpenAI agents...")

# Memory tools for lead agent (issue triaging)
if 'memory_id_lead_agent' in locals():
    lead_agent_memory_tools = create_lead_agent_memory_tools(
        memory_id_lead_agent, 
        openai_mem_client, 
        actor_id=_observability_instance.get_actor_id() if _observability_instance else f'lead_actor_{int(time.time())}'
    )
    print(f"✅ Created {len(lead_agent_memory_tools)} memory tools for lead agent")

# Memory tools for chatops agent
if 'memory_id_chatops' in locals():
    chatops_memory_tools = create_chatops_agent_memory_tools(
        memory_id_chatops, 
        openai_mem_client,
        actor_id=_observability_instance.get_actor_id() if _observability_instance else f'chatops_actor_{int(time.time())}'
    )
    print(f"✅ Created {len(chatops_memory_tools)} memory tools for chatops agent")

print("🎉 Ops orchestrator multi-agent setup with Keycloak authentication completed!")        

