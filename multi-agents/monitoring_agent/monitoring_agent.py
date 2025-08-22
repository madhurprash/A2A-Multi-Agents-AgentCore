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
logging.getLogger("strands").setLevel(logging.DEBUG)

# Add a handler to see the logs
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
        print("Continuing without creating log group...")
        # Continue execution instead of raising the error
        pass
except Exception as e:
    print(f"Unexpected error while creating log group: {e}")
    print("Continuing without creating log group...")
    # Continue execution for any other unexpected errors
    pass

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
        print("Continuing without creating log stream...")
        # Continue execution instead of raising the error
        pass
except Exception as e:
    print(f"Unexpected error while creating log stream: {e}")
    print("Continuing without creating log stream...")
    # Continue execution for any other unexpected errors
    pass
    
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
            logger.info(f"Going to use the following memory: {config_data['agent_information']['monitoring_agent_model_info'].get('memory_execution_role')}")
            memory = client.create_memory_and_wait(
                name=f"{MONITORING_GATEWAY_NAME}_memory_{int(time.time())}",
                memory_execution_role_arn=config_data['agent_information']['monitoring_agent_model_info'].get('memory_execution_role'),
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

print("Setting up AgentCore Gateway from configuration...")


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

# Create MCP client and agent at module level for reuse
from strands.tools.mcp.mcp_client import MCPClient
from mcp.client.streamable_http import streamablehttp_client 

def create_streamable_http_transport():
    """
    This is the client to return a streamablehttp access token
    Automatically refreshes token if connection fails
    """
    try:
        current_mcp_url = gateway_config_info.get('url')
        scope_string = "monitoring-agentcore-gateway-id/gateway:read monitoring-agentcore-gateway-id/gateway:write"
        token_response = get_access_token(
            user_pool_id=config_data['idp_setup'].get('user_pool_id'),
            client_id=config_data['idp_setup'].get('client_id'),
            client_secret=config_data['idp_setup'].get('client_secret'),
            scope_string=scope_string,
            discovery_url=config_data['idp_setup'].get('discovery_url'),
        )
        print(f"Token response: {token_response}")
        # Check if token request was successful
        if "error" in token_response:
            raise Exception(f"Token request failed: {token_response['error']}")
        
        if "access_token" not in token_response:
            raise Exception(f"No access_token in response: {token_response}")
            
        current_access_token = token_response["access_token"]
        response = streamablehttp_client(current_mcp_url, headers={"Authorization": f"Bearer {current_access_token}"})
        return response
    except Exception as auth_error:
        logger.error(f"Authentication failed: {auth_error}")
        raise

# Initialize MCP client
print(f"Going to start the MCP session...")

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
            MONITORING_AGENT_SYSTEM_PROMPT_W_USER_QUESTION: str = MONITORING_AGENT_SYSTEM_PROMPT.format(question=user_message)
            # Initialize agent at module level
            agent = Agent(
                system_prompt=MONITORING_AGENT_SYSTEM_PROMPT_W_USER_QUESTION,
                model=bedrock_model,
                hooks=hooks,
                tools=gateway_tools,
            )
            response = agent(user_message)
            print(f"Response: {response}")
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
            # clean_resp = filter_agent_output(resp)
            print(f"agent> {resp}\n")
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