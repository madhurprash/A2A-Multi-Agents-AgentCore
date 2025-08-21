# This is the operations agent that is responsible for
# getting the latest status from the JIRA dashboard and then
# provide some documentation and remediation on the solution.
# It does the follows: 
# 1. It provides documentation and reports on the fixes on the JIRA ticket
# by searching the web for AWS documentation.
# 2. It provides the documentation and updates on slack as there are any updates.
# In this case, this agent acts as an ambient agent.
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
import argparse
from datetime import datetime
from dotenv import load_dotenv
from typing import Dict, Any, Optional
# To correlate traces across multiple agent runs, 
# we will associate a session ID with our telemetry data using the 
# Open Telemetry baggage
from opentelemetry import context, baggage
from botocore.exceptions import ClientError

# Load environment variables first
load_dotenv()

# AWS Secrets Manager client for retrieving API keys
secrets_manager_client = boto3.client('secretsmanager')

def _get_secret(secret_name: str, region_name: str = 'us-west-2') -> str:
    """
    Retrieve a secret from AWS Secrets Manager.
    
    Args:
        secret_name: Name of the secret in AWS Secrets Manager
        region_name: AWS region where the secret is stored
        
    Returns:
        The secret value as a string
        
    Raises:
        ValueError: If secret cannot be retrieved
    """
    try:
        client = boto3.client('secretsmanager', region_name=region_name)
        response = client.get_secret_value(SecretId=secret_name)
        
        # Handle both string and JSON secrets
        secret_string = response['SecretString']
        try:
            # Try to parse as JSON first
            secret_data = json.loads(secret_string)
            # If it's a JSON object, look for common key patterns
            if isinstance(secret_data, dict):
                # Try common key patterns for API keys
                for key in ['api_key', 'key', 'value', 'OPENAI_API_KEY', 'TAVILY_API_KEY', 'JIRA_API_KEY']:
                    if key in secret_data:
                        return secret_data[key]
                # If no standard key found, return the first value
                return list(secret_data.values())[0] if secret_data else secret_string
            return secret_string
        except json.JSONDecodeError:
            # It's a plain string secret
            return secret_string
            
    except Exception as e:
        raise ValueError(f"Failed to retrieve secret '{secret_name}': {str(e)}")

def _get_api_key(key_name: str, secret_name: Optional[str] = None) -> str:
    """
    Get API key from Secrets Manager or environment variables as fallback.
    
    Args:
        key_name: Environment variable name (e.g., 'OPENAI_API_KEY')
        secret_name: Optional AWS Secrets Manager secret name
        
    Returns:
        The API key value
        
    Raises:
        ValueError: If key cannot be found in either location
    """
    # First try Secrets Manager if secret name provided
    if secret_name:
        try:
            return _get_secret(secret_name)
        except ValueError as e:
            print(f"Warning: Failed to get {key_name} from Secrets Manager: {e}")
            print(f"Falling back to environment variable...")
    
    # Fallback to environment variable
    env_value = os.getenv(key_name)
    if env_value:
        return env_value
        
    raise ValueError(f"{key_name} not found in Secrets Manager or environment variables")

# Get API keys from Secrets Manager with environment variable fallback
try:
    OPENAI_API_KEY = _get_api_key('OPENAI_API_KEY', 'prod/openai/api-key')
    # Set in environment for other parts of the code
    os.environ['OPENAI_API_KEY'] = OPENAI_API_KEY
    print(f"OpenAI API Key loaded from Secrets Manager: {'***' + OPENAI_API_KEY[-4:] if OPENAI_API_KEY else 'NOT FOUND'}")
except ValueError as e:
    print(f"Error loading OpenAI API key: {e}")
    raise

try:
    TAVILY_API_KEY = _get_api_key('TAVILY_API_KEY', 'prod/tavily/api-key')
    os.environ['TAVILY_API_KEY'] = TAVILY_API_KEY
    print(f"Tavily API Key loaded from Secrets Manager: {'***' + TAVILY_API_KEY[-4:] if TAVILY_API_KEY else 'NOT FOUND'}")
except ValueError as e:
    print(f"Warning: Tavily API key not available: {e}")
    TAVILY_API_KEY = None

try:
    JIRA_API_KEY = _get_api_key('JIRA_API_KEY', 'prod/jira/api-key')
    os.environ['JIRA_API_KEY'] = JIRA_API_KEY
    print(f"JIRA API Key loaded from Secrets Manager: {'***' + JIRA_API_KEY[-4:] if JIRA_API_KEY else 'NOT FOUND'}")
except ValueError as e:
    print(f"Warning: JIRA API key not available: {e}")
    JIRA_API_KEY = None

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


from bedrock_agentcore.memory import MemoryClient
# This will help set up for strategies that can then be used 
# across the code - user preferences, semantic memory or even
# summarizations across the sessions along with custom strategies
# for this monitoring agent
from bedrock_agentcore.memory.constants import StrategyType
# Configure the root strands logger
logging.getLogger("strands").setLevel(logging.DEBUG)
# Import Cognito authentication setup from utils
# These are openAI tools created to extract from, retrieve, store and manage memory through
# the amazon bedrock agentcore service
from openAI_memory_tools import create_memory_tools
# Local search functionality only - no gateway dependencies
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
print(f"Going to be using the customer extraction prompt for user preferences: {CUSTOM_EXTRACTION_PROMPT_LEAD_AGENT}")

# this is the flag to check if the existing memory needs to be used or not
# if there is a memory that is already created and existing, you can flag this in the config file as true
create_memories: bool = config_data['agent_information']['ops_orchestrator_agent_model_info'].get('use_existing_memory')
existing_memory_id: bool = config_data['agent_information']['ops_orchestrator_agent_model_info'].get('existing_memory_id')
# set the memory id and memory to none for now
memory_id = None
memory = None
local_tools_config = config_data.get('local_tools', {})

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
            "namespaces": ["/users/{actorId}/preferences/"]
        }
    },
    {
        "semanticMemoryStrategy": {
            "name": "SemanticMemory",
            "namespaces": ["/knowledge/{actorId}/semantics/"]
        }
    },
    {
        "summaryMemoryStrategy": {
            "name": "SessionSummarizer",
            "namespaces": ["/summaries/{actorId}/{sessionId}/"]
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
agent_cfg = config_data['agent_information']['ops_orchestrator_agent_model_info']
memory_cfg = agent_cfg.get('memories')
print(f"Found relevant memory configurations: {memory_cfg}")

# Storage for memory details
memories_data: Dict[str, Dict[str, Any]] = {}
created_memories: Dict[str, str] = {}

# Helper: mapping agent names to their strategies & descriptions
strategy_map = {
    'lead_agent': (lead_agent_strategy, "Memory for lead issue triaging OpenAI agent with custom issue tracking"),
}

for agent_name, cfg in memory_cfg.items():
    """
    For each of the strategy we will create the memory and wait
    """
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

# Continue with the rest of your agent initialization...
print("🚀 Continuing with ops orchestrator multi-agent setup...")

# Load prompt templates
prompt_template_path_lead_agent: str = "prompt_template/ops_orchestrator_agent_prompt.txt"
logger.info(f"Going to read the ops orchestrator agent prompt template from: {prompt_template_path_lead_agent}")
OPS_ORCHESTRATOR_AGENT_SYSTEM_PROMPT = read_prompt_file(prompt_template_path_lead_agent)
print(f"Going to read the ops orchestrator agent prompt template from: {OPS_ORCHESTRATOR_AGENT_SYSTEM_PROMPT}")

# ────────────────────────────────────────────────────────────────────────────────────
# SPECIALIZED AGENT CLASSES FOR OPENAI AGENTS SDK - USING ONLY LOCAL TOOLS
# ────────────────────────────────────────────────────────────────────────────────────
"""
OpenAI Agents SDK implementation with local tools
Agents get only local file search and web search tools - no external dependencies
"""
# Removed requests import - not needed for local tools
from agents import Agent, Runner, function_tool
import os, asyncio, datetime
import httpx
from tavily import TavilyClient

# TAVILY_API_KEY already loaded from Secrets Manager above
# Keep this line for compatibility but use the global variable
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY") or TAVILY_API_KEY

@function_tool
async def web_search_impl(query: str, top_k: int = 5, recency_days: int | None = None):
    """
    Uses Tavily's search API to return top web results with snippets.
    """
    if not TAVILY_API_KEY:
        raise RuntimeError("Missing TAVILY_API_KEY env var")

    client = TavilyClient(api_key=TAVILY_API_KEY)
    search_kwargs = {
        "query": query,
        "max_results": max(1, min(top_k, 10)),
        "include_domains": None,
        "exclude_domains": None,
    }
    if recency_days:
        # Tavily supports time windows like 'd7', 'd30'
        if recency_days <= 1:
            search_kwargs["time_range"] = "d1"
        elif recency_days <= 7:
            search_kwargs["time_range"] = "d7"
        elif recency_days <= 30:
            search_kwargs["time_range"] = "d30"
        else:
            search_kwargs["time_range"] = "y1"

    res = client.search(**search_kwargs)
    results = []
    for item in res.get("results", []):
        results.append({
            "title": item.get("title"),
            "url": item.get("url"),
            "snippet": item.get("content") or item.get("snippet"),
            "score": item.get("score"),
        })
    return {"results": results, "provider": "tavily", "query": query}

@function_tool
def list_local_tools() -> list:
    """List available local tools"""
    return [
        {
            'name': 'web_search_impl',
            'description': 'Search the web using Tavily API',
            'parameters': {
                'query': 'Search query string',
                'top_k': 'Number of results to return (max 10)',
                'recency_days': 'Filter results by recency in days'
            }
        }
    ]

def _get_memory_tools(agent_type: str):
    """Get memory tools for the specified agent type"""
    memory_map = {
        'lead_agent': memories_data.get('lead_agent', {}).get('id'),
    }
    
    memory_id = memory_map.get(agent_type)
    if memory_id:
        return create_memory_tools(
            memory_id,
            openai_mem_client,
            actor_id='default_actor',
            session_id='default_session'
        )
    return []
    
async def create_lead_orchestrator_agent(memory_tools: list):
    """Create lead orchestrator agent with local tools only"""
    
    # Disable OpenAI tracing to prevent span_data.result errors
    os.environ["OPENAI_ENABLE_TRACING"] = "false"
    
    # Use the memory tools passed as parameter
    if not memory_tools:
        memory_tools = _get_memory_tools('lead_agent')
    print(f"Going to add memory tools: {memory_tools}")
    
    # Add only local tools - no gateway dependencies
    agent_tools = [web_search_impl, *memory_tools]
    
    print(f"✅ Local tools initialized: web search, file search, and {len(memory_tools)} memory tools")
    
    # Create the orchestrator agent with local tools only
    orchestrator = Agent(
        name="Ops_Orchestrator",
        instructions=OPS_ORCHESTRATOR_AGENT_SYSTEM_PROMPT,  # Use your existing prompt
        model=config_data['agent_information']['ops_orchestrator_agent_model_info'].get('model_id'),
        tools=agent_tools
    )
    print(f"✅ Orchestrator Agent created with local tools only: {len(agent_tools)} total tools")
    return orchestrator

# ────────────────────────────────────────────────────────────────────────────────────
# ENTRYPOINT FUNCTION FOR BEDROCK AGENTCORE INVOCATION
# ────────────────────────────────────────────────────────────────────────────────────

# Import only what's needed for the AgentCore app entrypoint
print(f"Going to start the app.entrypoint from where this invocations will process...")
from bedrock_agentcore.runtime import BedrockAgentCoreApp

async def get_lead_orchestrator():
    """
    Build and return the lead orchestrator Agent.
    You already define create_lead_orchestrator_agent(memory_tools: list) above.
    """
    # If you want to pass explicit memory tools, replace [] with your list.
    return await create_lead_orchestrator_agent([])

async def _call_agent(agent, prompt: str):
    """
    Call agent using the proper OpenAI Agents SDK Runner.
    """
    try:
        # Use the proper OpenAI Agents SDK Runner
        result = await Runner().run(agent, prompt)
        return {"output": result.final_output}
    except Exception as e:
        return {"output": f"Error running agent: {str(e)}"}

app = BedrockAgentCoreApp()
print(f"Created the Bedrock agent core app and we will be using an entrypoint from this app to invoke the agent from the runtime feature: {app}")

@app.entrypoint
async def invoke(payload):
    """Entrypoint for the lead ops orchestrator agent"""
    user_message = payload.get("prompt")
    print(f"🎯 Invoking operations agent with prompt: {user_message}")

    try:
        orchestrator = await get_lead_orchestrator()
        result = await _call_agent(orchestrator, user_message)
        print("✅ Lead orchestrator execution completed")
        return result
    except Exception as e:
        error_msg = f"❌ Error in lead orchestrator execution: {str(e)}"
        print(error_msg)
        return {"error": error_msg}


# ──────────────────────────────────────────────────────────────────────────────
# INTERACTIVE MODE & SINGLE-COMMAND MODE
# (Use the same lead orchestrator in both)
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import argparse
import sys
from typing import Optional

async def interactive_mode():
    """Run the lead orchestrator in interactive mode"""
    print("🚀 Starting Lead Orchestrator Interactive Mode")
    print("Type 'quit', 'exit', or 'q' to stop | Type 'help' for example commands")

    try:
        orchestrator = await get_lead_orchestrator()
        print("✅ Lead Orchestrator initialized successfully!\n")

        while True:
            try:
                # Use synchronous input - asyncio.to_thread can cause issues in some environments
                user_input = input("🎯 Ops Orchestrator > ").strip()

                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("👋 Goodbye!")
                    break

                if not user_input:
                    continue

                if user_input.lower() == 'help':
                    _print_help()
                    continue

                print(f"\n🔄 Processing: {user_input}")
                result = await _call_agent(orchestrator, user_input)
                print(f"✅ Result:\n{result}\n")

            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                return  # Use return instead of break to exit cleanly
            except EOFError:
                print("\n👋 Goodbye!")
                return
            except Exception as e:
                print(f"❌ Error: {e}")

    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        return
    except Exception as e:
        print(f"❌ Failed to initialize lead orchestrator: {e}")
        return

def _print_help():
    """Print help information with example commands"""
    print("\n📚 Example commands:")
    print("🎫 JIRA: 'Create a JIRA ticket for high CPU usage investigation'")
    print("🐙 GitHub: 'Create an issue in our ops repo about database performance'")
    print("🔧 Combined: 'Production outage - create JIRA ticket and GitHub issue'")
    print("📊 Info: 'Show me recent alerts and their resolution status'\n")

async def run_single_command(command: str):
    """Run a single command and exit using the lead orchestrator"""
    try:
        orchestrator = await get_lead_orchestrator()
        result = await _call_agent(orchestrator, command)
        print(f"✅ Result:\n{result}")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

def _parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Ops Orchestrator Agent")
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('-c', '--command', type=str, help='Execute a single command and exit')
    parser.add_argument('--server', action='store_true', help='Run as AgentCore server (default)')
    return parser.parse_args()

if __name__ == "__main__":
    args = _parse_arguments()

    try:
        if args.command:
            asyncio.run(run_single_command(args.command))
        else:
            print("Running the application for the Bedrock agent core runtime.")
            app.run()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)