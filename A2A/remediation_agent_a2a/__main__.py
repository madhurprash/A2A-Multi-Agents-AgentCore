# this is the main file for the remediation agent
import os
import sys
import yaml
import httpx
import uvicorn
import logging
from pathlib import Path
from dotenv import load_dotenv

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentSkill
from utils import get_agent_config
from agent_executer import RemediationAgentCoreExecutor

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MissingConfigError(Exception):
    pass

def required_env(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise MissingConfigError(f"Missing required env: {name}")
    return v

def load_config() -> dict:
    """Load configuration from config.yaml file."""
    config_path = Path(__file__).parent / "config.yaml"
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        raise MissingConfigError(f"Configuration file not found: {config_path}")
    except yaml.YAMLError as e:
        raise MissingConfigError(f"Error parsing config file: {e}")

def main():
    """Starts the AgentCore Remediation Agent A2A server."""
    print("Starting AgentCore Remediation Agent A2A server...")
    
    # Load configuration
    print("Loading configuration from config.yaml...")
    config = load_config()
    print("Configuration loaded successfully")
    
    # Server configuration with defaults from config
    host = config['server']['default_host']
    port = int(str(config['server']['default_port']))
    print(f"Server will start on {host}:{port}")

    try:
        # ---- Identity / Gateway config (from config.yaml and AWS Secrets Manager) ----
        print("Loading agent configuration and credentials...")
        agent_config = get_agent_config()
        print("Agent configuration loaded successfully")
        
        base_url = agent_config['base_url']
        agent_arn = agent_config['agent_arn'] 
        agent_session_id = agent_config['agent_session_id']
        user_pool_id = agent_config['user_pool_id']
        client_id = agent_config['client_id']
        client_secret = agent_config['client_secret']
        scope = agent_config['scope']
        discovery_url = agent_config.get('discovery_url')
        identity_provider = agent_config.get('identity_group')
        
        
        print(f"Base URL: {base_url}")
        print(f"Agent ARN: {agent_arn}")
        print(f"Session ID: {agent_session_id}")
        print(f"Going to use the following identity provider: {identity_provider}")
        
        # ---- A2A Agent metadata (Card + Skills) from config ----
        print("Setting up agent capabilities and skills...")
        capabilities = AgentCapabilities(
            streaming=config['agent_metadata']['capabilities']['streaming'],
            pushNotifications=config['agent_metadata']['capabilities']['push_notifications']
        )

        skills = [
            AgentSkill(
                id=skill['id'],
                name=skill['name'],
                description=skill['description'],
                tags=skill['tags'],
                examples=skill['examples']
            )
            for skill in config['agent_skills']
        ]
        print(f"Loaded {len(skills)} agent skills")

        # Supported content types from config
        supported_ct = config['agent_metadata']['supported_content_types']

        # Agent card from config
        print("Creating agent card...")
        agent_card = AgentCard(
            name=config['agent_metadata']['name'],
            description=config['agent_metadata']['description'],
            url=base_url,
            version=config['agent_metadata']['version'],
            defaultInputModes=supported_ct,
            defaultOutputModes=supported_ct,
            capabilities=capabilities,
            skills=skills,
            identity_provider=identity_provider,
        )
        print(f"Agent card created: {agent_card}")

        # ---- Wire executor into the A2A app ----
        print("Initializing agent executor and request handler...")
        httpx_client = httpx.AsyncClient()
        request_handler = DefaultRequestHandler(
            agent_executor=RemediationAgentCoreExecutor(
                base_url=base_url,
                agent_arn=agent_arn,
                agent_session_id=agent_session_id,
                user_pool_id=user_pool_id,
                client_id=client_id,
                client_secret=client_secret,
                scope='operations-agentcore-gateway-id/gateway:read operations-agentcore-gateway-id/gateway:write',
                discovery_url=discovery_url,
                identity_provider=identity_provider,
            ),
            task_store=InMemoryTaskStore(),
        )
        print("Agent executor initialized successfully")

        print("Creating A2A Starlette application...")
        server = A2AStarletteApplication(agent_card=agent_card, http_handler=request_handler)
        print(f"Starting server on http://{host}:{port}")
        uvicorn.run(server.build(), host=host, port=port)

    except MissingConfigError as e:
        logger.error("Configuration error: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("An error occurred during server startup: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
