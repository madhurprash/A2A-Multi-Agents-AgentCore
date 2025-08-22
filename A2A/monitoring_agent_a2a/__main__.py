import logging
import os
import sys

import httpx
import uvicorn
from dotenv import load_dotenv

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryPushNotifier, InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentSkill

from app.agent_executor import MonitoringAgentCoreExecutor

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


def main():
    """Starts the AgentCore Monitoring Agent A2A server."""
    host = os.getenv("A2A_HOST", "localhost")
    port = int(os.getenv("A2A_PORT", "10004"))

    try:
        # ---- Identity / Gateway config (from env) ----
        base_url = required_env("A2A_GATEWAY_BASE_URL")  # e.g., https://<gateway-domain>/runtime
        agent_arn = required_env("A2A_AGENT_ARN")        # arn:aws:bedrock-agentcore:...:runtime/monitoring_agent-...
        agent_session_id = required_env("A2A_AGENT_SESSION_ID")

        user_pool_id = required_env("A2A_USER_POOL_ID")  # us-west-2_...
        client_id = required_env("A2A_CLIENT_ID")
        client_secret = required_env("A2A_CLIENT_SECRET")
        scope = required_env("A2A_OAUTH_SCOPE")          # e.g., "monitoring-agentcore-gateway-id/gateway:read monitoring-agentcore-gateway-id/gateway:write"

        # ---- A2A Agent metadata (Card + Skills) ----
        capabilities = AgentCapabilities(streaming=True, pushNotifications=True)

        skills = [
            AgentSkill(
                id="monitor_cloudwatch",
                name="CloudWatch Monitor",
                description="Scan AWS logs/metrics for bedrock logs.",
                tags=["monitoring", "cloudwatch", "metrics"],
                examples=[
                    "Check errors for service X in us-west-2 over the last 2 hours",
                    "List recent high-latency alarms in prod",
                ],
            ),
            AgentSkill(
                id="log_root_cause",
                name="Log-based Diagnostics",
                description="Perform log triage to suggest likely root causes.",
                tags=["diagnostics", "logs", "triage"],
                examples=["Can you list some of the alarms for EC2 instances and why?"],
            ),
            AgentSkill(
                id="create_jira_tickets",
                name="Create Jira tickets",
                description="For issues and customer queries, create JIRA tickets",
                tags=["jira", "ticket", "remediation"],
                examples=["Can you create a Jira ticket for issue XYZ?"],
            )
        ]

        # No local agent class; declare generic text support
        supported_ct = ["text/plain"]

        # this should contain he idp provider
        agent_card = AgentCard(
            name="Monitoring Agent (AgentCore)",
            description="Routes requests to a Bedrock AgentCore runtime that monitors AWS logs/metrics and creates Jira tickets.",
            url=f"http://{host}:{port}/",
            version="1.0.0",
            defaultInputModes=supported_ct,
            defaultOutputModes=supported_ct,
            capabilities=capabilities,
            skills=skills,
        )

        # ---- Wire executor into the A2A app ----
        httpx_client = httpx.AsyncClient()
        request_handler = DefaultRequestHandler(
            agent_executor=MonitoringAgentCoreExecutor(
                base_url=base_url,
                agent_arn=agent_arn,
                agent_session_id=agent_session_id,
                user_pool_id=user_pool_id,
                client_id=client_id,
                client_secret=client_secret,
                scope=scope,
                stream=True,  # set False if your gateway doesn’t support SSE
            ),
            task_store=InMemoryTaskStore(),
            push_notifier=InMemoryPushNotifier(httpx_client),
        )

        server = A2AStarletteApplication(agent_card=agent_card, http_handler=request_handler)
        uvicorn.run(server.build(), host=host, port=port)

    except MissingConfigError as e:
        logger.error("Configuration error: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("An error occurred during server startup: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
