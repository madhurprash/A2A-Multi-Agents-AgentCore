# This is the host adk agent that is responsible for understanding the other
# agents in the ecosystem and then invoking the agent that is the most relevant to this
# use case
import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, AsyncIterable, List, Dict

import httpx
import nest_asyncio
from a2a.client import A2ACardResolver
# These are the A2A types for communication
from a2a.types import (
    AgentCard, 
    MessageSendParams, 
    SendMessageRequest, 
    SendMessageResponse, 
    SendMessageSuccessResponse, 
    Task,
)
from dotenv import load_dotenv
# next, we will import google ADK import statements
# that will help us build an agent using ADK
from google.adk import Agent
from google.adk.artifacts import InMemoryArtifactService
from google.adk.memory.in_memory_memory_service import InMemoryMemoryService
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.tool_context import ToolContext
from google.genai import types

# import the remote agent connection
from .remote_agent_connection import RemoteAgentConnections

load_dotenv()
nest_asyncio.apply()

# create the host agent
class HostAgent:
    """
    This is the host agent that contains information about the remote agent
    connections, cards, agents, user id and runner.
    """
    def __init__(self):
        """
        This is the init function that initializes the remote agent connections, the cards available, 
        the agent cards, the agent, user id and the runner
        """
        self.remote_agent_connections: dict[str, RemoteAgentConnections] = {}
        self.cards: dict[str, AgentCard] = {}
        self.agents: str = ""
        self._agent = self.create_agent()
        self._user_id: str = "incident_response_logging_host_agent"
        self._runner = Runner(
            app_name=self._agent.name, 
            agent=self._agent, 
            artifact_service=InMemoryArtifactService(), 
            session_service=InMemorySessionService(), 
            memory_service=InMemoryMemoryService(),
        )
    
    async def _async_init_components(self, remote_agent_addresses: List[str]):
        """
        This function gets the agents in the A2A remote agent addresses and then 
        gets the agent card for each, establishes a remove connection and then provide the
        information about the agents.
        """
        async with httpx.AsyncClient(timeout=30) as client:
            for address in remote_agent_addresses:
                card_resolver = A2ACardResolver(client, address)
                try:
                    card = await card_resolver.get_agent_card()
                    remote_connection = RemoteAgentConnections(
                        agent_card=card, agent_url=address
                    )
                    self.remote_agent_connections[card.name] = remote_connection
                    self.cards[card.name] = card
                except httpx.ConnectError as e:
                    print(f"ERROR: Failed to get agent card from {address}: {e}")
                except Exception as e:
                    print(f"ERROR: Failed to initialize connection for {address}: {e}")

        agent_info = [
            json.dumps({"name": card.name, "description": card.description})
            for card in self.cards.values()
        ]
        print("agent_info:", agent_info)
        self.agents = "\n".join(agent_info) if agent_info else "No agents found"
    
    @classmethod
    async def create(
        cls,
        remote_agent_addresses: List[str],
    ):
        instance = cls()
        await instance._async_init_components(remote_agent_addresses)
        return instance

    def create_agent(self) -> Agent:
        return Agent(
            model="gemini-2.0-flash",
            name="Host_Agent",
            instruction=self.root_instruction,
            description="This Host agent orchestrates requests for incident response logging systems",
            tools=[
                self.send_message,
            ],
        )

    def root_instruction(self, context) -> str:
        return f"""
        Role: You are the Lead Orchestrator, an expert triage and coordination agent. Your primary function is to route user requests to the right specialist agent, track progress, and report back clearly.

        Specialist Agents

        OpsRemediation_Agent — executes searches and remediation tasks (e.g., investigate incidents, look up AWS docs/runbooks, propose and perform fixes).

        Monitoring_Agent — tracks and monitors AWS logs/metrics/dashboards and creates Jira tickets for detected issues (with links, severity, and context).

        Core Directives

        Initiate Triage: When asked for help, first clarify the objective and relevant scope (AWS account/region/service, time window, urgency).

        Task Delegation: Use the send_message tool to contact the appropriate agent(s).

        Be explicit: e.g., “Please scan CloudWatch logs and metrics for service X between 2024-08-01 and 2024-08-03.”

        Always pass the official agent name (OpsRemediation_Agent, Monitoring_Agent) in each message request.

        Analyze Responses: Correlate findings from all contacted agents. Summarize root causes, evidence (metrics/logs), and proposed actions.

        Jira Workflow: If Monitoring_Agent reports an issue, ensure a Jira ticket is (or gets) created, capture the ticket ID, status, and assignee, and keep it updated as remediation proceeds.

        Propose and Confirm: Present recommended actions (and any risk/impact) to the user for confirmation. If the user has pre-approved runbooks, proceed accordingly.

        Execute Remediation: After confirmation, instruct OpsRemediation_Agent to perform the fix. Track outcomes and validation steps (post-fix metrics, log baselines).

        Transparent Communication: Relay progress and final results, including Jira IDs/links and any residual follow-ups. Do not ask for permission before contacting specialist agents.

        Tool Reliance: Strictly rely on available tools to fulfill requests. Do not invent results or act without agent/tool confirmation.

        Readability: Respond concisely, preferably with bullet points and short sections.

        Agent Naming: Each available agent entry represents a specialist. For example, Monitoring_Agent represents the Monitoring agent.

        Availability Queries: When asked which agents are available, return the names of the active agents (the agents listed under Available Agents).

        Today’s Date (YYYY-MM-DD): {datetime.now().strftime("%Y-%m-%d")}

        <Available Agents> {self.agents} </Available Agents>
        """

    async def stream(
        self, query: str, session_id: str
    ) -> AsyncIterable[dict[str, Any]]:
        """
        Streams the agent's response to a given query.
        """
        session = await self._runner.session_service.get_session(
            app_name=self._agent.name,
            user_id=self._user_id,
            session_id=session_id,
        )
        content = types.Content(role="user", parts=[types.Part.from_text(text=query)])
        if session is None:
            session = await self._runner.session_service.create_session(
                app_name=self._agent.name,
                user_id=self._user_id,
                state={},
                session_id=session_id,
            )
        async for event in self._runner.run_async(
            user_id=self._user_id, session_id=session.id, new_message=content
        ):
            if event.is_final_response():
                response = ""
                if (
                    event.content
                    and event.content.parts
                    and event.content.parts[0].text
                ):
                    response = "\n".join(
                        [p.text for p in event.content.parts if p.text]
                    )
                yield {
                    "is_task_complete": True,
                    "content": response,
                }
            else:
                yield {
                    "is_task_complete": False,
                    "updates": "The host agent is thinking...",
                }

    async def send_message(self, agent_name: str, task: str, tool_context: ToolContext):
        """Sends a task to a remote agent."""
        if agent_name not in self.remote_agent_connections:
            raise ValueError(f"Agent {agent_name} not found")
        client = self.remote_agent_connections[agent_name]

        if not client:
            raise ValueError(f"Client not available for {agent_name}")

        # Simplified task and context ID management
        state = tool_context.state
        task_id = state.get("task_id", str(uuid.uuid4()))
        context_id = state.get("context_id", str(uuid.uuid4()))
        message_id = str(uuid.uuid4())

        payload = {
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": task}],
                "messageId": message_id,
                "taskId": task_id,
                "contextId": context_id,
            },
        }

        message_request = SendMessageRequest(
            id=message_id, params=MessageSendParams.model_validate(payload)
        )
        send_response: SendMessageResponse = await client.send_message(message_request)
        print("send_response", send_response)

        if not isinstance(
            send_response.root, SendMessageSuccessResponse
        ) or not isinstance(send_response.root.result, Task):
            print("Received a non-success or non-task response. Cannot proceed.")
            return

        response_content = send_response.root.model_dump_json(exclude_none=True)
        json_content = json.loads(response_content)

        resp = []
        if json_content.get("result", {}).get("artifacts"):
            for artifact in json_content["result"]["artifacts"]:
                if artifact.get("parts"):
                    resp.extend(artifact["parts"])
        return resp


def _get_initialized_host_agent_sync():
    """Synchronously creates and initializes the HostAgent."""

    async def _async_main():
        # Hardcoded URLs for the agents
        agent_urls = [
            "http://localhost:10002", 
            "http://localhost:10003", 
            "http://localhost:10004", 
        ]

        print("initializing host agent")
        hosting_agent_instance = await HostAgent.create(
            remote_agent_addresses=agent_urls
        )
        print("HostAgent initialized")
        return hosting_agent_instance.create_agent()

    try:
        return asyncio.run(_async_main())
    except RuntimeError as e:
        if "asyncio.run() cannot be called from a running event loop" in str(e):
            print(
                f"Warning: Could not initialize HostAgent with asyncio.run(): {e}. "
                "This can happen if an event loop is already running (e.g., in Jupyter). "
                "Consider initializing HostAgent within an async function in your application."
            )
        else:
            raise

root_agent = _get_initialized_host_agent_sync()
    
