#!/usr/bin/env python3
"""
A2A (Agent-to-Agent) Communication Service - Fully Compliant Implementation

This service implements the Agent2Agent (A2A) Protocol for bidirectional communication 
between monitoring and ops orchestrator agents using AWS Bedrock AgentCore runtime.
Follows A2A specification with Agent Cards, Task Lifecycle, and JSON-RPC messaging.

Usage:
    python a2a_communication_compliant.py --demo
    
From agents:
    from a2a_communication_compliant import A2AService
    a2a = A2AService()
    task = await a2a.create_task("monitoring_agent", "Investigate high CPU usage")
    response = await a2a.send_message(task["id"], "Please analyze EC2 metrics")
"""

import os
import sys
import json
import uuid
import time
import boto3
import asyncio
import argparse
from enum import Enum
from datetime import datetime
from dotenv import load_dotenv
from botocore.exceptions import ClientError
from typing import Dict, Any, Optional, List

# Load environment variables
load_dotenv()

# Import the existing invoke_agent functionality
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'multi-agents'))
# This is the function that invokes the agents
from invoke_agent import invoke_monitoring_agent

# Import Strands agent for intelligent routing
try:
    from strands import Agent
    from strands.models import BedrockModel
    STRANDS_AVAILABLE = True
except ImportError:
    STRANDS_AVAILABLE = False
    print("⚠️ Strands not available. Install strands-agents for intelligent routing.")

# Import bedrock runtime for LiteLLM fallback
try:
    bedrock_runtime = boto3.client('bedrock-runtime', region_name='us-west-2')
    BEDROCK_RUNTIME_AVAILABLE = True
except Exception:
    BEDROCK_RUNTIME_AVAILABLE = False
    print("⚠️ Bedrock runtime not available. Using hardcoded routing.")

# Constants that are defined to bring in the agent skills
AGENTIC_SKILLS: str = os.path.join(os.path.dirname(__file__), "agentic_cards")
INCIDENT_AGENT_SKILLS: str = os.path.join(AGENTIC_SKILLS, 'operations_skills.json')
MONITORING_AGENT_SKILLS: str = os.path.join(AGENTIC_SKILLS, 'monitoring_skills.json')

# A2A Protocol Enums and Types
# This is the task state and the task state
# consists of various fields
class TaskState(Enum):
    """
    This state consists of parameters that are required while maintaining the 
    state during the agent implementation
    """
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input-required"
    COMPLETED = "completed"
    CANCELED = "canceled"
    FAILED = "failed"
    REJECTED = "rejected"
    AUTH_REQUIRED = "auth-required"
    UNKNOWN = "unknown"

class MessageRole(Enum):
    USER = "user"
    AGENT = "agent"

class PartType(Enum):
    TEXT = "text"
    FILE = "file"
    DATA = "data"

class IntelligentA2ARouter:
    """
    Intelligent Agent Router using Strands Agent or Bedrock LiteLLM
    
    This router decides which agent should handle incoming requests based on:
    - Agent capability cards
    - Query analysis
    - Historical patterns
    """
    
    def __init__(self, region: str = "us-west-2"):
        self.region = region
        self.router_agent = None
        self.bedrock_runtime = None
        self.routing_enabled = False
        
        # Initialize Strands router agent if available
        if STRANDS_AVAILABLE:
            try:
                self.router_agent = Agent(
                    model=BedrockModel(),
                    system_prompt="""You are an intelligent agent router for A2A communication.
                    
                    Your job is to analyze user queries and decide which agent should handle them based on their capabilities:
                    
                    - monitoring_agent: CloudWatch logs, metrics, alarms, dashboards, AWS service monitoring, root cause analysis, infrastructure discovery
                    - ops_orchestrator: JIRA tickets, GitHub issues, incident management, team coordination, workflow automation
                    
                    Respond with ONLY the agent_id (either "monitoring_agent" or "ops_orchestrator").
                    No explanation needed, just the agent name."""
                )
                self.routing_enabled = True
                print("🧠 Strands intelligent router initialized")
            except Exception as e:
                print(f"⚠️ Failed to initialize Strands router: {e}")
        
        # Fallback to Bedrock Runtime for LiteLLM approach
        elif BEDROCK_RUNTIME_AVAILABLE:
            try:
                self.bedrock_runtime = boto3.client('bedrock-runtime', region_name=region)
                self.routing_enabled = True
                print("🧠 Bedrock LiteLLM router initialized")
            except Exception as e:
                print(f"⚠️ Failed to initialize Bedrock runtime: {e}")
        
        if not self.routing_enabled:
            print("⚠️ No intelligent routing available - falling back to hardcoded routing")
    
    async def select_agent(self, query: str, available_agents: Dict[str, Any]) -> str:
        """
        Use LLM to intelligently select which agent should handle the query
        
        Args:
            query: User's request/message
            available_agents: Dictionary of available agents with their cards
            
        Returns:
            agent_id: The ID of the selected agent
        """
        if not self.routing_enabled:
            return self._fallback_routing(query)
        
        try:
            # First try Strands agent approach
            if self.router_agent:
                return await self._route_with_strands(query, available_agents)
            
            # Fallback to Bedrock LiteLLM approach
            elif self.bedrock_runtime:
                return await self._route_with_bedrock(query, available_agents)
            
        except Exception as e:
            print(f"⚠️ Intelligent routing failed: {e}")
            return self._fallback_routing(query)
        
        return self._fallback_routing(query)
    
    async def _route_with_strands(self, query: str, available_agents: Dict[str, Any]) -> str:
        """Route using Strands agent"""
        # Build context with agent capabilities
        agent_capabilities = {}
        for agent_id, agent_info in available_agents.items():
            card = agent_info.get("card", {})
            if "skills" in card:
                skills = [skill.get("name", "") + ": " + skill.get("description", "") 
                         for skill in card["skills"]]
                agent_capabilities[agent_id] = skills
            else:
                agent_capabilities[agent_id] = [card.get("description", "")]
        
        context = f"""
Query to route: "{query}"

Available agents and their capabilities:
{json.dumps(agent_capabilities, indent=2)}

Which agent should handle this query?
"""
        
        # Use Strands agent to make decision
        result = await self.router_agent.run(context)
        selected_agent = result.content.strip().lower()
        
        # Validate and clean the response
        if "monitoring_agent" in selected_agent:
            return "monitoring_agent"
        elif "ops_orchestrator" in selected_agent:
            return "ops_orchestrator"
        else:
            print(f"⚠️ Invalid agent selection: {selected_agent}")
            return self._fallback_routing(query)
    
    async def _route_with_bedrock(self, query: str, available_agents: Dict[str, Any]) -> str:
        """Route using Bedrock LiteLLM approach"""
        # Build agent capabilities summary
        agent_summary = []
        for agent_id, agent_info in available_agents.items():
            card = agent_info.get("card", {})
            description = card.get("description", "")
            if "skills" in card:
                skills = [skill.get("name") for skill in card["skills"][:5]]  # Top 5 skills
                description += f" Skills: {', '.join(skills)}"
            agent_summary.append(f"- {agent_id}: {description}")
        
        prompt = f"""Human: You are an intelligent agent router. Analyze this query and decide which agent should handle it.

Query: "{query}"

Available agents:
{chr(10).join(agent_summary)}

Respond with ONLY the agent_id (monitoring_agent or ops_orchestrator). No explanation.
        """
        
        try:
            response = self.bedrock_runtime.invoke_model(
                modelId="anthropic.claude-3-5-sonnet-20240620-v1:0",
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 100,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1
                })
            )
            
            response_body = json.loads(response.get('body').read())
            selected_agent = response_body['content'][0]['text'].strip().lower()
            
            # Validate and clean the response
            if "monitoring_agent" in selected_agent:
                return "monitoring_agent"
            elif "ops_orchestrator" in selected_agent:
                return "ops_orchestrator"
            else:
                print(f"⚠️ Invalid agent selection: {selected_agent}")
                return self._fallback_routing(query)
                
        except Exception as e:
            print(f"⚠️ Bedrock routing failed: {e}")
            return self._fallback_routing(query)
    
    def _fallback_routing(self, query: str) -> str:
        """Fallback to rule-based routing when LLM routing fails"""
        query_lower = query.lower()
        
        # Keywords that suggest monitoring agent
        monitoring_keywords = [
            'cloudwatch', 'logs', 'metrics', 'alarm', 'dashboard', 'monitoring',
            'cpu', 'memory', 'disk', 'network', 'performance', 'latency',
            'error rate', 'health check', 'aws service', 'infrastructure'
        ]
        
        # Keywords that suggest ops orchestrator
        ops_keywords = [
            'jira', 'ticket', 'github', 'issue', 'incident', 'coordinate',
            'notify', 'team', 'escalate', 'assign', 'workflow', 'automation',
            'create issue', 'update ticket', 'documentation'
        ]
        
        monitoring_score = sum(1 for keyword in monitoring_keywords if keyword in query_lower)
        ops_score = sum(1 for keyword in ops_keywords if keyword in query_lower)
        
        if monitoring_score > ops_score:
            print(f"🔄 Fallback routing: monitoring_agent (score: {monitoring_score})")
            return "monitoring_agent"
        elif ops_score > monitoring_score:
            print(f"🔄 Fallback routing: ops_orchestrator (score: {ops_score})")
            return "ops_orchestrator"
        else:
            # Default to monitoring for ambiguous queries
            print(f"🔄 Fallback routing: monitoring_agent (default)")
            return "monitoring_agent"


class A2AService:
    """
    A2A Protocol Compliant Communication Service
    
    Implements the Agent2Agent protocol for communication between agents
    using AWS Bedrock AgentCore runtime with proper A2A structures.
    Enhanced with intelligent LLM-based agent routing.
    """
    
    def __init__(self, region: str = "us-west-2", use_intelligent_routing: bool = True):
        self.region = region
        self.client = boto3.client('bedrock-agentcore', region_name=region)
        
        # Initialize intelligent router
        self.use_intelligent_routing = use_intelligent_routing
        self.router = None
        if use_intelligent_routing:
            try:
                self.router = IntelligentA2ARouter(region)
                print(f"🧠 Intelligent routing enabled")
            except Exception as e:
                print(f"⚠️ Failed to initialize intelligent router: {e}")
                self.use_intelligent_routing = False
        
        # A2A Agent Registry with Agent Cards
        # In this, the arn of the agent is the arn that is used to connect to the agent 
        # runtime object over bedrock agentcore
        self.agents = {
            "monitoring_agent": {
                "arn": "arn:aws:bedrock-agentcore:us-west-2",
                "card": self._create_monitoring_agent_card()
            },
            "ops_orchestrator": {
                "arn": "arn:aws:bedrock-agentcore:us-west-2:",
                "card": self._create_ops_orchestrator_card()
            }
        }
        
        # A2A Task Registry
        self.tasks = {}
        # to maintain the session of the multi-turn conversation
        self.session_id = f"a2a_session_{int(time.time())}_{str(uuid.uuid4())[:8]}"
        
        print(f"🤖 A2A Protocol Service initialized")
        print(f"📊 Registered Agents: {list(self.agents.keys())}")
        print(f"🆔 Session ID: {self.session_id}")
    
    def _create_monitoring_agent_card(self) -> Dict[str, Any]:
        """Create A2A compliant Agent Card for monitoring agent"""
        with open(MONITORING_AGENT_SKILLS, 'r') as f:
            data = json.load(f)
            print(f"loading the monitoring agent card: {data}")
            return data
    
    def _create_ops_orchestrator_card(self) -> Dict[str, Any]:
        """Create A2A compliant Agent Card for ops orchestrator agent"""
        with open(INCIDENT_AGENT_SKILLS, 'r') as f:
            data = json.load(f)
            print(f"loading the ops agent card: {data}")
            return data
    
    def get_agent_card(self, agent_id: str) -> Dict[str, Any]:
        """Get A2A compliant Agent Card for discovery"""
        if agent_id not in self.agents:
            raise ValueError(f"Unknown agent: {agent_id}")
        return self.agents[agent_id]["card"]
    
    def list_agents(self) -> List[str]:
        """List available agents for discovery"""
        return list(self.agents.keys())
    
    async def create_task_with_intelligent_routing(self, initial_message: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Create A2A task with intelligent agent selection
        
        Uses LLM-based routing to automatically select the best agent for the task
        """
        if self.use_intelligent_routing and self.router:
            try:
                selected_agent = await self.router.select_agent(initial_message, self.agents)
                print(f"🧠 Intelligent routing selected: {selected_agent}")
            except Exception as e:
                print(f"⚠️ Intelligent routing failed, using fallback: {e}")
                selected_agent = self.router._fallback_routing(initial_message) if self.router else "monitoring_agent"
        else:
            # Default fallback routing
            selected_agent = "monitoring_agent"
            print(f"🔄 Using default agent: {selected_agent}")
        
        return self.create_task(selected_agent, initial_message, context)
    
    def create_task(self, agent_id: str, initial_message: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """Create A2A compliant task with proper lifecycle"""
        if agent_id not in self.agents:
            raise ValueError(f"Unknown agent: {agent_id}")
        
        task_id = str(uuid.uuid4())
        task = {
            "id": task_id,
            "agent_id": agent_id,
            "state": TaskState.SUBMITTED.value,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "messages": [],
            "artifacts": [],
            "context": context or {},
            "metadata": {
                "session_id": self.session_id,
                "protocol_version": "a2a-1.0"
            }
        }
        
        # Add initial message
        initial_msg = self._create_message(MessageRole.USER.value, initial_message, task_id)
        task["messages"].append(initial_msg)
        
        self.tasks[task_id] = task
        print(f"📝 Created A2A Task {task_id} for agent {agent_id}")
        return task
    
    def _create_message(self, role: str, content: str, task_id: str, parts: Optional[List] = None) -> Dict[str, Any]:
        """Create A2A compliant message structure"""
        message = {
            "id": str(uuid.uuid4()),
            "task_id": task_id,
            "role": role,
            "timestamp": datetime.utcnow().isoformat(),
            "parts": parts or [
                {
                    "type": PartType.TEXT.value,
                    "content": content
                }
            ]
        }
        return message
    
    def _update_task_state(self, task_id: str, new_state: TaskState, message: Optional[str] = None) -> None:
        """Update task state following A2A lifecycle"""
        if task_id not in self.tasks:
            raise ValueError(f"Unknown task: {task_id}")
        
        task = self.tasks[task_id]
        old_state = task["state"]
        task["state"] = new_state.value
        task["updated_at"] = datetime.utcnow().isoformat()
        
        if message:
            task["status_message"] = message
        
        print(f"🔄 Task {task_id}: {old_state} → {new_state.value}")
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get A2A compliant task status"""
        if task_id not in self.tasks:
            raise ValueError(f"Unknown task: {task_id}")
        
        task = self.tasks[task_id]
        return {
            "task_id": task_id,
            "state": task["state"],
            "message": task.get("status_message"),
            "timestamp": task["updated_at"],
            "final": task["state"] in [TaskState.COMPLETED.value, TaskState.CANCELED.value, TaskState.FAILED.value, TaskState.REJECTED.value]
        }
    
    async def send_message(self, task_id: str, message_content: str, role: str = MessageRole.USER.value, 
                          allow_agent_switching: bool = False) -> Dict[str, Any]:
        """
        Send A2A compliant message to agent and get response
        
        Args:
            task_id: The task ID to send the message to
            message_content: The message content
            role: The role of the sender
            allow_agent_switching: If True, allows intelligent routing to switch agents mid-conversation
        """
        if task_id not in self.tasks:
            raise ValueError(f"Unknown task: {task_id}")
        
        task = self.tasks[task_id]
        agent_id = task["agent_id"]
        
        # Optional intelligent agent switching mid-conversation
        if allow_agent_switching and self.use_intelligent_routing and self.router:
            try:
                suggested_agent = await self.router.select_agent(message_content, self.agents)
                if suggested_agent != agent_id:
                    print(f"🔄 Intelligent routing suggests switching from {agent_id} to {suggested_agent}")
                    # Ask user or auto-switch based on configuration
                    agent_id = suggested_agent
                    task["agent_id"] = agent_id
                    task["agent_switches"] = task.get("agent_switches", 0) + 1
                    print(f"✅ Switched to {agent_id} (switches: {task['agent_switches']})")
            except Exception as e:
                print(f"⚠️ Agent switching failed: {e}")
        
        # Check if task is in terminal state
        if task["state"] in [TaskState.COMPLETED.value, TaskState.CANCELED.value, TaskState.FAILED.value, TaskState.REJECTED.value]:
            raise ValueError(f"Cannot send message to task in terminal state: {task['state']}")
        
        # Update task state to working
        self._update_task_state(task_id, TaskState.WORKING, "Processing message")
        
        # Create and add message to task
        message = self._create_message(role, message_content, task_id)
        task["messages"].append(message)
        
        print(f"\n💬 Sending A2A message to {agent_id}")
        print(f"Task: {task_id}")
        print(f"Message: {message_content[:100]}...")
        
        try:
            # Route to appropriate agent
            if agent_id == "monitoring_agent":
                response_content = await self._invoke_monitoring_agent(task)
            elif agent_id == "ops_orchestrator":
                response_content = await self._invoke_ops_orchestrator(task)
            else:
                raise ValueError(f"Unknown agent: {agent_id}")
            
            # Create response message
            response_message = self._create_message(MessageRole.AGENT.value, response_content, task_id)
            task["messages"].append(response_message)
            
            # Update task state to completed
            self._update_task_state(task_id, TaskState.COMPLETED, "Message processed successfully")
            
            print(f"✅ A2A message processed successfully")
            return {
                "task_id": task_id,
                "message": response_message,
                "status": self.get_task_status(task_id)
            }
            
        except Exception as e:
            self._update_task_state(task_id, TaskState.FAILED, f"Error: {str(e)}")
            error_msg = f"❌ A2A message failed: {str(e)}"
            print(error_msg)
            raise Exception(error_msg)
    
    async def _invoke_monitoring_agent(self, task: Dict[str, Any]) -> str:
        """Invoke monitoring agent with A2A context"""
        # Build A2A compliant prompt with full context
        a2a_prompt = self._build_a2a_prompt(task, "monitoring_agent")
        
        response = invoke_monitoring_agent(
            agent_arn=self.agents["monitoring_agent"]["arn"],
            region=self.region,
            prompt=a2a_prompt,
            qualifier="DEFAULT",
            stream=True
        )
        return response
    
    async def _invoke_ops_orchestrator(self, task: Dict[str, Any]) -> str:
        """Invoke ops orchestrator agent with A2A context"""
        # Build A2A compliant prompt with full context
        a2a_prompt = self._build_a2a_prompt(task, "ops_orchestrator")
        
        payload = {
            "prompt": a2a_prompt,
            "stream": True,
            "a2a_context": {
                "task_id": task["id"],
                "agent_card": self.agents["ops_orchestrator"]["card"],
                "protocol_version": "a2a-1.0"
            }
        }
        
        response = self.client.invoke_agent_runtime(
            agentRuntimeArn=self.agents["ops_orchestrator"]["arn"],
            qualifier="DEFAULT",
            payload=json.dumps(payload)
        )
        
        # Process streaming response
        response_content = ""
        if "text/event-stream" in response.get("contentType", ""):
            for line in response["response"].iter_lines(chunk_size=1):
                if line:
                    line_text = line.decode("utf-8")
                    if line_text.startswith("data: "):
                        data_part = line_text[6:]
                        try:
                            data_json = json.loads(data_part)
                            if isinstance(data_json, str):
                                response_content += data_json
                            elif 'text' in data_json:
                                response_content += data_json['text']
                            else:
                                response_content += data_part
                        except json.JSONDecodeError:
                            response_content += data_part
        else:
            response_data = response.get("response", [])
            if hasattr(response_data, '__iter__') and not isinstance(response_data, (str, bytes)):
                for event in response_data:
                    if hasattr(event, 'decode'):
                        response_content += event.decode("utf-8")
                    else:
                        response_content += str(event)
            else:
                if isinstance(response_data, bytes):
                    response_content = response_data.decode("utf-8")
                else:
                    response_content = str(response_data)
        
        return response_content
    
    def _build_a2a_prompt(self, task: Dict[str, Any], agent_id: str) -> str:
        """Build A2A compliant prompt with full context"""
        agent_card = self.agents[agent_id]["card"]
        
        # Get latest user message
        user_messages = [msg for msg in task["messages"] if msg["role"] == MessageRole.USER.value]
        latest_message = user_messages[-1] if user_messages else {"parts": [{"content": "No message"}]}
        latest_content = latest_message["parts"][0]["content"]
        
        prompt = f"""
[A2A Protocol Communication]

Agent Card: {json.dumps(agent_card, indent=2)}

Task Context:
- Task ID: {task["id"]}
- State: {task["state"]}
- Created: {task["created_at"]}
- Session: {task["metadata"]["session_id"]}
- Protocol: {task["metadata"]["protocol_version"]}

Message History:
{self._format_message_history(task["messages"])}

Current Request:
{latest_content}

Please respond according to your agent card capabilities and provide a detailed response that follows A2A protocol standards.
"""
        return prompt
    
    def _format_message_history(self, messages: List[Dict]) -> str:
        """Format message history for context"""
        formatted = []
        for msg in messages:
            role = "🧑 User" if msg["role"] == MessageRole.USER.value else "🤖 Agent"
            content = msg["parts"][0]["content"][:100] + "..." if len(msg["parts"][0]["content"]) > 100 else msg["parts"][0]["content"]
            formatted.append(f"{role}: {content}")
        return "\n".join(formatted)
    
    # Intelligent routing convenience methods
    async def send_intelligent_message(self, message: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Send a message with automatic intelligent agent selection
        
        This is the main entry point for intelligent A2A communication
        """
        task = await self.create_task_with_intelligent_routing(message, context)
        return await self.send_message(task["id"], message)
    
    async def continue_conversation(self, task_id: str, message: str, allow_switching: bool = True) -> Dict[str, Any]:
        """
        Continue a conversation with optional intelligent agent switching
        """
        return await self.send_message(task_id, message, allow_agent_switching=allow_switching)
    
    # Legacy compatibility methods
    async def ops_to_monitoring(self, prompt: str, context: Optional[Dict] = None) -> str:
        """Legacy method - creates task and sends message to monitoring agent"""
        task = self.create_task("monitoring_agent", prompt, context)
        result = await self.send_message(task["id"], prompt)
        return result["message"]["parts"][0]["content"]
    
    async def monitoring_to_ops(self, prompt: str, context: Optional[Dict] = None) -> str:
        """Legacy method - creates task and sends message to ops orchestrator"""
        task = self.create_task("ops_orchestrator", prompt, context)
        result = await self.send_message(task["id"], prompt)
        return result["message"]["parts"][0]["content"]
    
    async def coordinate_incident_response(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        A2A compliant coordinated incident response between agents
        
        Args:
            incident_data: Incident details and context
            
        Returns:
            Coordinated response with A2A task tracking
        """
        print(f"\n🚨 A2A Coordinated Incident Response")
        print(f"Incident: {incident_data.get('summary', 'Unknown incident')}")
        
        # Step 1: Create monitoring analysis task
        monitoring_request = f"""
        Incident Analysis Request:
        
        Summary: {incident_data.get('summary', 'Unknown incident')}
        Details: {json.dumps(incident_data, indent=2)}
        
        Please provide:
        1. Root cause analysis
        2. Impact assessment
        3. Related metrics and logs analysis
        4. Recommended immediate actions
        """
        
        monitoring_task = self.create_task("monitoring_agent", monitoring_request, incident_data)
        monitoring_result = await self.send_message(monitoring_task["id"], monitoring_request)
        monitoring_response = monitoring_result["message"]["parts"][0]["content"]
        
        # Step 2: Create ops coordination task
        ops_request = f"""
        Incident Coordination Request:
        
        Incident Data: {json.dumps(incident_data, indent=2)}
        
        Monitoring Agent Analysis:
        {monitoring_response}
        
        Please coordinate response actions:
        1. Create appropriate tickets in JIRA
        2. Send notifications to relevant teams
        3. Create incident documentation in GitHub
        4. Set up monitoring for resolution
        """
        
        ops_task = self.create_task("ops_orchestrator", ops_request, {
            "incident_data": incident_data,
            "monitoring_analysis": monitoring_response,
            "monitoring_task_id": monitoring_task["id"]
        })
        ops_result = await self.send_message(ops_task["id"], ops_request)
        ops_response = ops_result["message"]["parts"][0]["content"]
        
        # Return A2A compliant coordinated response
        return {
            "incident_id": incident_data.get("id", str(uuid.uuid4())),
            "timestamp": datetime.utcnow().isoformat(),
            "monitoring_task": {
                "task_id": monitoring_task["id"],
                "status": self.get_task_status(monitoring_task["id"]),
                "analysis": monitoring_response
            },
            "ops_task": {
                "task_id": ops_task["id"],
                "status": self.get_task_status(ops_task["id"]),
                "coordination": ops_response
            },
            "status": "a2a_coordinated_response_complete",
            "protocol_version": "a2a-1.0"
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """
        A2A compliant health check for all registered agents
        
        Returns:
            Health status with A2A task tracking
        """
        print(f"\n🏥 A2A Protocol Health Check")
        
        agent_health = {}
        
        for agent_id in self.agents.keys():
            try:
                # Create health check task
                health_message = f"Health check: Please confirm you are operational and list your available capabilities based on your agent card."
                task = self.create_task(agent_id, health_message)
                result = await self.send_message(task["id"], health_message)
                
                response_content = result["message"]["parts"][0]["content"]
                healthy = "error" not in response_content.lower() and result["status"]["state"] == TaskState.COMPLETED.value
                
                agent_health[agent_id] = {
                    "healthy": healthy,
                    "task_id": task["id"],
                    "status": result["status"],
                    "response_preview": response_content[:100] + "..." if len(response_content) > 100 else response_content
                }
                
            except Exception as e:
                agent_health[agent_id] = {
                    "healthy": False,
                    "error": str(e),
                    "task_id": None,
                    "status": {"state": TaskState.FAILED.value}
                }
        
        all_healthy = all(agent["healthy"] for agent in agent_health.values())
        
        status = {
            "agents": agent_health,
            "a2a_service_healthy": all_healthy,
            "protocol_version": "a2a-1.0",
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": self.session_id
        }
        
        # Print status
        for agent_id, health in agent_health.items():
            emoji = "✅" if health["healthy"] else "❌"
            status_text = "Healthy" if health["healthy"] else "Unhealthy"
            print(f"🤖 {agent_id}: {emoji} {status_text}")
        
        print(f"🔧 A2A Service: {'✅ Operational' if all_healthy else '❌ Degraded'}")
        
        return status

async def demo_intelligent_a2a_routing():
    """
    Demonstration of Intelligent A2A Routing capabilities
    """
    print("🧠 Starting Intelligent A2A Routing Demo")
    print("=" * 60)
    
    a2a = A2AService(use_intelligent_routing=True)
    
    # Demo intelligent routing with various queries
    test_queries = [
        {
            "query": "Check CloudWatch alarms for high CPU usage in EC2 instances",
            "expected": "monitoring_agent"
        },
        {
            "query": "Create a JIRA ticket for database performance issue and assign to DevOps team",
            "expected": "ops_orchestrator"
        },
        {
            "query": "Analyze error logs from Lambda functions for the past hour",
            "expected": "monitoring_agent"
        },
        {
            "query": "Update GitHub issue #123 with incident resolution steps and close it",
            "expected": "ops_orchestrator"
        },
        {
            "query": "Monitor API Gateway latency metrics and check for anomalies",
            "expected": "monitoring_agent"
        }
    ]
    
    print("\\n🎯 Testing Intelligent Agent Selection:")
    for i, test in enumerate(test_queries, 1):
        print(f"\\n{i}️⃣ Query: {test['query'][:80]}...")
        print(f"   Expected: {test['expected']}")
        
        try:
            result = await a2a.send_intelligent_message(test['query'])
            actual_agent = a2a.tasks[result['task_id']]['agent_id']
            status = "✅ CORRECT" if actual_agent == test['expected'] else "❌ INCORRECT"
            print(f"   Selected: {actual_agent} {status}")
            print(f"   Response: {result['message']['parts'][0]['content'][:100]}...")
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    print("\\n✅ Intelligent A2A Routing Demo Complete!")
    print("=" * 60)

async def demo_a2a_communication():
    """
    Demonstration of A2A Protocol compliant communication capabilities
    """
    print("🚀 Starting A2A Protocol Communication Demo")
    print("=" * 60)
    
    a2a = A2AService()
    
    # Demo 1: Agent Discovery
    print("\n1️⃣ Agent Discovery Demo")
    print("Available agents:", a2a.list_agents())
    for agent_id in a2a.list_agents():
        card = a2a.get_agent_card(agent_id)
        print(f"  - {card['name']}: {card['description'][:80]}...")
    
    # Demo 2: Health check
    print("\n2️⃣ A2A Health Check Demo")
    await a2a.health_check()
    
    # Demo 3: Task-based communication
    print("\n3️⃣ A2A Task-Based Communication Demo")
    ops_message = """
    We've received reports of high response times in our API Gateway. 
    Can you analyze the CloudWatch logs and metrics for the last 2 hours and identify:
    1. Error rates and patterns
    2. Performance bottlenecks
    3. Any related AWS service issues
    4. Recommended remediation steps
    """
    
    # Create task and send message
    task = a2a.create_task("monitoring_agent", ops_message)
    print(f"Created task: {task['id']}")
    
    result = await a2a.send_message(task["id"], ops_message)
    print(f"Task Status: {result['status']['state']}")
    print(f"Response Preview: {result['message']['parts'][0]['content'][:200]}...")
    
    # Demo 4: Coordinated incident response
    print("\n4️⃣ A2A Coordinated Incident Response Demo")
    incident = {
        "id": "INC-2025-001",
        "summary": "Database performance degradation affecting user authentication",
        "severity": "high",
        "affected_services": ["RDS", "Lambda", "API Gateway"],
        "user_impact": "Login failures for 15% of users",
        "detection_time": datetime.utcnow().isoformat()
    }
    
    coordinated_response = await a2a.coordinate_incident_response(incident)
    print(f"\n📋 A2A Coordinated Response Summary:")
    print(f"   Incident ID: {coordinated_response['incident_id']}")
    print(f"   Protocol Version: {coordinated_response['protocol_version']}")
    print(f"   Monitoring Task: {coordinated_response['monitoring_task']['status']['state']}")
    print(f"   Ops Task: {coordinated_response['ops_task']['status']['state']}")
    print(f"   Status: {coordinated_response['status']}")
    
    print("\n✅ A2A Protocol Communication Demo Complete!")
    print("=" * 60)

def main():
    """Main function with CLI interface"""
    parser = argparse.ArgumentParser(description="A2A Protocol Communication Service with Intelligent Routing")
    parser.add_argument("--demo", action="store_true", help="Run A2A protocol communication demo")
    parser.add_argument("--intelligent-demo", action="store_true", help="Run intelligent routing demo")
    parser.add_argument("--health", action="store_true", help="Run A2A health check")
    parser.add_argument("--list-agents", action="store_true", help="List available agents")
    parser.add_argument("--agent-card", type=str, help="Get agent card for specified agent")
    parser.add_argument("--create-task", nargs=2, metavar=('AGENT_ID', 'MESSAGE'), help="Create task for agent")
    parser.add_argument("--intelligent-message", type=str, help="Send message with intelligent agent selection")
    parser.add_argument("--ops-to-monitoring", type=str, help="Send message from ops to monitoring (legacy)")
    parser.add_argument("--monitoring-to-ops", type=str, help="Send message from monitoring to ops (legacy)")
    
    args = parser.parse_args()
    
    if args.demo:
        asyncio.run(demo_a2a_communication())
    elif args.intelligent_demo:
        asyncio.run(demo_intelligent_a2a_routing())
    elif args.intelligent_message:
        a2a = A2AService(use_intelligent_routing=True)
        result = asyncio.run(a2a.send_intelligent_message(args.intelligent_message))
        print(f"Task ID: {result['task_id']}")
        print(f"Selected Agent: {a2a.tasks[result['task_id']]['agent_id']}")
        print(f"Status: {result['status']['state']}")
        print(f"Response: {result['message']['parts'][0]['content']}")
    elif args.health:
        a2a = A2AService()
        asyncio.run(a2a.health_check())
    elif args.list_agents:
        a2a = A2AService()
        print("Available A2A agents:", a2a.list_agents())
    elif args.agent_card:
        a2a = A2AService()
        try:
            card = a2a.get_agent_card(args.agent_card)
            print(json.dumps(card, indent=2))
        except ValueError as e:
            print(f"Error: {e}")
    elif args.create_task:
        agent_id, message = args.create_task
        a2a = A2AService()
        task = a2a.create_task(agent_id, message)
        result = asyncio.run(a2a.send_message(task["id"], message))
        print(f"Task ID: {result['task_id']}")
        print(f"Status: {result['status']['state']}")
        print(f"Response: {result['message']['parts'][0]['content']}")
    elif args.ops_to_monitoring:
        a2a = A2AService()
        response = asyncio.run(a2a.ops_to_monitoring(args.ops_to_monitoring))
        print(f"\n📋 Response:\n{response}")
    elif args.monitoring_to_ops:
        a2a = A2AService()
        response = asyncio.run(a2a.monitoring_to_ops(args.monitoring_to_ops))
        print(f"\n📋 Response:\n{response}")
    else:
        # Interactive mode
        print("🤖 A2A Protocol Communication Service - Interactive Mode")
        print("🧠 Enhanced with Intelligent LLM-based Agent Routing")
        print("=" * 60)
        print("1. Run demo: python a2a_communication_compliant.py --demo")
        print("2. Intelligent routing demo: python a2a_communication_compliant.py --intelligent-demo")
        print("3. Health check: python a2a_communication_compliant.py --health")
        print("4. List agents: python a2a_communication_compliant.py --list-agents")
        print("5. Get agent card: python a2a_communication_compliant.py --agent-card monitoring_agent")
        print("6. Create task: python a2a_communication_compliant.py --create-task monitoring_agent 'Check CPU usage'")
        print("7. Intelligent message: python a2a_communication_compliant.py --intelligent-message 'Check CloudWatch alarms'")
        print("8. Legacy ops→monitoring: python a2a_communication_compliant.py --ops-to-monitoring 'message'")
        print("9. Legacy monitoring→ops: python a2a_communication_compliant.py --monitoring-to-ops 'message'")

if __name__ == "__main__":
    main()