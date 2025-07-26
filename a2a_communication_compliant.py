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
from datetime import datetime
from dotenv import load_dotenv
from typing import Dict, Any, Optional, List
from enum import Enum
from botocore.exceptions import ClientError

# Load environment variables
load_dotenv()

# Import the existing invoke_agent functionality
sys.path.append(os.path.join(os.path.dirname(__file__), 'multi-agents'))
from invoke_agent import invoke_monitoring_agent

# A2A Protocol Enums and Types
class TaskState(Enum):
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

class A2AService:
    """
    A2A Protocol Compliant Communication Service
    
    Implements the Agent2Agent protocol for communication between agents
    using AWS Bedrock AgentCore runtime with proper A2A structures.
    """
    
    def __init__(self, region: str = "us-west-2"):
        self.region = region
        self.client = boto3.client('bedrock-agentcore', region_name=region)
        
        # A2A Agent Registry with Agent Cards
        self.agents = {
            "monitoring_agent": {
                "arn": "arn:aws:bedrock-agentcore:us-west-2:218208277580:runtime/monitoring_agent-MlJQsnFk04",
                "card": self._create_monitoring_agent_card()
            },
            "ops_orchestrator": {
                "arn": "arn:aws:bedrock-agentcore:us-west-2:218208277580:runtime/ops_orchestrator_multi_agent-db8C1qCrVP",
                "card": self._create_ops_orchestrator_card()
            }
        }
        
        # A2A Task Registry
        self.tasks = {}
        self.session_id = f"a2a_session_{int(time.time())}_{str(uuid.uuid4())[:8]}"
        
        print(f"🤖 A2A Protocol Service initialized")
        print(f"📊 Registered Agents: {list(self.agents.keys())}")
        print(f"🆔 Session ID: {self.session_id}")
    
    def _create_monitoring_agent_card(self) -> Dict[str, Any]:
        """Create A2A compliant Agent Card for monitoring agent"""
        return {
            "name": "CloudWatch Monitoring Agent",
            "description": "Advanced monitoring and analysis agent for AWS CloudWatch metrics, logs, and infrastructure health",
            "url": "arn:aws:bedrock-agentcore:us-west-2:218208277580:runtime/monitoring_agent-MlJQsnFk04",
            "provider": {
                "organization": "AWS Infrastructure Team",
                "url": "https://aws.amazon.com/bedrock"
            },
            "version": "1.0.0",
            "capabilities": {
                "streaming": True,
                "pushNotifications": False,
                "stateTransitionHistory": True
            },
            "authentication": {
                "schemes": ["AWS4-HMAC-SHA256"]
            },
            "defaultInputModes": ["text"],
            "defaultOutputModes": ["text", "data"],
            "skills": [
                {
                    "id": "cloudwatch_analysis",
                    "name": "CloudWatch Metrics Analysis",
                    "description": "Analyze CloudWatch metrics for anomalies and performance issues",
                    "tags": ["monitoring", "metrics", "cloudwatch"],
                    "inputModes": ["text"],
                    "outputModes": ["text", "data"]
                },
                {
                    "id": "root_cause_analysis",
                    "name": "Root Cause Analysis",
                    "description": "Deep dive analysis to identify root causes of system issues",
                    "tags": ["analysis", "troubleshooting"],
                    "inputModes": ["text"],
                    "outputModes": ["text", "data"]
                }
            ]
        }
    
    def _create_ops_orchestrator_card(self) -> Dict[str, Any]:
        """Create A2A compliant Agent Card for ops orchestrator agent"""
        return {
            "name": "Operations Orchestrator Agent",
            "description": "Multi-agent orchestrator for incident management, ticket creation, and team coordination",
            "url": "arn:aws:bedrock-agentcore:us-west-2:218208277580:runtime/ops_orchestrator_multi_agent-db8C1qCrVP",
            "provider": {
                "organization": "AWS Operations Team",
                "url": "https://aws.amazon.com/bedrock"
            },
            "version": "1.0.0",
            "capabilities": {
                "streaming": True,
                "pushNotifications": True,
                "stateTransitionHistory": True
            },
            "authentication": {
                "schemes": ["AWS4-HMAC-SHA256"]
            },
            "defaultInputModes": ["text"],
            "defaultOutputModes": ["text", "data"],
            "skills": [
                {
                    "id": "incident_management",
                    "name": "Incident Management",
                    "description": "Coordinate incident response including ticket creation and team notifications",
                    "tags": ["incident", "coordination", "jira"],
                    "inputModes": ["text"],
                    "outputModes": ["text", "data"]
                },
                {
                    "id": "team_coordination",
                    "name": "Team Coordination",
                    "description": "Notify relevant teams and coordinate response actions",
                    "tags": ["coordination", "notifications"],
                    "inputModes": ["text"],
                    "outputModes": ["text", "data"]
                }
            ]
        }
    
    def get_agent_card(self, agent_id: str) -> Dict[str, Any]:
        """Get A2A compliant Agent Card for discovery"""
        if agent_id not in self.agents:
            raise ValueError(f"Unknown agent: {agent_id}")
        return self.agents[agent_id]["card"]
    
    def list_agents(self) -> List[str]:
        """List available agents for discovery"""
        return list(self.agents.keys())
    
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
    
    async def send_message(self, task_id: str, message_content: str, role: str = MessageRole.USER.value) -> Dict[str, Any]:
        """Send A2A compliant message to agent and get response"""
        if task_id not in self.tasks:
            raise ValueError(f"Unknown task: {task_id}")
        
        task = self.tasks[task_id]
        agent_id = task["agent_id"]
        
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
    parser = argparse.ArgumentParser(description="A2A Protocol Communication Service")
    parser.add_argument("--demo", action="store_true", help="Run A2A protocol communication demo")
    parser.add_argument("--health", action="store_true", help="Run A2A health check")
    parser.add_argument("--list-agents", action="store_true", help="List available agents")
    parser.add_argument("--agent-card", type=str, help="Get agent card for specified agent")
    parser.add_argument("--create-task", nargs=2, metavar=('AGENT_ID', 'MESSAGE'), help="Create task for agent")
    parser.add_argument("--ops-to-monitoring", type=str, help="Send message from ops to monitoring (legacy)")
    parser.add_argument("--monitoring-to-ops", type=str, help="Send message from monitoring to ops (legacy)")
    
    args = parser.parse_args()
    
    if args.demo:
        asyncio.run(demo_a2a_communication())
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
        print("=" * 50)
        print("1. Run demo: python a2a_communication_compliant.py --demo")
        print("2. Health check: python a2a_communication_compliant.py --health")
        print("3. List agents: python a2a_communication_compliant.py --list-agents")
        print("4. Get agent card: python a2a_communication_compliant.py --agent-card monitoring_agent")
        print("5. Create task: python a2a_communication_compliant.py --create-task monitoring_agent 'Check CPU usage'")
        print("6. Legacy ops→monitoring: python a2a_communication_compliant.py --ops-to-monitoring 'message'")
        print("7. Legacy monitoring→ops: python a2a_communication_compliant.py --monitoring-to-ops 'message'")

if __name__ == "__main__":
    main()