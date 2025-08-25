# Incident response logging system: Using A2A for Strands and OpenAI agents hosted on Bedrock AgentCore

In this example, we will be setting up an A2A example for building an application where the host or the client agent is enabled to look for incidents and metrics in the AWS account, create JIRA tickets and then also search for the remediation strategies for those issues with the help of capabilities and tools that are offered by two agents:

1. `Strands agent on AgentCore`: This agent is built using Strands and uses all primitives on AgentCore. It is hosted over `HTTP` and uses `OAuth` for identity. In this case, this agent has access to tools and capabilities to get any metrics and interact with your AWS account in natural language and have the ability to create JIRA tickets based on the issues encountered and assign it to the required members.

2. `OpenAI agent on AgentCore`: This agent is built using OpenAI and uses all primitives on AgentCore. It is hosted over `HTTP` and uses `OAuth` for identity. In this case, this agent has access to tools and capabilities to search for remediation strategies on issues that the first agent comes up with.

Our goal is to build a multi-agentic implementation where we can talk to both of these agents built on different frameworks running on agentcore runtime.

## What is A2A

A2A protocol is an open protocol that enables AI agents to communicate and collaborate across different platforms and frameworks, regardless of their underlying technologies. It is designed to maximize the benefits of agentic AI by enabling true multi-agent scenarios. This protocol enables us to have completely opaque systems or agents communicate with one another over standard agent to agent protocol (JSON RPC 2.0) and supports any framework, language or different vendors. In this case, the protocol allows for the following:

1. Discover each other's capabilities.

2. Negotiate interaction modalities (text, files and structured data).

3. Manage collaborative tasks and securely exchange information to achieve user goals without needing access to each other's internal state, memory or tools.

## About this solution

This solution demonstrates a multi-agent A2A (Agent-to-Agent) implementation for incident response and logging systems. It consists of three main components:

### Components

**A2A Client (Host Agent)**: A Google ADK agent that serves as the orchestrator and client. It discovers remote agents, manages communication, and coordinates tasks between specialized agents. The client has access to a `send_message` tool for communicating with remote A2A servers.

**A2A Remote Agents**: Two specialized agents hosted on Amazon Bedrock AgentCore runtime:

1. **Monitoring Agent** (`Monitoring_Agent`): Built on Strands framework, this agent monitors AWS logs/metrics/dashboards, performs log analysis, manages CloudWatch alarms, and creates Jira tickets for incident tracking.

2. **Remediation Agent** (`OpsRemediation_Agent`): Built on OpenAI framework, this agent searches for remediation strategies using Tavily search API and provides solutions for AWS-related issues and documentation.

### A2A Protocol Elements

- **Agent Card**: Each remote agent publishes a JSON metadata document describing its identity, capabilities, skills, service endpoint, and authentication requirements
- **Message**: Communication turns between the client and remote agents with roles ("user" or "agent") containing text parts
- **Task**: The fundamental unit of work with unique IDs, managed through a defined lifecycle
- **Context**: Server-generated identifiers to logically group related tasks
- **Streaming (SSE)**: Real-time updates for task status and artifact delivery
- **Authentication**: OAuth-based security where each agent has its own identity, with bearer tokens fetched through identity providers for runtime URL requests

## Configuration

The solution uses YAML configuration files to define agent metadata, capabilities, and connection details:

### Host Agent Configuration (`host_adk/host/main_agent.yaml`)
```yaml
model_information:
  model_id: gemini-2.0-flash
  agent_name: Host_Agent
  description: "This Host agent orchestrates requests for incident response logging systems"

servers:
  - http://localhost:10004  # Monitoring Agent
  - http://localhost:10003  # Remediation Agent
```

### Remote Agent Configuration
Each remote agent has a `config.yaml` file containing:

**Agent Card Information**:
- `identity_group`: OAuth client identity group
- `scope`: Required OAuth scopes for agent access
- `agent_arn`: Amazon Bedrock AgentCore runtime ARN
- `client_id`: OAuth client ID
- `discovery_url`: OAuth discovery endpoint

**Agent Metadata**:
- `name`: Agent display name
- `description`: Agent purpose and capabilities
- `version`: Agent version
- `capabilities`: Streaming and push notification support
- `supported_content_types`: Accepted content formats

**Agent Skills**: Detailed skill definitions with:
- `id`: Unique skill identifier
- `name`: Human-readable skill name
- `description`: Skill functionality description
- `tags`: Categorization tags
- `examples`: Usage examples

### Server Configuration
- `default_host`: Server host (typically localhost)
- `default_port`: Server port (10003 for Remediation, 10004 for Monitoring)

## Steps to Run

### Prerequisites
- Python 3.11+
- AWS credentials configured
- Amazon Bedrock AgentCore runtime agents deployed
- OAuth client configurations set up in AWS Cognito

### Launch All Agents

1. **Start Remote Agents**
   ```bash
   # Terminal 1: Launch Monitoring Agent
   cd monitoring_agent_a2a
   python __main__.py
   
   # Terminal 2: Launch Remediation Agent  
   cd remediation_agent_a2a
   python __main__.py
   ```

2. **Start Host Agent**
   ```bash
   # Terminal 3: Launch Google ADK Host Agent
   cd host_adk
   adk web
   # Run the ADK web interface for the host agent
   # This will start the orchestrator agent with web interface
   ```

The agents will be available on:
- Monitoring Agent: `http://localhost:10004`
- Remediation Agent: `http://localhost:10003`
- Host Agent: Google ADK web interface

### Verification
Once all agents are running, the Host Agent will:
1. Discover and connect to remote agents via their HTTP endpoints
2. Retrieve agent cards containing capabilities and skills
3. Enable message routing between the client and specialized agents
4. Provide a unified interface for incident response workflows

## Security

The A2A implementation uses OAuth 2.0 for secure authentication and authorization:

### Identity Management
- **Individual Agent Identity**: Each agent has its own unique identity and OAuth client configuration
- **Identity Groups**: Agents are organized into logical identity groups (e.g., `monitoring-agent`, `resource-provider-oauth-client-z89nr`)
- **Client Credentials**: Each agent has a dedicated `client_id` for OAuth authentication

### Authentication Flow
1. **Token Acquisition**: Clients authenticate with the identity provider to obtain bearer tokens
2. **Scope-Based Access**: Each agent defines required OAuth scopes for access control
3. **Runtime Authentication**: Bearer tokens are used to authenticate requests to Amazon Bedrock AgentCore runtime URLs
4. **Discovery Integration**: OAuth discovery URLs provide authentication endpoint information

### Security Features
- **Transport Security**: All communications use HTTPS for data in transit
- **Token-Based Authorization**: Bearer tokens provide fine-grained access control
- **Scoped Permissions**: OAuth scopes limit agent access to specific capabilities
- **Identity Isolation**: Each agent operates with its own distinct identity context

### Configuration Security
- Agent ARNs and client IDs are configured in YAML files
- OAuth discovery endpoints are fetched dynamically for security metadata
- Runtime URLs are protected by identity provider authentication 