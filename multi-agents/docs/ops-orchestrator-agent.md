---
layout: page
title: Ops Orchestrator Agent
---

# Ops Orchestrator Multi-Agent System

A comprehensive multi-agent system built on AWS Bedrock AgentCore that provides automated incident triaging, ChatOps collaboration, and report generation for operational workflows.

## Quick Start Guide

### Prerequisites
First, ensure you have completed all prerequisite setup as outlined in the [Prerequisites](#prerequisites) section below.

### Local Deployment Steps

1. **Configure and Launch the Agent Runtime**
   ```bash
   python ops_orchestrator_runtime.py --configure --launch
   ```
   This will:
   - Configure the AgentCore runtime environment
   - Set up authentication and gateway connections
   - Launch the ops orchestrator agent with runtime capabilities

2. **Navigate to Parent Directory and Invoke Agent**
   ```bash
   cd ..
   python invoke_agent.py
   ```

3. **Agent Invocation Options**
   You can invoke the agent using either:
   
   **Option A: HTTP/REST API**
   - Use standard HTTP requests to interact with the agent
   - The agent will be accessible via the configured gateway endpoint
   
   **Option B: AWS SDK (boto3)**
   - Use the AWS Bedrock AgentCore SDK for direct agent invocation
   - Requires your agent ARN for programmatic access
   - Example:
     ```python
     import boto3
     client = boto3.client('bedrock-agentcore')
     response = client.invoke_agent(
         agentId='your-agent-arn',
         message='Your incident description here'
     )
     ```

### Summary of Deployment Process
1. ✅ Complete prerequisites setup
2. ✅ Run `python ops_orchestrator_runtime.py --configure --launch`
3. ✅ Navigate up one directory: `cd ..`
4. ✅ Invoke agent: `python invoke_agent.py`
5. ✅ Use HTTP or boto3 for agent communication

## Architecture Overview

The Ops Orchestrator Agent is a sophisticated multi-agent system that consists of three specialized agents working collaboratively:

1. **Lead Agent (Issue Triaging)** - Automated incident analysis and classification
2. **ChatOps Agent** - Real-time collaboration through Teams, Slack, and Gmail
3. **Ticket Creator Agent** - Automated ticket creation in JIRA and other systems

Each agent leverages AWS Bedrock AgentCore memory primitives and connects to external services through an MCP (Model Context Protocol) gateway with OAuth2 authentication.

## Prerequisites

### AWS Requirements
- AWS CLI configured with appropriate permissions
- Access to AWS Bedrock AgentCore services
- IAM permissions for:
  - `bedrock:*`
  - `bedrock-agentcore:*`
  - `s3:*`
  - `lambda:*`
  - `iam:*`
  - `cognito-idp:*`
  - `secretsmanager:*`
  - `logs:*`
  - `cloudwatch:*`

### Python Dependencies
```bash
pip install boto3 pyyaml python-keycloak requests openai anthropic
```

### External Service Authentication
You'll need API credentials for the services you want to integrate:
- **JIRA**: Username and API token
- **GitHub**: Personal Access Token or OAuth app credentials
- **Slack**: Bot token (optional)

## Environment Setup

Create a `.env` file or export the following environment variables:

```bash
# AWS Configuration
export AWS_REGION="us-east-1"
export AWS_ACCOUNT_ID="your-account-id"

# JIRA Integration (Required)
export JIRA_USERNAME="your-jira-username"
export JIRA_API_TOKEN="[REDACTED]"
export JIRA_DOMAIN="yourcompany.atlassian.net"

# GitHub Integration (Required)
export GITHUB_TOKEN="[REDACTED]"

# Optional: GitHub OAuth (for advanced features)
export GITHUB_CLIENT_ID="your-oauth-client-id"
export GITHUB_CLIENT_SECRET="[REDACTED]"

# Optional: JIRA OAuth (for advanced features)
export JIRA_CLIENT_ID="your-jira-oauth-client-id"
export JIRA_CLIENT_SECRET="[REDACTED]"

# Optional: Keycloak Authentication (Alternative to Cognito)
export KEYCLOAK_URL="http://localhost:8080/"
export KEYCLOAK_ADMIN_USER="admin"
export KEYCLOAK_ADMIN_PASS="[REDACTED]"
```

## Configuration Setup

The system uses a `config.yaml` file for configuration. Here's the essential structure:

```yaml
general:
  name: "ops-orchestrator-agent"
  description: "Multi-agent system for operations orchestration"

agent_information:
  ops_orchestrator_agent_model_info: 
    model_id: gpt-4o-2024-08-06
    inference_parameters:
      temperature: 0.1
      max_tokens: 2048
    
    # Memory configuration for each agent
    memories:
      lead_agent:
        use_existing: false  # Set to true if you have existing memory
        memory_id: null      # Fill if reusing existing memory
      chat_ops_agent:
        use_existing: false
        memory_id: null
      ticket_agent:
        use_existing: false
        memory_id: null
    
    # Gateway configuration
    gateway_config:
      name: "ops-gw"
      
      # Authentication method (choose one)
      inbound_auth:
        type: "cognito"  # or "keycloak"
        cognito:
          create_user_pool: true
          user_pool_name: "agentcore-gateway-ops"
          resource_server_id: "ops_orchestrator_agent"
          resource_server_name: "agentcore-gateway-ops"
          client_name: "agentcore-client-ops"
          scopes:
            - ScopeName: "gateway:read"
              ScopeDescription: "Read access"
            - ScopeName: "gateway:write"
              ScopeDescription: "Write access"
      
      credentials:
        use_cognito: true
        use_existing: false
        create_new_access_token: false
        gateway_id: null
        mcp_url: null
        access_token: null
      
      # S3 bucket for storing API specifications
      bucket_name: "ops-orchestrator-gateway-bucket"
      
      # Target integrations
      targets:
        - name: "jira-integration"
          spec_file: /absolute/path/to/tools/jira_api_spec.yaml
          type: "openapi"
          api_type: "jira"
          endpoint: "https://your-jira-instance.atlassian.net"
          authentication:
            type: "basic"
            credentials:
              username: "${JIRA_USERNAME}"
              password: "${JIRA_API_TOKEN}"
        
        - name: "github-integration" 
          spec_file: /absolute/path/to/tools/github_api_spec.yaml
          type: "openapi"
          api_type: "github"
          endpoint: "https://api.github.com"
          authentication:
            type: "bearer"
            credentials:
              token: "${GITHUB_TOKEN}"
```

## Authentication Options

### Option 1: AWS Cognito (Default)

The system automatically creates:
- Cognito User Pool for authentication
- Resource server with custom scopes
- Machine-to-machine client for API access
- Access tokens for gateway authentication

### Option 2: Keycloak Authentication

For organizations using Keycloak for identity management:

1. **Start Keycloak** (if running locally):
```bash
docker run -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=[REDACTED] \
  quay.io/keycloak/keycloak:latest start-dev
```

2. **Update config.yaml**:
```yaml
inbound_auth:
  type: "keycloak"
  keycloak:
    url: "${KEYCLOAK_URL}"
    admin_user: "${KEYCLOAK_ADMIN_USER}"
    admin_pass: "${KEYCLOAK_ADMIN_PASS}"
    realm_name: "ops-orchestrator-realm"
    client_id: "ops-orchestrator-gateway-client"
    create_realm: true
    scopes:
      - "gateway:read"
      - "gateway:write"
      - "ops:manage"
      - "incidents:create"

credentials:
  use_keycloak: true
```

## Service Integrations

### JIRA Integration

The system integrates with JIRA for automated ticket creation and management.

**Required Setup:**
1. Create a JIRA API token in your Atlassian account
2. Set environment variables:
```bash
export JIRA_USERNAME="your-email@company.com"
export JIRA_API_TOKEN="[REDACTED]"
export JIRA_DOMAIN="yourcompany.atlassian.net"
```

### GitHub Integration

Integrates with GitHub for repository management and issue tracking.

**Required Setup:**
1. Create a GitHub Personal Access Token with appropriate scopes
2. Set environment variable:
```bash
export GITHUB_TOKEN="[REDACTED]"
```

## Agent Memory System

Each agent uses AWS Bedrock AgentCore memory with different strategies:

### Lead Agent Memory
- **User Preferences**: Stores user-specific incident handling preferences
- **Semantic Memory**: Contextual understanding of technical issues
- **Summary Memory**: Session-based conversation summaries
- **Custom Issue Triaging**: Specialized memory for incident classification

### ChatOps Agent Memory
- **User Preferences**: Communication preferences and channels
- **Semantic Memory**: Chat context and collaboration patterns
- **Summary Memory**: Chat session summaries
- **ChatOps Memory**: Communication templates and escalation procedures

### Ticket Creator Agent Memory  
- **User Preferences**: Ticket creation preferences and templates
- **Semantic Memory**: Ticket patterns and classifications
- **Summary Memory**: Ticket creation session history
- **Ticket Creator Memory**: Template management and field mapping

### Memory Configuration

```yaml
memories:
  lead_agent:
    use_existing: false      # Set to true to reuse existing memory
    memory_id: null          # Memory ID if reusing
  chat_ops_agent:
    use_existing: false
    memory_id: null
  ticket_agent:
    use_existing: false
    memory_id: null
```

## Troubleshooting

### Common Issues

#### Memory Creation Fails
```
❌ Error creating memory for agent: AccessDenied
```
**Solution**: Check AWS permissions for `bedrock-agentcore:*`

#### Gateway Creation Fails
```
❌ Error creating gateway: ValidationException
```
**Solutions**:
- Verify AWS region supports Bedrock AgentCore
- Check IAM role permissions
- Validate authentication configuration

#### JIRA/GitHub Integration Fails
```
❌ Target creation failed: Authentication failed
```
**Solutions**:
- Verify API credentials are correct
- Check environment variables are exported
- Validate API endpoint URLs
- Ensure API tokens have required permissions

### Debug Mode

Enable detailed logging:
```bash
export PYTHONPATH=.
python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
exec(open('ops_orchestrator_multi_agent.py').read())
"
```

## Security Best Practices

### Credential Management
- Use environment variables, not hardcoded credentials
- Rotate API tokens regularly
- Use IAM roles with minimal required permissions

### Network Security
- Use HTTPS for all external API calls
- Implement VPC endpoints for AWS services
- Consider private subnets for production deployments

### Access Control
- Implement least-privilege IAM policies
- Use OAuth2 scopes to limit API access
- Regularly audit service integrations

## Success Indicators

When properly configured, you should see:
```
✅ Observability initialized
✅ Created memory for lead_agent: OpsAgent_mem_xxx
✅ Created memory for chat_ops_agent: OpsAgent_chat_xxx  
✅ Created memory for ticket_agent: TicketCreation_chat_xxx
✅ Gateway setup completed with URL: https://xxxxx
✅ Created 2 targets successfully
🚀 Ops orchestrator multi-agent system ready!
```

Your multi-agent system is now ready to handle operational incidents, create tickets, and collaborate across your organization! 🚀