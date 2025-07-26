---
layout: page
title: A2A Multi-Agents AgentCore Documentation
---

# Multi-Agents AgentCore System

Welcome to the comprehensive documentation for the A2A Multi-Agents AgentCore system - a sophisticated multi-agent framework built on AWS Bedrock AgentCore for automated operations, monitoring, and incident management.

## Overview

The Multi-Agents AgentCore system consists of two main components:

1. **[Monitoring Agent](monitoring-agent.md)** - AWS Bedrock AgentCore runtime for monitoring CloudWatch logs, metrics, dashboards, and other AWS services
2. **[Ops Orchestrator Agent](ops-orchestrator-agent.md)** - Multi-agent system for automated incident triaging, ChatOps collaboration, and report generation

## Key Features

- **Simplified Setup**: No manual CLI commands required
- **Automatic Configuration**: Runtime handles Docker, ECR, and deployment
- **Status Monitoring**: Built-in status checking and waiting
- **Multiple Invocation Methods**: Runtime, boto3, or local modes
- **Comprehensive Error Handling**: Error reporting and cleanup
- **Multi-Agent Collaboration**: Specialized agents working together
- **ChatOps Integration**: Teams, Slack, and Gmail support
- **Automated Ticket Creation**: JIRA and PagerDuty integration

## Quick Start

### Prerequisites

1. **AWS Account and Credentials**: Ensure AWS credentials are configured
2. **IAM Execution Role**: Create an IAM role with permissions for:
   - Amazon Bedrock access
   - CloudWatch logs/metrics access  
   - Any other AWS services the agent needs
3. **Required Python Packages**: Install dependencies from requirements.txt

### Environment Setup

Create a `.env` file or export the following environment variables:

```bash
# AWS Configuration
export AWS_REGION="us-east-1"
export AWS_ACCOUNT_ID="your-account-id"

# JIRA Integration
export JIRA_USERNAME="your-jira-username"
export JIRA_API_TOKEN="[REDACTED]"
export JIRA_DOMAIN="yourcompany.atlassian.net"

# GitHub Integration
export GITHUB_TOKEN="[REDACTED]"
```

## Architecture

The system uses AWS Bedrock AgentCore as the foundation, providing:

- **Memory Management**: Persistent memory for each agent type
- **Gateway Integration**: MCP (Model Context Protocol) gateway with OAuth2 authentication
- **Service Integrations**: JIRA, GitHub, Slack, and other external services
- **Observability**: Built-in CloudWatch logging and OpenTelemetry support

## Getting Started

Choose your agent based on your needs:

- **For AWS Monitoring**: Start with the [Monitoring Agent](monitoring-agent.md)
- **For Operations Management**: Begin with the [Ops Orchestrator Agent](ops-orchestrator-agent.md)

## Security Best Practices

1. **Credential Management**
   - Use environment variables, not hardcoded credentials
   - Rotate API tokens regularly
   - Use IAM roles with minimal required permissions

2. **Network Security**
   - Use HTTPS for all external API calls
   - Implement VPC endpoints for AWS services
   - Consider private subnets for production deployments

3. **Access Control**
   - Implement least-privilege IAM policies
   - Use OAuth2 scopes to limit API access
   - Regularly audit service integrations

## Support

For issues and questions:
1. Check the troubleshooting sections in each agent's documentation
2. Review AWS CloudWatch logs
3. Verify configuration against examples
4. Check service status of integrated APIs

---

*This documentation is automatically generated from the project README files with sensitive information redacted for security purposes.*