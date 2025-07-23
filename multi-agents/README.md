# Multi-Agent System for AWS Monitoring

This multi-agent system demonstrates AWS agentic primitives for monitoring and triage operations. The system uses AWS Bedrock AgentCore runtime with various AWS services including Lambda tool gateways, Cognito authentication, and CloudWatch monitoring capabilities.

## Overview

The multi-agent system consists of a monitoring agent that leverages several AWS primitives:

- **AWS Bedrock AgentCore Runtime**: Serverless agent execution environment
- **Agent Memory**: Long-term memory for context persistence using Amazon Bedrock Memory
- **Tool Gateway**: Lambda-based tool execution with MCP protocol support
- **Cognito Authentication**: Secure access control for agent invocations
- **CloudWatch Integration**: Comprehensive AWS resource monitoring

## System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User Client   │───▶│  Monitoring Agent │───▶│  Tool Gateway   │
│  (invoke_agent) │    │ (Bedrock Runtime) │    │   (Lambda)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                       │
         │                        ▼                       ▼
         │              ┌──────────────────┐    ┌─────────────────┐
         │              │  Agent Memory    │    │   CloudWatch    │
         │              │   (Bedrock)      │    │   Services      │
         │              └──────────────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐
│    Cognito      │
│ Authentication  │
└─────────────────┘
```

## Use Case
Automated monitoring and incident response system that continuously monitors application and infrastructure metrics, automatically triages issues, performs root cause analysis, and executes remediation actions with minimal human intervention.

## Pain Points
- **Manual Monitoring**: Operations teams spend significant time manually monitoring dashboards and alerts
- **Slow Response Times**: Critical issues may go unnoticed or take too long to escalate
- **Context Switching**: Engineers must switch between multiple tools and dashboards to understand issues
- **Inconsistent Triage**: Different team members may prioritize incidents differently
- **Delayed Root Cause Analysis**: Time-consuming manual investigation of complex issues
- **Reactive Remediation**: Fixes are applied after significant impact has occurred

## Monitoring Agent Capabilities

The monitoring agent provides comprehensive AWS monitoring capabilities:

### Core Functions
- **CloudWatch Dashboard Analysis**: List and analyze CloudWatch dashboards
- **Log Analysis**: Fetch and analyze logs from various AWS services
- **Alarm Management**: Monitor and analyze CloudWatch alarms
- **Cross-Account Access**: Support for monitoring across multiple AWS accounts
- **Service-Specific Monitoring**: Specialized monitoring for EC2, Lambda, RDS, EKS, API Gateway, and more

### Supported AWS Services
- EC2/Compute Instances
- Lambda Functions
- RDS Databases
- EKS Kubernetes clusters
- API Gateway
- CloudTrail
- S3 Storage
- VPC Networking
- WAF Web Security
- Amazon Bedrock
- IAM Security Logs
- Dynamic service mapping for other AWS services

### Available Tools
1. `list_cloudwatch_dashboards` - List all CloudWatch dashboards
2. `fetch_cloudwatch_logs_for_service` - Retrieve recent logs for specific services
3. `get_cloudwatch_alarms_for_service` - Get CloudWatch alarms for services
4. `setup_cross_account_access` - Configure cross-account monitoring
5. `list_log_groups` - List all CloudWatch log groups
6. `analyze_log_group` - Analyze specific log groups for patterns
7. `get_dashboard_summary` - Get detailed dashboard configuration

## Deployment Instructions

### Prerequisites
- AWS Account with appropriate permissions
- IAM execution role for Bedrock AgentCore
- Python 3.8+ environment

### Option 1: Deploy Lambda Tool Gateway First (Recommended)

Before deploying the monitoring agent, deploy the Lambda tool gateway:

1. **Deploy Lambda Function**:
   ```bash
   cd multi-agents/monitoring_agent
   ./deploy_lambda.sh
   ```

2. **Configure Lambda ARN** in `config.yaml`:
   ```yaml
   targets:
     lambda:
       - function_name: "monitoring-agent-lambda"
         role_arn: arn:aws:lambda:us-west-2:ACCOUNT_ID:function:monitoring-agent-lambda
         config_struct: tools/lambda_monitoring_tools.json
   ```

### Option 2: Deploy Using Bedrock AgentCore Runtime

1. **Configure IAM Role**:
   Create an IAM execution role with trust policy:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "Service": [
             "bedrock.amazonaws.com",
             "bedrock-agentcore.amazonaws.com"
           ]
         },
         "Action": "sts:AssumeRole"
       }
     ]
   }
   ```

2. **Update Configuration**:
   Edit `config.yaml` with your specific values:
   ```yaml
   gateway_config:
     runtime_exec_role: "arn:aws:iam::YOUR-ACCOUNT:role/YOUR-ROLE-NAME"
     launch_agentcore_runtime: true
   ```

3. **Deploy Agent**:
   ```bash
   cd multi-agents/monitoring_agent
   ./run_with_observability.py monitoring_agent.py
   ```

   This process will:
   - Initialize the Runtime instance
   - Configure the agent with your entrypoint and execution role
   - Deploy to AWS Bedrock AgentCore
   - Monitor deployment status until READY
   - Return the agent ARN for invocation

### Configuration Files

The system uses several configuration files:

1. **config.yaml**: Main configuration containing:
   - Agent model information (Claude 3.5 Sonnet)
   - Memory configuration with actor/session IDs
   - Gateway configuration with Lambda targets
   - Cognito authentication settings
   - IAM role specifications

2. **lambda_monitoring_tools.json**: Tool definitions for Lambda gateway
3. **mcp_credentials.json**: MCP protocol credentials for tool access
4. **monitoring_agent_prompt_template.txt**: System prompt for agent behavior

## Using the Agent

### Method 1: Python Invocation Script

After deployment, use the provided Python script to invoke the agent:

```bash
cd multi-agents
python invoke_agent.py
```

The script provides two authentication methods:

#### Boto3 with IAM Authentication
- Uses AWS credentials from environment/profiles
- Direct boto3 client invocation
- Suitable for programmatic access

#### HTTP Client with Cognito Authentication
- Uses Cognito access tokens
- Bearer token authentication
- Suitable for web applications

#### Multi-turn Conversations
Both methods support interactive multi-turn conversations:
- Type questions about AWS resources
- Get comprehensive monitoring insights
- Type 'quit' or 'exit' to end sessions

### Method 2: Direct Runtime Invocation

```python
from bedrock_agentcore_starter_toolkit import Runtime

runtime = Runtime()
response = runtime.invoke({
    'prompt': 'Show me all CloudWatch dashboards and analyze any recent Lambda errors'
})
print(response)
```

## Authentication & Security

### Cognito Configuration
The system uses Amazon Cognito for secure authentication:
- User pool with custom scopes (gateway:read, gateway:write)
- Resource server configuration
- Automatic token refresh on expiry

### Cross-Account Access
Configure cross-account monitoring by:
1. Setting up IAM roles in target accounts
2. Configuring trust relationships
3. Using the `setup_cross_account_access` tool

## Primitives Used

### 1. AWS Bedrock AgentCore Runtime
- **Purpose**: Serverless agent execution environment
- **Configuration**: Runtime execution role, automatic ECR management
- **Benefits**: Scalable, managed infrastructure

### 2. Agent Memory (Amazon Bedrock Memory)
- **Purpose**: Long-term context persistence across conversations
- **Configuration**: Actor ID, session management
- **Custom Prompts**: Extraction and consolidation prompts for memory operations

### 3. Tool Gateway with Lambda
- **Purpose**: Secure tool execution via AWS Lambda
- **Protocol**: MCP (Model Context Protocol)
- **Tools**: CloudWatch monitoring, log analysis, alarm management

### 4. Cognito Authentication
- **Purpose**: Secure API access control
- **Features**: JWT tokens, scoped access, automatic refresh
- **Integration**: Gateway inbound authentication

### 5. CloudWatch Integration
- **Purpose**: Comprehensive AWS resource monitoring
- **Services**: Logs, Metrics, Dashboards, Alarms
- **Cross-Account**: Multi-account monitoring support

## Required Configuration Values

Update these values in `config.yaml`:

```yaml
# Replace with your account ID
runtime_exec_role: arn:aws:iam::YOUR-ACCOUNT:role/YOUR-ROLE-NAME

# Replace with your Lambda function ARN
role_arn: arn:aws:lambda:us-west-2:YOUR-ACCOUNT:function:monitoring-agent-lambda

# Replace with your memory ID
memory_credentials:
  id: YOUR-MEMORY-ID

# Replace with your actor ID
memory_allocation:
  actor_id: YOUR-ACTOR-ID

# Replace with your bucket name
bucket_name: YOUR-BUCKET-NAME
```

## Development and Testing

### Local Development
```bash
cd multi-agents/monitoring_agent
python interactive_agent.py
```

### Testing with Agent ARN
Once deployed, you'll receive an agent ARN like:
```
arn:aws:bedrock-agentcore:us-west-2:218208277580:runtime/monitoring_agent-bF3wIF6soo
```

Use this ARN with `invoke_agent.py` for testing.

### Observability
The system includes OpenTelemetry integration for monitoring:
```bash
./run_with_observability.py monitoring_agent.py
```

## File Structure

```
multi-agents/
├── README.md                          # This file
├── invoke_agent.py                     # Agent invocation script
├── test_invoke.py                      # Testing utilities
└── monitoring_agent/
    ├── README.md                       # Deployment instructions
    ├── config.yaml                     # Main configuration
    ├── monitoring_agent.py             # Core agent implementation
    ├── constants.py                    # Configuration constants
    ├── utils.py                        # Utility functions
    ├── Dockerfile                      # Container configuration
    ├── deploy_lambda.sh                # Lambda deployment script
    ├── lambda_function.py              # Lambda handler
    ├── tools/
    │   └── lambda_monitoring_tools.json # Tool definitions
    ├── prompt_template/
    │   └── monitoring_agent_prompt_template.txt # System prompt
    └── custom_memory_prompts/
        └── monitoring_agent_memory/
            ├── custom_extraction_prompt.txt
            └── custom_consolidation_prompt.txt
```

## Troubleshooting

### Common Issues
1. **Deployment Fails**: Check IAM permissions and trust policies
2. **Authentication Errors**: Verify Cognito configuration and tokens
3. **Tool Execution Fails**: Ensure Lambda function is deployed and accessible
4. **Memory Issues**: Verify memory service is created and accessible

### Logs and Debugging
- Check CloudWatch logs for detailed error messages
- Use verbose mode in `invoke_agent.py` for debugging
- Monitor agent status during deployment

## Security Considerations

- Never commit credentials to the repository
- Use environment variables for sensitive configuration
- Implement least-privilege IAM policies
- Regularly rotate Cognito tokens and credentials
- Monitor cross-account access permissions

## Future Enhancements

- Support for additional AWS services
- Enhanced multi-agent orchestration
- Real-time alerting capabilities
- Dashboard customization features
- Advanced analytics and reporting

## Benefits
- **Reduced MTTR**: Automated detection and response significantly reduces mean time to resolution
- **Consistent Triage**: AI-powered classification ensures consistent prioritization
- **Proactive Monitoring**: Continuous monitoring prevents issues from escalating
- **Audit Trail**: Complete event history for compliance and post-incident analysis
- **Scalable Architecture**: Event-driven design scales with infrastructure growth