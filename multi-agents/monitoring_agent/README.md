# Monitoring Agent - AWS Bedrock AgentCore Runtime

This monitoring agent is built using the Strands agent SDK and AWS Bedrock AgentCore runtime for monitoring CloudWatch logs, metrics, dashboards, and other AWS services.

## Overview

The monitoring agent uses the simplified `bedrock_agentcore_starter_toolkit.Runtime` approach instead of manual CLI commands, making it easier to configure, launch, and manage.

## Prerequisites

1. **AWS Account and Credentials**: Ensure AWS credentials are configured
2. **IAM Execution Role**: Create an IAM role with permissions for:
   - Amazon Bedrock access
   - CloudWatch logs/metrics access  
   - Any other AWS services the agent needs
3. **Required Python Packages**: Install dependencies from `requirements.txt`

## Configuration

### 1. IAM Role Setup

Create an IAM execution role with the following trust policy:

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

### 2. Config File Setup

Update your `config.yaml` with:

```yaml
agent_information:
  monitoring_agent_model_info:
    gateway_config:
      runtime_exec_role: "arn:aws:iam::YOUR-ACCOUNT:role/YOUR-ROLE-NAME"
      launch_agentcore_runtime: true
```

## Launch Instructions

### Method 1: Using the Runtime Toolkit (Recommended)

The agent automatically handles configuration and launch when `launch_agentcore_runtime: true` is set:

```bash
./run_with_observability.py monitoring_agent.py
```

This approach:
1. Initializes the `Runtime()` instance
2. Calls `runtime.configure()` with your entrypoint and execution role
3. Calls `runtime.launch()` to deploy to AWS
4. Monitors status until `READY`
5. Enables invocations via `runtime.invoke()`

### Method 2: Manual Runtime Management

You can also manage the runtime programmatically:

```python
from bedrock_agentcore_starter_toolkit import Runtime
from boto3.session import Session

# Initialize
boto_session = Session()
region = boto_session.region_name
agentcore_runtime = Runtime()

# Configure
response = agentcore_runtime.configure(
    entrypoint="monitoring_agent.py",
    execution_role="arn:aws:iam::YOUR-ACCOUNT:role/YOUR-ROLE-NAME", 
    auto_create_ecr=True,
    requirements_file="requirements.txt",
    region=region
)

# Launch
launch_result = agentcore_runtime.launch()

# Check status
status_response = agentcore_runtime.status()
status = status_response.endpoint['status']

# Wait until ready
while status not in ['READY', 'CREATE_FAILED', 'DELETE_FAILED', 'UPDATE_FAILED']:
    time.sleep(10)
    status_response = agentcore_runtime.status()
    status = status_response.endpoint['status']
    print(status)

# Invoke
if status == 'READY':
    invoke_response = agentcore_runtime.invoke({"prompt": "Hi, what can you do?"})
    print(invoke_response)
```

### Method 3: Using Boto3 for Remote Invocation

Once deployed, you can invoke the agent using boto3:

```python
import boto3
import json

agentcore_client = boto3.client('bedrock-agentcore', region_name='us-east-1')

response = agentcore_client.invoke_agent_runtime(
    agentRuntimeArn="arn:aws:bedrock-agentcore:region:account:agent-runtime/agent-id",
    qualifier="DEFAULT", 
    payload=json.dumps({"prompt": "How much is 2X2?"})
)

# Process response based on content type
if "text/event-stream" in response.get("contentType", ""):
    # Handle streaming response
    content = []
    for line in response["response"].iter_lines(chunk_size=1):
        if line:
            line = line.decode("utf-8")
            if line.startswith("data: "):
                content.append(line[6:])
    result = "\\n".join(content)
else:
    # Handle direct response
    events = [event for event in response.get("response", [])]
    result = json.loads(events[0].decode("utf-8")) if events else "No response"

print(result)
```

## Requirements

Ensure your `requirements.txt` contains:

```
strands
boto3
bedrock-agentcore-starter-toolkit
python-dotenv
opentelemetry-distro[otlp]
```

## Running Modes

### 1. AgentCore Runtime Mode
When `runtime_exec_role` and `launch_agentcore_runtime` are configured, the agent runs in managed AWS runtime.

### 2. Remote Agent Mode  
When `remote_endpoint_url` is configured, invocations go to a remote agent endpoint.

### 3. Local Interactive Mode
When neither runtime nor remote endpoint is configured, runs locally with terminal chat interface.

## Testing

Once deployed, test the agent:

```bash
# Using the Runtime instance
python -c "
from bedrock_agentcore_starter_toolkit import Runtime
runtime = Runtime()
response = runtime.invoke({'prompt': 'Hello monitoring agent!'})
print(response)
"
```

## Troubleshooting

1. **Runtime Configuration Fails**: Check IAM role permissions and trust policy
2. **Launch Fails**: Ensure execution role has required permissions for ECR, Bedrock, etc.
3. **Status Shows Failed**: Check CloudWatch logs for detailed error messages
4. **Invocation Fails**: Verify runtime status is 'READY' before invoking

## Key Features

- **Simplified Setup**: No manual CLI commands required
- **Automatic Configuration**: Runtime handles Docker, ECR, and deployment
- **Status Monitoring**: Built-in status checking and waiting
- **Multiple Invocation Methods**: Runtime, boto3, or local modes
- **Error Handling**: Comprehensive error reporting and cleanup