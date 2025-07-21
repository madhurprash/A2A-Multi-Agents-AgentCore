# Lambda Target Deployment for Monitoring Agent

This guide shows how to deploy Lambda functions as AgentCore Gateway targets for your monitoring agent, replacing Smithy definitions with dynamic Lambda functions.

## Overview

Instead of using Smithy definitions, this approach deploys your monitoring tools as AWS Lambda functions that can be invoked through the AgentCore Gateway using the Model Context Protocol (MCP).

### Benefits of Lambda Targets

1. **Dynamic Logic**: Full programming capability vs static Smithy definitions
2. **Real-time Processing**: Process and filter data before returning results
3. **Error Handling**: Sophisticated error handling and retry logic
4. **Cross-Account Support**: Built-in cross-account monitoring capabilities
5. **Integration**: Easy integration with other AWS services
6. **Scalability**: Automatic scaling based on demand

## Configuration

The deployment method is controlled by the `tools/monitoring_tools_config.json` file:

```json
{
  "target_type": "lambda",
  "lambda_config": {
    "function_name": "MonitoringAgentLambda",
    "runtime": "python3.12",
    "handler": "lambda_handler.lambda_handler",
    "code_path": "tools/lambda_handler.py",
    "timeout": 300,
    "memory_size": 512,
    "environment_variables": {
      "AWS_REGION": "us-west-2",
      "DEFAULT_ROLE_NAME": "CloudWatchCrossAccountRole"
    },
    "create_lambda": true
  },
  "tools": [...]
}
```

### Key Configuration Options

- `target_type`: Set to `"lambda"` to use Lambda deployment
- `create_lambda`: Set to `true` to enable Lambda creation
- `function_name`: Name of the Lambda function to create
- `code_path`: Path to the Lambda handler code (relative to monitoring_agent directory)
- `environment_variables`: Environment variables for the Lambda function

## Deployment Options

### Option 1: Automatic Deployment (Integrated)

When running the main monitoring agent (`monitoring_agent.py`), if the configuration specifies `"create_lambda": true`, the system will:

1. Automatically deploy the Lambda function
2. Create the gateway target pointing to the Lambda
3. Use the Lambda function for all monitoring operations

### Option 2: Manual Deployment

Use the standalone deployment script:

```bash
# Deploy the Lambda function
python deploy.py --role-arn arn:aws:iam::ACCOUNT_ID:role/YourLambdaRole --region us-west-2

# Deploy and test
python deploy.py --role-arn arn:aws:iam::ACCOUNT_ID:role/YourLambdaRole --test
```

## File Structure

```
monitoring_agent/
├── tools/
│   ├── lambda_handler.py              # Lambda function code
│   ├── monitoring_tools_config.json   # Tools configuration
│   └── monitoring_tools_openapi.json  # Original OpenAPI schema (fallback)
├── lambda_utils.py                    # Lambda deployment utilities
├── deploy.py                          # Standalone deployment script
├── monitoring_agent.py                # Main agent with integrated deployment
└── README_LAMBDA.md                   # This file
```

## Lambda Function Features

The Lambda function (`tools/lambda_handler.py`) supports:

### Available Operations

1. `setup_cross_account_access` - Test cross-account role assumption
2. `list_cloudwatch_dashboards` - List CloudWatch dashboards
3. `get_cloudwatch_alarms_for_service` - Get alarms for a service
4. `fetch_cloudwatch_logs_for_service` - Fetch logs for a service
5. `get_dashboard_summary` - Get dashboard configuration
6. `list_log_groups` - List CloudWatch log groups
7. `analyze_log_group` - Analyze log group events

### Invocation Methods

The Lambda function handles multiple invocation methods:

1. **API Gateway HTTP Events** - For REST API integration
2. **Direct Lambda Invokes** - For MCP/Gateway integration
3. **Custom Events** - Based on operation ID

### Cross-Account Support

All operations support cross-account access by providing:
- `account_id`: Target AWS account ID
- `role_name`: IAM role to assume in target account

## IAM Permissions

The Lambda execution role needs the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:*",
                "logs:*",
                "sts:AssumeRole"
            ],
            "Resource": "*"
        }
    ]
}
```

For cross-account access, the target account roles need:
- CloudWatch and CloudWatch Logs permissions
- Trust relationship allowing your account to assume the role

## Testing

### Test Lambda Function Directly

```python
import boto3
import json

lambda_client = boto3.client('lambda')

# Test dashboard listing
payload = {
    'method': 'list_cloudwatch_dashboards',
    'arguments': {}
}

response = lambda_client.invoke(
    FunctionName='MonitoringAgentLambda',
    Payload=json.dumps(payload)
)

result = json.loads(response['Payload'].read())
print(result)
```

### Test Cross-Account Access

```python
payload = {
    'method': 'setup_cross_account_access',
    'arguments': {
        'account_id': 123456789012,
        'role_name': 'CloudWatchCrossAccountRole'
    }
}
```

## Troubleshooting

### Common Issues

1. **Lambda Deployment Fails**
   - Check IAM role permissions
   - Verify role ARN format
   - Ensure code file exists

2. **Gateway Target Creation Fails**
   - Verify Lambda function was deployed successfully
   - Check gateway IAM role has Lambda invoke permissions

3. **Cross-Account Access Fails**
   - Verify target role exists and has correct trust policy
   - Check CloudWatch permissions on target role

### Logs

Check Lambda logs in CloudWatch Logs:
- Log group: `/aws/lambda/MonitoringAgentLambda`
- Look for error messages and stack traces

## Migration from OpenAPI

To migrate from OpenAPI to Lambda:

1. Update `monitoring_tools_config.json`:
   - Set `"target_type": "lambda"`
   - Set `"create_lambda": true`

2. Run the monitoring agent or deployment script

3. The system will automatically deploy the Lambda and update the gateway target

The OpenAPI schema file is kept as a fallback if Lambda deployment fails or if you want to switch back.