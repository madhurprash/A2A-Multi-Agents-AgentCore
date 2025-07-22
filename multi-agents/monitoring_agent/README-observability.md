# Monitoring Agent Observability

This observability module provides comprehensive monitoring and tracing for the monitoring agent based on AWS Bedrock AgentCore patterns.

## Features

- **OpenTelemetry Integration**: Automatic tracing with AWS X-Ray propagation
- **CloudWatch Integration**: Metrics and logs export to CloudWatch
- **Agent Performance Monitoring**: Track agent invocations, response times, and tool calls
- **Cross-Account Operation Tracking**: Monitor cross-account AWS operations
- **Memory Operation Tracing**: Track AgentCore memory operations
- **Gateway Operation Monitoring**: Monitor MCP gateway interactions

## How It Works

The observability system uses OpenTelemetry with AWS distro for automatic instrumentation, similar to the AWS Bedrock AgentCore sample. It provides:

1. **Automatic Tracing**: All agent interactions are traced with spans
2. **Metrics Collection**: Performance metrics are collected and sent to CloudWatch
3. **Custom Instrumentation**: Specific monitoring for agent operations
4. **Error Tracking**: Automatic exception capture and error metrics

## Setup

### 1. Install Dependencies
```bash
pip install -r requirements-observability.txt
```

### 2. Configure Environment Variables
Copy `.env.observability` to your `.env` file or set environment variables:

```bash
# Enable observability
export ENABLE_TRACING=true
export ENABLE_METRICS=true

# AWS Configuration
export AWS_REGION=us-east-1
export CLOUDWATCH_LOG_GROUP=/aws/monitoring-agent/traces
```

### 3. AWS IAM Permissions
Ensure your execution role has permissions for:
- `logs:CreateLogGroup`
- `logs:CreateLogStream` 
- `logs:PutLogEvents`
- `cloudwatch:PutMetricData`
- `xray:PutTraceSegments`
- `xray:PutTelemetryRecords`

## Usage

### Automatic Instrumentation

The observability module automatically instruments:
- Agent invocations and responses
- Tool calls to AWS services
- Memory operations (AgentCore)
- Gateway interactions (MCP)
- Cross-account operations

### Manual Instrumentation

You can add custom tracing:

```python
from observability import get_observability

# Custom span
with get_observability().trace_span("custom_operation", 
                                   attributes={"key": "value"}):
    # Your code here
    pass

# Custom metric
get_observability().record_custom_metric(
    "custom_metric",
    1.0,
    dimensions={"operation": "test"}
)
```

### Decorators

Use decorators for automatic tracing:

```python
@get_observability().trace_tool_call("my_tool", account_id="123456789012")
def my_tool_function():
    # Tool logic here
    pass

@get_observability().trace_memory_operation("create")
def create_memory():
    # Memory operation logic
    pass
```

## CloudWatch Integration

### Metrics

The following metrics are automatically collected:

- `agent_invocations_total`: Count of agent invocations
- `tool_calls_total`: Count of tool calls 
- `cross_account_operations_total`: Count of cross-account operations
- `agent_response_time_seconds`: Agent response time histogram
- `memory_operations_total`: Count of memory operations

### Logs

Traces are exported to CloudWatch Logs in the configured log group with structured JSON format.

### Dashboards

Access the GenAI Observability dashboard in CloudWatch to visualize:
- Agent decision-making process
- Tool interaction flows
- Performance metrics
- Error rates and patterns

## Architecture Integration

The observability system integrates with existing components:

1. **Memory Hooks**: Works alongside `MonitoringMemoryHooks`
2. **Strands Framework**: Uses `HookProvider` for agent lifecycle events
3. **MCP Gateway**: Traces all gateway operations
4. **AWS Services**: Automatic instrumentation of AWS SDK calls

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_TRACING` | `true` | Enable OpenTelemetry tracing |
| `ENABLE_METRICS` | `true` | Enable CloudWatch metrics |
| `OTEL_SERVICE_NAME` | `monitoring-agent` | Service name for traces |
| `CLOUDWATCH_LOG_GROUP` | `/aws/monitoring-agent/traces` | Log group for traces |
| `METRICS_EXPORT_INTERVAL` | `30000` | Metrics export interval (ms) |
| `OBSERVABILITY_DEBUG` | `false` | Enable debug logging |

## Troubleshooting

### Common Issues

1. **Missing AWS Permissions**: Ensure IAM role has CloudWatch and X-Ray permissions
2. **Network Issues**: Check connectivity to CloudWatch endpoints
3. **Configuration Errors**: Verify environment variables are set correctly

### Debug Mode

Enable debug mode for detailed logging:
```bash
export OBSERVABILITY_DEBUG=true
export OTEL_LOG_LEVEL=debug
```

### Verification

Check observability status:
```python
from observability import get_observability
print(get_observability().get_observability_status())
```

## Performance Impact

The observability system is designed for minimal performance impact:
- Async trace export
- Configurable sampling rates
- Efficient metric collection
- Automatic cleanup on shutdown

## Similar to AWS Sample

This implementation follows the same patterns as the AWS Bedrock AgentCore observability sample:
- Uses AWS OpenTelemetry Python Distro
- Automatic instrumentation without code changes
- CloudWatch GenAI Observability dashboard integration
- Minimal configuration overhead