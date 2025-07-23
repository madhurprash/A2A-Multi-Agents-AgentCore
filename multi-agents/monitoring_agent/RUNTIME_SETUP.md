# AgentCore Runtime Setup - Separated Architecture

## Overview

The AgentCore runtime configuration has been separated from the main monitoring agent for better modularity and to fix issues where the agent would attempt runtime configuration even when not needed.

## Files

### `monitoring_agent.py`
- **Purpose**: Main monitoring agent logic using MCP gateway and access tokens
- **When to use**: For local development, testing, and when you have MCP gateway credentials
- **Runtime behavior**: Skips AgentCore runtime configuration when no agent ARN is provided

### `agent_runtime.py`
- **Purpose**: Handles AgentCore Runtime configuration and deployment
- **When to use**: When you need to deploy the monitoring agent as a containerized runtime
- **Runtime behavior**: Manages the full lifecycle of AgentCore Runtime (configure, launch, status)

### `invoke_agent.py`
- **Purpose**: Invokes a deployed AgentCore runtime using agent ARN
- **When to use**: When you have a deployed agent ARN and want to interact with it

## Usage Scenarios

### Scenario 1: Local Development (No Agent ARN)
```bash
# Just run the monitoring agent directly
python monitoring_agent.py
```

**What happens**:
- Agent uses MCP URL and access token from existing credentials
- NO AgentCore runtime configuration attempted
- NO Docker/container requirements
- Agent runs in local mode with MCP gateway tools

### Scenario 2: Deploy as AgentCore Runtime
```bash
# First, configure and launch the runtime
python agent_runtime.py --configure --launch

# Then interact with the deployed agent
python invoke_agent.py
```

**What happens**:
- `agent_runtime.py` handles Docker/container setup
- Agent gets deployed as AgentCore runtime
- You get an agent ARN for remote invocation

### Scenario 3: Use Existing Agent ARN
```bash
# If you already have an agent ARN, just invoke it
python invoke_agent.py
```

## Configuration

In your `config.yaml`, the behavior is now:

- **No `agent_arn`** → Uses MCP gateway approach (no runtime configuration)
- **Has `agent_arn`** → Skips all gateway/runtime setup

## Key Changes Made

1. **Removed runtime configuration from monitoring_agent.py** when no agent ARN is provided
2. **Created agent_runtime.py** for dedicated runtime management  
3. **Simplified monitoring_agent.py** to focus on agent logic only
4. **Fixed Docker requirement issue** by separating concerns

## Benefits

- ✅ No more "Docker not found" errors when running locally
- ✅ Clear separation between agent logic and runtime deployment
- ✅ Easier debugging and development
- ✅ Flexible deployment options

## Troubleshooting

### "Docker not found" error
This should no longer occur when running `monitoring_agent.py` without an agent ARN.

### "No agent ARN provided" logs
This is normal - the agent will use MCP gateway credentials instead.

### Agent not responding
Check that your MCP gateway credentials in `mcp_credentials.json` are valid and not expired.