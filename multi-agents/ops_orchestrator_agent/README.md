# Ops Orchestrator Agent

AI-powered operations agent that searches for best practices, creates JIRA tickets, and provides infrastructure remediation guidance.

## Prerequisites

- Python 3.11+
- AWS CLI configured with appropriate permissions
- AWS Secrets Manager access
- Cognito IdP permissions

## Quick Setup

### 1. Environment Setup
```bash
# Copy and fill environment variables
cp .env.example .env

# Add your API keys to .env:
# - OPENAI_API_KEY
# - TAVILY_API_KEY  
# - JIRA_API_KEY (optional)
```

### 2. Store Keys in Secrets Manager
```bash
# Dry run to see what will be created
python setup_secrets.py --dry-run

# Store API keys in AWS Secrets Manager
python setup_secrets.py --setup --region us-west-2

# Verify secrets are accessible
python setup_secrets.py --verify
```

### 3. Configure Cognito Authentication
```bash
# Setup Cognito User Pool
python idp_setup/setup_cognito.py
```

After Cognito setup, update `config.yaml`:
```yaml
idp_setup:
  user_pool_id: # From cognito_config.json
  discovery_url: # From cognito_config.json  
  client_secret: # From cognito_config.json
  client_id: # From cognito_config.json
```

### 4. Launch Agent

#### AgentCore Runtime (Default)
```bash
python ops_remediation_agent.py
```

#### Interactive Mode
```bash  
python ops_remediation_agent.py --interactive
```

#### Single Command
```bash
python ops_remediation_agent.py --command "search best practices for EC2 utilization"
```

## Usage Example

Test via HTTP with bearer token:
```bash
curl -X POST http://localhost:8080/invoke \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "can you search up the best practices for managing ec2 instance utilization?"}'
```

Expected output:
```json
{
  "response": {
    "output": "Here are some useful resources on best practices for managing EC2 instance utilization..."
  }
}
```

## Configuration Files

- `config.yaml` - Agent configuration and AWS settings
- `.env` - API keys (local development only)
- `cognito_config.json` - Generated after Cognito setup
- `requirements.txt` - Python dependencies