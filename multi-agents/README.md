1. Install dependencies:
  cd /Users/madhurpt/Desktop/genesis
  pip install -e .

  2. Set up environment variables:
  export AWS_DEFAULT_REGION=us-west-2  # or your preferred region
  export GITHUB_CLIENT_ID=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
  export JIRA_ORG_ID=fa5d9a36-e5d5-4b2a-9e45-ebf7128912e6
  export JIRA_API_KEY=ATCTT3xFfGN0tgNGudZGGFo7UmWzRNfvdwEAyvGH5dmO0A_30BNlW20f3-UUglu80ELO-laEapOQTE1077sSOj8hbMpF19414zfZg2XUwKPgdjd42-XlMiOLy9URtv-XMqbVN1Ogu6e4jtoEe6pEod1CT_Qv7LpInDl1jiP9qqSMh8QbxP1SigU=FC63175B

  Quick Start

  3. Navigate to the ops orchestrator directory:
  cd multi-agents/ops_orchestrator_agent

  4. Run the main agent:
  python ops_orchestrator_multi_agent.py

  Key Features

  - Automated incident triaging with PagerDuty and JIRA integration
  - ChatOps collaboration via Teams, Slack, Gmail
  - Report generation with GitHub integration
  - Multi-agent memory system using Bedrock AgentCore
  - MCP Gateway for tool integration

  Configuration

  The agent uses config.yaml for configuration. Key settings:
  - Memory IDs are pre-configured for existing memories
  - Gateway credentials are stored in mcp_credentials.json
  - API integrations configured for GitHub, JIRA, Slack, PagerDuty

  The system is already configured with gateway credentials and memory IDs, so it should work immediately after installing dependencies.
