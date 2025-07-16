import os
import sys
import json
import glob
import boto3
import logging
import subprocess

wheel_files = glob.glob("../GenesisSDKExamples/wheelhouse/*.whl")
if wheel_files:
    subprocess.check_call([sys.executable, "-m", "pip", "install"] + wheel_files)

from bedrock_agentcore.gateway import GatewayClient

# Initialize the gateway and the authorizer
gateway_name = "GenesisGatewayTest"
# Initialize the gateway client
client = GatewayClient(region_name="us-west-2")
account_id = boto3.client("sts").get_caller_identity()["Account"]
execution_role_arn = f"arn:aws:iam::{account_id}:role/GenesisGatewayExecutionRole"
lambda_arn = f"arn:aws:lambda:us-west-2:{account_id}:function:GenesisTestFunction"

# setup your authorizer
cognito_result = client.create_oauth_authorizer_with_cognito(gateway_name)

# setup your gateway
lambda_config = {
    "arn": lambda_arn,
    "tools": [
        {
            "name": "get_weather",
            "description": "Get weather for a location",
            "inputSchema": {
                "type": "object",
                "properties": {"location": {"type": "string"}},
                "required": ["location"],
            },
        },
        {
            "name": "get_time",
            "description": "Get time for a timezone",
            "inputSchema": {
                "type": "object",
                "properties": {"timezone": {"type": "string"}},
                "required": ["timezone"],
            },
        },
    ],
}

# Create gateway using the high-level method
gateway = client.setup_gateway(
    gateway_name=gateway_name,
    target_source=json.dumps(lambda_config),
    execution_role_arn=execution_role_arn,
    authorizer_config=cognito_result["authorizer_config"],
    target_type="lambda",
    description="Test Gateway with Cognito OAuth",
)

access_token = client.get_test_token_for_cognito(cognito_result["client_info"])
mcp_url = gateway.get_mcp_url()
print(f"MCP Server URL: {mcp_url} Access Token: {access_token}")

# Next, use this with an agent
import os
import logging
from strands import Agent
from strands.models import BedrockModel
from strands.tools.mcp.mcp_client import MCPClient
from mcp.client.streamable_http import streamablehttp_client 

def create_streamable_http_transport(mcp_url: str, access_token: str):
       return streamablehttp_client(mcp_url, headers={"Authorization": f"Bearer {access_token}"})

def run_agent(mcp_url: str, access_token: str):
    bedrockmodel = BedrockModel(
        inference_profile_id="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
        temperature=0.1,
        streaming=True,
    )
     
    mcp_client = MCPClient(lambda: create_streamable_http_transport(mcp_url, access_token))
     
    with mcp_client:
        tools = mcp_client.list_tools_sync()
        print(f"Found the following tools: {[{"name": tool.tool_name, "spec": tool.tool_spec} for tool in tools]}")
        agent = Agent(model=bedrockmodel,tools=tools)
        while True:
            user_input = input("\nThis is an interactive Strands Agent. Ask me something. When you're finished, say exit or quit: ")
            if user_input.lower() in ["exit", "quit", "bye"]:
                print("Goodbye!")
                break
            print("\nThinking...\n")
            agent(user_input)

# Run your agent!
run_agent(mcp_url, access_token)