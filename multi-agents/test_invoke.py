#!/usr/bin/env python3

import boto3
import json

def test_invoke():
    """Test invoke the monitoring agent to see print statements in logs"""
    
    # Your agent details from .bedrock_agentcore.yaml
    agent_arn = "arn:aws:bedrock-agentcore:us-west-2:218208277580:runtime/monitoring_agent-SDshHG3yeE"
    region = "us-west-2"
    
    print(f"🚀 Invoking agent: {agent_arn}")
    
    # Create AgentCore client
    client = boto3.client('bedrock-agentcore', region_name=region)
    
    # Invoke the agent - this will trigger the @app.entrypoint function
    response = client.invoke_agent_runtime(
        agentRuntimeArn=agent_arn,
        qualifier="DEFAULT",
        payload=json.dumps({"prompt": "Hello, list available CloudWatch dashboards"})
    )
    
    print("✅ Agent invoked successfully!")
    print(f"Response type: {response.get('contentType')}")
    
    # Parse response
    response_body = response.get("response")
    if hasattr(response_body, 'read'):
        # StreamingBody - read the content
        content = response_body.read().decode('utf-8')
        print(f"Agent response: {content}")
    else:
        print(f"Agent response: {response_body}")

if __name__ == "__main__":
    test_invoke()