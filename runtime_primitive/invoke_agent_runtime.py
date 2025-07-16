# This file can be used to invoke the agent runtime operation
import json
import uuid
import boto3
import glob
import subprocess
import sys
import yaml

wheel_files = glob.glob("../GenesisSDKExamples/wheelhouse/*.whl")
if wheel_files:
    subprocess.check_call([sys.executable, "-m", "pip", "install"] + wheel_files)

# Invoke the agent using the prompt provided below
prompt: str = "What are your capabilities?"
# Initialize the Bedrock AgentCore client
agent_core_client = boto3.client('bedrock-agentcore')
# Load agent ARN from config file
with open('.bedrock_agentcore.yaml', 'r') as f:
    config = yaml.safe_load(f)
    agent_name = config['default_agent']
    agent_arn = config['agents'][agent_name]['bedrock_agentcore']['agent_arn']
    print(f"Using ARN: {agent_arn}")

# Generate a unique session ID using UUID
session_id = str(uuid.uuid4())

# Prepare the payload
payload = json.dumps({"prompt": prompt}).encode()

# Invoke the agent
response = agent_core_client.invoke_agent_runtime(
    agentRuntimeArn=agent_arn,
    runtimeSessionId=session_id,
    payload=payload
)

# Process and print the response
if "text/event-stream" in response.get("contentType", ""):
    # Handle streaming response
    content = []
    for line in response["response"].iter_lines(chunk_size=10):
        if line:
            line = line.decode("utf-8")
            if line.startswith("data: "):
                line = line[6:]
                print(line)
                content.append(line)
    print("\nComplete response:", "\n".join(content))
elif response.get("contentType") == "application/json":
    # Handle standard JSON response
    content = []
    for chunk in response.get("response", []):
        content.append(chunk.decode('utf-8'))
    print(json.loads(''.join(content)))
else:
    # Print raw response for other content types
    print(response)