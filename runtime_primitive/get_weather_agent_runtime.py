#!/usr/bin/env python
# coding: utf-8

# # Genesis Bedrock AgentCore 
# ---
# 
# Bedrock AgentCore is a managed serviced that enables you to deploy, run and scale your custom agent applications. `BedrockAgentCore` is a python SDK that provides a lightweight wrapper that helps you deploy your agent functions as HTTP services compatible with Amazon Bedrock. 
# 
# ### Deploy your agent with boto3
# ---
# 
# First, we will deploy the agent with boto3. Here, we will initialize a bedrock agent core control session with the endpoint `URL` set. Once done, we will be able to use that client to create a runtime object. This runtime will give us the ability to use a container configuration and then we will be able to interact with this client.
# 
# ```{.python}
# import boto3
# 
# client = boto3.client("bedrock-agentcore-control", region_name="us-west-2", endpoint_url="https://gamma.us-west-2.elcapcp.genesis-primitives.aws.dev")
# 
# response = client.create_agent_runtime(
#     agentRuntimeName='test_agent_boto',
#     agentRuntimeArtifact={
#         'containerConfiguration': {
#             'containerUri': '864899855746.dkr.ecr.us-west-2.amazonaws.com/bedrock_agentcore-test_agent:latest'
#         }
#     },
#     roleArn='arn:aws:iam::864899855746:role/SASTestAdmin',
#     networkConfiguration={
#         "networkMode": "PUBLIC"
#     }
# )
# print(response)
# 
# import boto3
# import json
# client = boto3.client("bedrock-agentcore", region_name="us-west-2", endpoint_url="https://gamma.us-west-2.elcapdp.genesis-primitives.aws.dev")
# response = client.invoke_agent_runtime(
#     agentRuntimeArn="arn:aws:bedrock-agentcore:us-west-2:864899855746:runtime/test_agent_boto2-nIg2xk3VSR",
#     runtimeSessionId="dfmeoagmreaklgmrkleafremoigrmtesogmtrskhmtkrlshmt",
#     payload='{ "prompt": "tell me a fact" }',
#     qualifier="DEFAULT"
# )
# response_body = response['response'].read()
# response_data = json.loads(response_body)
# print("Agent Response:", response_data)
# ```
# 
# 
import subprocess
import sys
import glob

import os
os.environ['_X_AMZN_TRACE_ID'] = ''

wheel_files = glob.glob("../GenesisSDKExamples/wheelhouse/*.whl")
if wheel_files:
    subprocess.check_call([sys.executable, "-m", "pip", "install"] + wheel_files)
import json
import logging

# Create a logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Remove existing handlers
logger.handlers.clear()

# Add a simple handler
handler = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s] p%(process)s {%(filename)s:%(lineno)d} %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# import the runtime 
from bedrock_agentcore.runtime import BedrockAgentCoreApp

# next step is to initialize the app, in this case the application is the BedrockAgentCoreApp
app = BedrockAgentCoreApp()
logger.info(f"Initialized the bedrock agent core app: {app}. Going to use it as an entrypoint that the application users will interact with.")


# ### Decorate the function
# ---
# 
# In this case, we will add the `@app.entrypoint` decorator to the existing function. This function is responsible for accessing a query/any other payload and the running the agent.
import os
import uuid
import logging
from strands import Agent
from datetime import datetime
from typing import Dict, Any, Optional

tool_use_ids=[]

# ─── LOGGER SETUP ──────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def comprehensive_callback_handler(**kwargs):
    """
    Enhanced comprehensive callback handler with LangSmith integration
    """
    
    # === REASONING EVENTS (Agent's thinking process) ===
    if kwargs.get("reasoning", False):
        if "reasoningText" in kwargs:
            reasoning_text = kwargs['reasoningText']
            logger.info(f"🧠 REASONING: {reasoning_text}")
            
        if "reasoning_signature" in kwargs:
            logger.info(f"🔍 REASONING SIGNATURE: {kwargs['reasoning_signature']}")
    
    # === TEXT GENERATION EVENTS ===
    elif "data" in kwargs:
        # Log streamed text chunks from the model
        if kwargs.get("complete", False):
            logger.info("")  # Add newline when complete
    
    # === TOOL EVENTS ===
    elif "current_tool_use" in kwargs:
        tool = kwargs["current_tool_use"]
        tool_use_id = tool["toolUseId"]
        
        if tool_use_id not in tool_use_ids:
            tool_name = tool.get('name', 'unknown_tool')
            tool_input = tool.get('input', {})
            
            logger.info(f"\n🔧 USING TOOL: {tool_name}")
            if "input" in tool:
                logger.info(f"📥 TOOL INPUT: {tool_input}")
            tool_use_ids.append(tool_use_id)
    
    # === TOOL RESULTS ===
    elif "tool_result" in kwargs:
        tool_result = kwargs["tool_result"]
        tool_use_id = tool_result.get("toolUseId")
        result_content = tool_result.get("content", [])
        
        logger.info(f"📤 TOOL RESULT: {result_content}")
    
    # === LIFECYCLE EVENTS ===
    elif kwargs.get("init_event_loop", False):
        logger.info("🔄 Event loop initialized")
        
    elif kwargs.get("start_event_loop", False):
        logger.info("▶️ Event loop cycle starting")
        
    elif kwargs.get("start", False):
        logger.info("📝 New cycle started")
        
    elif kwargs.get("complete", False):
        logger.info("✅ Cycle completed")
        
    elif kwargs.get("force_stop", False):
        reason = kwargs.get("force_stop_reason", "unknown reason")
        logger.info(f"🛑 Event loop force-stopped: {reason}")
    
    # === MESSAGE EVENTS ===
    elif "message" in kwargs:
        message = kwargs["message"]
        role = message.get("role", "unknown")
        logger.info(f"📬 New message created: {role}")
    
    # === ERROR EVENTS ===
    elif "error" in kwargs:
        error_info = kwargs["error"]
        logger.error(f"❌ ERROR: {error_info}")

    # === RAW EVENTS (for debugging) ===
    elif "event" in kwargs:
        # Log raw events from the model stream (optional, can be verbose)
        logger.debug(f"🔍 RAW EVENT: {kwargs['event']}")
    
    # === DELTA EVENTS ===
    elif "delta" in kwargs:
        # Raw delta content from the model
        logger.debug(f"📊 DELTA: {kwargs['delta']}")
    
    # === CATCH-ALL FOR DEBUGGING ===
    else:
        # Log any other events we might have missed
        logger.debug(f"❓ OTHER EVENT: {kwargs}")


# ### Create a simple strands get weather agent
# ---
# 
# In this example, we will create a simple strands get weather agent that will be used for invocation.

# Define the get weather tool
import requests
from strands import tool
from strands_tools import calculator, file_read, editor, journal

@tool
def get_weather(lat: float, lon: float, api_key: str) -> dict:
    """Get current weather data for given coordinates."""
    url = f"https://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={lon}&appid={api_key}&units=metric"
    response = requests.get(url)
    return response.json()

AGENT_SYSTEM_PROMPT: str = """
Human: You are a highly capable AI assistant with access to specialized tools that enhance your ability to help users with a wide range of tasks. You are designed to be helpful, harmless, and honest in all your interactions.

<role>
You are a versatile AI assistant equipped with advanced capabilities including weather data retrieval, mathematical calculations, file operations, code editing, and personal journaling. Your role is to provide comprehensive, accurate, and contextually appropriate responses while leveraging the appropriate tools when needed.
</role>

<capabilities>
You have access to the following tools:

1. **Weather Tool (get_weather)**
   - Retrieves current weather data for any location using latitude/longitude coordinates
   - Provides detailed meteorological information including temperature, humidity, wind speed, and conditions
   - Requires API key for access to OpenWeatherMap service

2. **Calculator Tool**
   - Performs mathematical calculations and complex computations
   - Handles arithmetic, algebraic, and statistical operations
   - Supports advanced mathematical functions and problem-solving

3. **File Reader Tool (file_read)**
   - Reads and processes various file formats
   - Extracts content from documents for analysis or manipulation
   - Supports text files, CSVs, and other common formats

4. **Code Editor Tool**
   - Creates, modifies, and refactors code in multiple programming languages
   - Provides syntax highlighting and code structure improvements
   - Supports debugging and code optimization

5. **Journal Tool**
   - Maintains personal notes and journal entries
   - Organizes thoughts, ideas, and information systematically
   - Supports structured note-taking and retrieval
</capabilities>

<behavioral_guidelines>
- Always consider which tool(s) would be most appropriate for the user's request
- Use tools efficiently and in parallel when possible to maximize productivity
- Provide clear explanations of what tools you're using and why
- If a tool requires specific parameters (like API keys), inform the user of these requirements
- Combine tool outputs with your reasoning to provide comprehensive responses
- Be transparent about any limitations or requirements for tool usage
- Prioritize accuracy and reliability in all tool operations
</behavioral_guidelines>

<interaction_principles>
1. **Clarity**: Always provide clear, structured responses using appropriate formatting
2. **Efficiency**: Use multiple tools simultaneously when tasks are independent
3. **Accuracy**: Verify information and calculations using available tools
4. **Helpfulness**: Actively suggest relevant tools that might assist the user
5. **Transparency**: Explain your tool selection and reasoning process
6. **Adaptability**: Adjust your approach based on the user's specific needs and context
</interaction_principles>

<response_format>
When responding to user requests:

1. **Assessment**: Quickly assess which tools are needed for the task
2. **Tool Selection**: Choose the most appropriate tool(s) for the job
3. **Execution**: Use tools efficiently, employing parallel execution when possible
4. **Integration**: Combine tool outputs with your analysis and reasoning
5. **Presentation**: Present results in a clear, organized manner with proper formatting
6. **Follow-up**: Offer additional assistance or suggest related tools if relevant
</response_format>

<tool_usage_best_practices>
- For weather queries: Always ask for location details if not provided, or help convert addresses to coordinates
- For calculations: Show your work and verify complex computations using the calculator tool
- For file operations: Confirm file access and format compatibility before processing
- For code editing: Understand the programming language and context before making modifications
- For journaling: Maintain organization and structure in entries for easy retrieval
</tool_usage_best_practices>

Assistant:
"""

# initialize the model that will power the financial agent
# in this case, we will use the claude 3-7 model to power the financial 
# agent
import boto3
from strands.models import BedrockModel

# Define the current aws region
region: str = boto3.Session().region_name
print(f"Going to use the agent in the region: {region}")

# Create a bedrock model using the BedrockModel interface
bedrock_model = BedrockModel(
    model_id='us.anthropic.claude-3-5-sonnet-20240620-v1:0',
    region_name=region,
    temperature=0.1,
    max_tokens=512
)
print(f"Initialized the bedrock model: {bedrock_model}")

# create the agent
basic_genesis_strands_agent = Agent(
    system_prompt=AGENT_SYSTEM_PROMPT, 
    tools=[get_weather, 
           calculator, 
           file_read, 
           editor, 
           journal
           ],
    callback_handler=comprehensive_callback_handler
)
logger.info(f"Created the basic strands genesis agent: {basic_genesis_strands_agent}")

DEFAULT_PROMPT: str = "What are your capabilities and what can you help me with? Ask the user back if the user has not provided a question."

@app.entrypoint
def invoke(payload):
    '''
    This is the function that is used as an entrypoint function
    to invoke the agent. This agent can be built using LangGraph, 
    Strands or Bedrock agents, or any other framework for that matter.
    This runtime is agent framework agnostic.
    '''
    user_message = payload.get("prompt", DEFAULT_PROMPT)
    print(f"Going to invoke the agent with the following prompt: {user_message}")
    response = basic_genesis_strands_agent(user_message)
    return {"result": response.message}


# Running this notebook starts a service in 
# The server starts at http://localhost:8080
# Test with curl:
# curl -X POST http://localhost:8080/invocations \
# -H "Content-Type: application/json" \
# -d '{"prompt": "Hello world!"}'

if __name__ == "__main__":
    app.run()
    
# Next steps:
# Now, ensure that this agent code is in a repository with agent.py, requirements.txt and an __init__.py
# Then, we will create a docker image of this agent and push it to ECR which we can then invoke and access through
# various applications
# Step 1: Create an IAM execution role: To use the bedrock agent core runtime, customers will need to pass in an
# execution role in the CreateAgentRuntime API.
# Step 2: Configure the agent to set it up, this will create a docker file and a bedrock agentcore file
# This IAM role has Admin access, but in a production like scenario, it will have access to Bedrock, and other relevant services
# command: agentcore configure --entrypoint get_weather_agent_runtime.py -er arn:aws:iam::218208277580:role/service-role/Amazon-Bedrock-IAM-Role-20240102T112809
# Step 3: There are two options now, launch locally or launch to the cloud
# LAUNCH LOCALLY: agentcore launch -l --> This will build a docker image, run it locally and start the server at localhost
# LAUNCH ON AWS: agentcore launch --> Build a docker image with the code, push to ECR repo, create the agentcore runtime and deploy the agent
# Make sure your requirements.txt file contains everything needed and all the packages required to deploy the agent to the cloud.
# IMPORTANT - MAKE SURE TO ADD THE TRUST POLICY TO THE IAM ROLE.