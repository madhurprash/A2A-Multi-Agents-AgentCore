#!/usr/bin/env python3

import boto3
import json
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)
logger = logging.getLogger(__name__)

# Initialize the bedrock-agentcore runtime client
client = boto3.client('bedrock-agentcore', region_name='us-west-2')

input_text = "Hello, how can you assist me today?"

try:
    response = client.invoke_agent_runtime(
        agentRuntimeArn="arn:aws:bedrock-agentcore:us-west-2:218208277580:runtime/monitoring_agent-ZDhxOY3gfl",
        qualifier="DEFAULT",
        payload=input_text
    )
    
    logger.info("Response received successfully")
    logger.info(f"Response:\n{json.dumps(response, indent=2, default=str)}")
    
except Exception as e:
    logger.error(f"Error invoking agent runtime: {e}")
    raise