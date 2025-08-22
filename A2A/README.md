# Incident response logging system: Using A2A for Strands and OpenAI agents hosted on Bedrock AgentCore

In this example, we will be setting up an A2A example for building an application where the host or the client agent is enabled to look for incidents and metrics in the AWS account, create JIRA tickets and then also search for the remediation strategies for those issues with the help of capabilities and tools that are offered by two agents:

1. `Strands agent on AgentCore`: This agent is built using Strands and uses all primitives on AgentCore. It is hosted over `HTTP` and uses `OAuth` for identity. In this case, this agent has access to tools and capabilities to get any metrics and interact with your AWS account in natural language and have the ability to create JIRA tickets based on the issues encountered and assign it to the required members.

2. `OpenAI agent on AgentCore`: This agent is built using OpenAI and uses all primitives on AgentCore. It is hosted over `HTTP` and uses `OAuth` for identity. In this case, this agent has access to tools and capabilities to search for remediation strategies on issues that the first agent comes up with.

Our goal is to build a multi-agentic implementation where we can talk to both of these agents built on different frameworks running on agentcore runtime.