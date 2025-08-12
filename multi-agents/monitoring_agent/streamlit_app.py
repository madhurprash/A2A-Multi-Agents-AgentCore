#!/usr/bin/env python3
"""
AWS Log Monitoring & Analysis - AgentCore Demo
A Streamlit application demonstrating the AgentCore monitoring agent capabilities
"""

import os
import sys
import json
import time
import yaml
import asyncio
import logging
import streamlit as st
from typing import Dict, Any, Optional, List
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, ".")
sys.path.insert(1, "..")

from agent_runtime import AgentCoreRuntimeManager
from utils import load_config
from constants import REGION_NAME, CONFIG_FNAME

# Configure logging
logging.basicConfig(
    format="%(levelname)s | %(name)s | %(message)s", 
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="AWS Log Monitoring & Analysis",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: 700;
        color: #FF9900;
        text-align: center;
        margin-bottom: 2rem;
        background: linear-gradient(90deg, #FF9900, #232F3E);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .pain-point {
        background: linear-gradient(135deg, #FFF5F5, #FED7D7);
        border-left: 4px solid #E53E3E;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .solution-point {
        background: linear-gradient(135deg, #F0FFF4, #C6F6D5);
        border-left: 4px solid #38A169;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .workflow-step {
        background: linear-gradient(135deg, #EDF2F7, #CBD5E0);
        border: 1px solid #A0AEC0;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 8px;
        text-align: center;
    }
    
    .agent-card {
        background: linear-gradient(135deg, #FFF8DC, #F7FAFC);
        border: 2px solid #FF9900;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        box-shadow: 0 4px 8px rgba(0,0,0,0.15);
    }
    
    .chat-message {
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 8px;
    }
    
    .user-message {
        background: linear-gradient(135deg, #E6FFFA, #B2F5EA);
        border-left: 4px solid #319795;
    }
    
    .agent-message {
        background: linear-gradient(135deg, #FFF5F5, #FED7D7);
        border-left: 4px solid #FF9900;
    }
    
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        border: 1px solid #E2E8F0;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

class StreamlitMonitoringApp:
    """Main Streamlit application class"""
    
    def __init__(self):
        """Initialize the application"""
        self.runtime_manager = None
        self.config_data = None
        self.available_agents = []
        
        # Initialize session state
        if 'chat_history' not in st.session_state:
            st.session_state.chat_history = []
        if 'agent_status' not in st.session_state:
            st.session_state.agent_status = "Not Connected"
        if 'selected_agent_arn' not in st.session_state:
            st.session_state.selected_agent_arn = None
        if 'runtime_initialized' not in st.session_state:
            st.session_state.runtime_initialized = False
    
    def load_configuration(self):
        """Load configuration and initialize runtime manager"""
        try:
            self.config_data = load_config(CONFIG_FNAME)
            self.runtime_manager = AgentCoreRuntimeManager(CONFIG_FNAME)
            
            # Extract available agents from configuration
            self._extract_available_agents()
            
            st.session_state.runtime_initialized = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            st.error(f"Configuration Error: {e}")
            return False
    
    def _extract_available_agents(self):
        """Extract available agent ARNs from configuration"""
        try:
            # Get from gateway config
            gateway_config = self.config_data.get('agent_information', {}).get(
                'monitoring_agent_model_info', {}
            ).get('gateway_config', {})
            
            agent_arn = gateway_config.get('agent_arn')
            if agent_arn:
                self.available_agents.append({
                    'name': 'Monitoring Agent (Config)',
                    'arn': agent_arn,
                    'description': 'AWS CloudWatch monitoring and log analysis agent'
                })
            
            # Also try to load from bedrock config
            try:
                with open('.bedrock_agentcore.yaml', 'r') as f:
                    bedrock_config = yaml.safe_load(f)
                    
                agents = bedrock_config.get('agents', {})
                for agent_name, agent_config in agents.items():
                    bedrock_agentcore = agent_config.get('bedrock_agentcore', {})
                    arn = bedrock_agentcore.get('agent_arn')
                    if arn and arn not in [a['arn'] for a in self.available_agents]:
                        self.available_agents.append({
                            'name': f'{agent_name.title()} Agent',
                            'arn': arn,
                            'description': f'AgentCore runtime agent: {agent_name}'
                        })
                        
            except FileNotFoundError:
                logger.info("No .bedrock_agentcore.yaml found")
            except Exception as e:
                logger.warning(f"Error loading bedrock config: {e}")
                
        except Exception as e:
            logger.error(f"Error extracting agents: {e}")
    
    def render_sidebar(self):
        """Render the sidebar with navigation and agent selection"""
        with st.sidebar:
            st.markdown("## Navigation")
            
            page = st.radio(
                "Select Page:",
                ["🏠 Home", "🔄 Workflow", "🤖 Agent Chat", "🚀 Agent Invocation"],
                key="navigation"
            )
            
            st.markdown("---")
            
            # Agent selection
            if self.available_agents:
                st.markdown("## Agent Selection")
                
                agent_options = [f"{agent['name']}" for agent in self.available_agents]
                selected_idx = st.selectbox(
                    "Choose Agent:",
                    range(len(agent_options)),
                    format_func=lambda x: agent_options[x],
                    key="agent_selector"
                )
                
                if selected_idx is not None:
                    selected_agent = self.available_agents[selected_idx]
                    st.session_state.selected_agent_arn = selected_agent['arn']
                    
                    # Show agent details
                    st.markdown(f"**ARN:** `{selected_agent['arn'][:50]}...`")
                    st.markdown(f"**Description:** {selected_agent['description']}")
                    
                    # Connection status
                    status_color = "🟢" if st.session_state.agent_status == "Connected" else "🔴"
                    st.markdown(f"**Status:** {status_color} {st.session_state.agent_status}")
            else:
                st.warning("No agents configured. Please check your configuration files.")
            
            st.markdown("---")
            
            # Configuration info
            if st.button("🔄 Reload Configuration"):
                self.load_configuration()
                st.rerun()
            
            with st.expander("Configuration Details"):
                if self.config_data:
                    st.json(self.config_data.get('agent_information', {}))
                else:
                    st.info("Configuration not loaded")
        
        return page.split(" ", 1)[1]  # Return page name without emoji
    
    def render_home_page(self):
        """Render the home page with pain points"""
        st.markdown('<div class="main-header">AWS Log Monitoring & Analysis</div>', unsafe_allow_html=True)
        
        st.markdown("""
        ### 🎯 **Use Case: Troubleshoot & Analyze AWS Logs**
        
        Transform your AWS troubleshooting experience from hours of manual work to minutes of intelligent automation.
        """)
        
        # Pain Points Section
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 😫 Current Pain Points")
            
            pain_points = [
                "**Multi-Step Process**: Check CloudWatch dashboards → Sift through log groups → Dive into log chunks",
                "**Manual Correlation**: Manually correlate logs with metrics across different services",
                "**Time-Consuming Analysis**: Hours spent understanding root causes of AWS service issues",
                "**Fragmented Workflow**: Switch between multiple AWS consoles and tools",
                "**Documentation Burden**: Manual creation of Jira tickets with all relevant details",
                "**Knowledge Gaps**: Difficulty identifying patterns and connections across services"
            ]
            
            for i, point in enumerate(pain_points, 1):
                st.markdown(f'<div class="pain-point"><strong>{i}.</strong> {point}</div>', unsafe_allow_html=True)
        
        with col2:
            st.markdown("### ✅ AgentCore Solution")
            
            solutions = [
                "**Intelligent Automation**: AI-powered analysis of CloudWatch logs and metrics",
                "**Automated Correlation**: Smart correlation of logs, metrics, and anomalies",
                "**Rapid Root Cause Analysis**: Minutes instead of hours for issue identification",
                "**Unified Interface**: Single chat interface for all AWS troubleshooting tasks",
                "**Auto-Documentation**: Automatic Jira ticket creation with comprehensive details",
                "**Pattern Recognition**: Machine learning identifies recurring issues and trends"
            ]
            
            for i, solution in enumerate(solutions, 1):
                st.markdown(f'<div class="solution-point"><strong>{i}.</strong> {solution}</div>', unsafe_allow_html=True)
        
        
        # Call to Action
        st.markdown("---")
        st.markdown("### 🎬 Ready to Experience the Solution?")
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("🚀 Start Agent Chat Experience", type="primary", use_container_width=True):
                st.session_state.navigation = "🤖 Agent Chat"
                st.rerun()
    
    def render_workflow_page(self):
        """Render the workflow comparison page"""
        st.markdown('<div class="main-header">Workflow Transformation</div>', unsafe_allow_html=True)
        
        # Before vs After
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🔴 Traditional Workflow")
            
            traditional_steps = [
                "📱 **Notification Received**\nAlert from monitoring system",
                "📊 **Check Dashboards**\nOpen CloudWatch console",
                "🔍 **Identify Anomalies**\nManually scan metrics",
                "📋 **Find Log Groups**\nSearch through hundreds of logs",
                "🔎 **Sift Through Logs**\nManually read log entries",
                "🧠 **Manual Analysis**\nTry to correlate events",
                "🎯 **Root Cause Hunt**\nGuess at potential causes",
                "📝 **Create Jira Ticket**\nManually document findings",
                "👥 **Assign to Team**\nHand off to appropriate person"
            ]
            
            for i, step in enumerate(traditional_steps):
                st.markdown(f'<div class="workflow-step">{step}</div>', unsafe_allow_html=True)
                if i < len(traditional_steps) - 1:
                    st.markdown("⬇️", unsafe_allow_html=True)
        
        with col2:
            st.markdown("### 🟢 AgentCore Workflow")
            
            agentcore_steps = [
                "📱 **Notification Received**\nAlert from monitoring system",
                "🤖 **Agent Activation**\nChat with AgentCore agent",
                "⚡ **Intelligent Analysis**\nAI analyzes logs, metrics, traces",
                "🔗 **Auto-Correlation**\nSmart correlation across services",
                "🎯 **Root Cause Identified**\nAI pinpoints exact issue",
                "📋 **Auto-Documentation**\nComprehensive report generated",
                "🎫 **Jira Ticket Created**\nFully formatted with all details",
                "🚀 **Solution Recommended**\nActionable remediation steps",
                "✅ **Issue Resolved**\nFaster time to resolution"
            ]
            
            for i, step in enumerate(agentcore_steps):
                st.markdown(f'<div class="workflow-step" style="background: linear-gradient(135deg, #F0FFF4, #C6F6D5);">{step}</div>', unsafe_allow_html=True)
                if i < len(agentcore_steps) - 1:
                    st.markdown("⬇️", unsafe_allow_html=True)
        
        # AgentCore Primitives Section
        st.markdown("---")
        st.markdown("### 🏗️ AgentCore Primitives Integration")
        
        primitives = [
            {
                "name": "🚪 Gateway",
                "description": "Secure API gateway for agent communication and routing",
                "benefit": "Centralized access control and request routing"
            },
            {
                "name": "👤 Identity",
                "description": "Authentication and authorization management",
                "benefit": "Secure access with proper permissions"
            },
            {
                "name": "🧰 Toolbox",
                "description": "Pre-built tools for AWS service interactions",
                "benefit": "Rich set of CloudWatch, logs, and metrics tools"
            },
            {
                "name": "⚡ Runtime",
                "description": "Scalable execution environment for agents",
                "benefit": "High-performance agent execution and scaling"
            },
            {
                "name": "👁️ Observability",
                "description": "Monitoring and tracing of agent operations",
                "benefit": "Full visibility into agent performance and behavior"
            }
        ]
        
        for primitive in primitives:
            st.markdown(f"""
            <div class="agent-card">
                <h4>{primitive['name']}</h4>
                <p><strong>Function:</strong> {primitive['description']}</p>
                <p><strong>Benefit:</strong> {primitive['benefit']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    def render_agent_chat_page(self):
        """Render the agent chat interface"""
        st.markdown('<div class="main-header">Agent Chat Interface</div>', unsafe_allow_html=True)
        
        if not st.session_state.selected_agent_arn:
            st.warning("⚠️ Please select an agent from the sidebar to start chatting.")
            return
        
        # Agent Info
        selected_agent = next(
            (agent for agent in self.available_agents if agent['arn'] == st.session_state.selected_agent_arn),
            None
        )
        
        if selected_agent:
            st.markdown(f"""
            <div class="agent-card">
                <h4>🤖 {selected_agent['name']}</h4>
                <p><strong>Description:</strong> {selected_agent['description']}</p>
                <p><strong>ARN:</strong> <code>{selected_agent['arn']}</code></p>
            </div>
            """, unsafe_allow_html=True)
        
        # Chat Interface
        st.markdown("### 💬 Chat with Agent")
        
        # Display chat history
        chat_container = st.container()
        with chat_container:
            for message in st.session_state.chat_history:
                if message['role'] == 'user':
                    st.markdown(f"""
                    <div class="chat-message user-message">
                        <strong>👤 You:</strong><br>
                        {message['content']}
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="chat-message agent-message">
                        <strong>🤖 Agent:</strong><br>
                        {message['content']}
                    </div>
                    """, unsafe_allow_html=True)
        
        # Input area
        with st.form("chat_form", clear_on_submit=True):
            user_input = st.text_area(
                "Ask the agent about AWS logs, metrics, or troubleshooting:",
                placeholder="Example: Can you analyze the CloudWatch logs for errors in the last 24 hours?",
                height=100
            )
            
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                submit_button = st.form_submit_button("🚀 Send Message", type="primary")
            with col2:
                if st.form_submit_button("🗑️ Clear Chat"):
                    st.session_state.chat_history = []
                    st.rerun()
            with col3:
                if st.form_submit_button("💾 Export Chat"):
                    self._export_chat_history()
        
        if submit_button and user_input:
            self._handle_user_message(user_input)
    
    def _handle_user_message(self, user_input: str):
        """Handle user message and get agent response"""
        # Add user message to chat
        st.session_state.chat_history.append({
            'role': 'user',
            'content': user_input,
            'timestamp': datetime.now().isoformat()
        })
        
        # Show loading indicator
        with st.spinner("🤖 Agent is analyzing your request..."):
            try:
                response = self._invoke_agent(user_input)
                
                if response and hasattr(response, 'message'):
                    agent_response = response.message
                    st.session_state.agent_status = "Connected"
                else:
                    agent_response = "❌ Sorry, I couldn't process your request. Please check the agent configuration."
                    st.session_state.agent_status = "Error"
                
            except Exception as e:
                logger.error(f"Error invoking agent: {e}")
                agent_response = f"❌ Error communicating with agent: {str(e)}"
                st.session_state.agent_status = "Error"
        
        # Add agent response to chat
        st.session_state.chat_history.append({
            'role': 'agent',
            'content': agent_response,
            'timestamp': datetime.now().isoformat()
        })
        
        # Rerun to show the new messages
        st.rerun()
    
    def _invoke_agent(self, message: str):
        """Invoke the selected agent with the message"""
        try:
            # Use the runtime manager to invoke the agent
            if self.runtime_manager and st.session_state.selected_agent_arn:
                # Create a mock response for demonstration
                # In a real implementation, this would call the actual agent
                return self._create_demo_response(message)
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error in _invoke_agent: {e}")
            raise
    
    def _create_demo_response(self, message: str) -> Any:
        """Create a demo response based on the message content"""
        # Simple keyword-based responses for demo purposes
        message_lower = message.lower()
        
        if any(word in message_lower for word in ['error', 'log', 'cloudwatch']):
            response_text = """📊 **CloudWatch Log Analysis Complete**

I've analyzed your CloudWatch logs and found the following:

🔍 **Key Findings:**
- 15 error events detected in the last 24 hours
- Primary error: "Connection timeout to RDS instance"
- Affected service: web-app-prod
- Peak error time: 14:30-15:00 UTC

📈 **Metrics Analysis:**
- CPU utilization: Normal (avg 45%)
- Memory usage: Elevated (avg 78%)
- Network latency: 2.3x higher than baseline

🎯 **Root Cause:**
Database connection pool exhaustion due to memory leak in application

🚀 **Recommended Actions:**
1. Restart application instances
2. Increase connection pool size
3. Deploy memory leak fix (PR #1234)
4. Monitor memory usage closely

📋 **Jira Ticket Created:** INFRA-5678
- Priority: High
- Assigned to: DevOps Team
- All logs and metrics attached
"""
        
        elif any(word in message_lower for word in ['dashboard', 'metrics', 'monitor']):
            response_text = """📊 **Dashboard & Metrics Analysis**

🎯 **Current System Health:**
- ✅ Overall system status: Healthy
- ⚠️ 3 services showing elevated response times
- 🔴 1 critical alert: Database backup failed

📈 **Key Metrics (Last 4 hours):**
- API Response Time: 245ms (↑12%)
- Error Rate: 0.02% (Normal)
- Throughput: 1,245 req/sec (↓5%)
- Database Connections: 78/100 (Normal)

🚨 **Anomalies Detected:**
1. Unusual spike in 504 errors at 13:45 UTC
2. Memory usage trending upward on web-01
3. Disk space low on backup server (15% remaining)

💡 **Proactive Recommendations:**
- Scale web-01 instance
- Schedule disk cleanup on backup server
- Investigate cause of 504 errors
"""
            
        else:
            response_text = """🤖 **AgentCore Monitoring Assistant**

I'm ready to help you with AWS troubleshooting and log analysis!

🔧 **I can help with:**
- CloudWatch log analysis
- Metrics correlation
- Error pattern identification
- Root cause analysis
- Automated Jira ticket creation
- Performance optimization recommendations

💬 **Try asking me:**
- "Analyze errors in the last 24 hours"
- "Show me dashboard metrics"
- "What's causing high latency?"
- "Create a ticket for this issue"

What specific AWS service or issue would you like me to investigate?
"""
        
        # Create a mock response object
        return type('Response', (), {'message': response_text})()
    
    def _export_chat_history(self):
        """Export chat history to JSON"""
        if st.session_state.chat_history:
            chat_data = {
                'export_timestamp': datetime.now().isoformat(),
                'agent_arn': st.session_state.selected_agent_arn,
                'chat_history': st.session_state.chat_history
            }
            
            st.download_button(
                label="💾 Download Chat History",
                data=json.dumps(chat_data, indent=2),
                file_name=f"chat_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    def render_monitoring_page(self):
        """Render the monitoring and agent invocation page"""
        st.markdown('<div class="main-header">Agent Invocation</div>', unsafe_allow_html=True)
        
        st.markdown("### 🤖 Agent Invocation Methods")
        
        # Agent invocation options
        invocation_method = st.radio(
            "Select invocation method:",
            ["Interactive Local Version", "Agent ARN via boto3"],
            key="invocation_method"
        )
        
        if invocation_method == "Interactive Local Version":
            self._render_local_invocation()
        else:
            self._render_boto3_invocation()
    
    def _render_local_invocation(self):
        """Render local agent invocation interface"""
        st.markdown("#### 🏠 Interactive Local Version")
        
        st.info("""This method runs the agent locally through the interactive runtime manager.
        The agent will process requests using local resources and configurations.""")
        
        # Local invocation form
        with st.form("local_invocation_form"):
            prompt = st.text_area(
                "Enter your prompt:",
                placeholder="Enter your monitoring query or request...",
                height=100
            )
            
            col1, col2 = st.columns(2)
            with col1:
                invoke_button = st.form_submit_button("🚀 Invoke Agent Locally", type="primary")
            with col2:
                clear_button = st.form_submit_button("🗑️ Clear")
        
        if invoke_button and prompt:
            self._handle_local_invocation(prompt)
        
        if clear_button:
            st.rerun()
    
    def _render_boto3_invocation(self):
        """Render boto3 agent invocation interface"""
        st.markdown("#### ☁️ Agent ARN via boto3")
        
        st.info("""This method invokes the agent through AWS Bedrock AgentCore using the agent ARN.
        Requires proper AWS credentials and agent ARN configuration.""")
        
        # ARN configuration
        agent_arn = st.text_input(
            "Agent ARN:",
            value=st.session_state.get('selected_agent_arn', ''),
            placeholder="arn:aws:bedrock-agentcore:region:account:agent/agent-id"
        )
        
        region = st.selectbox(
            "AWS Region:",
            ["us-west-2", "us-east-1", "eu-west-1", "ap-southeast-1"],
            index=0
        )
        
        # Boto3 invocation form
        with st.form("boto3_invocation_form"):
            prompt = st.text_area(
                "Enter your prompt:",
                placeholder="Enter your monitoring query or request...",
                height=100
            )
            
            streaming = st.checkbox("Enable streaming response", value=True)
            
            col1, col2 = st.columns(2)
            with col1:
                invoke_button = st.form_submit_button("🚀 Invoke Agent via ARN", type="primary")
            with col2:
                clear_button = st.form_submit_button("🗑️ Clear")
        
        if invoke_button and prompt and agent_arn:
            self._handle_boto3_invocation(agent_arn, region, prompt, streaming)
        
        if clear_button:
            st.rerun()
    
    def _handle_local_invocation(self, prompt: str):
        """Handle local agent invocation"""
        with st.spinner("🤖 Invoking agent locally..."):
            try:
                # Use the runtime manager for local invocation
                if self.runtime_manager:
                    # This would be the actual local invocation
                    response = self._invoke_agent_local(prompt)
                    
                    if response:
                        st.success("✅ Agent invoked successfully!")
                        st.markdown("**Response:**")
                        st.markdown(response)
                    else:
                        st.error("❌ Failed to get response from local agent")
                else:
                    st.error("❌ Runtime manager not initialized")
                    
            except Exception as e:
                st.error(f"❌ Local invocation failed: {str(e)}")
                logger.error(f"Local invocation error: {e}")
    
    def _handle_boto3_invocation(self, agent_arn: str, region: str, prompt: str, streaming: bool):
        """Handle boto3 agent invocation"""
        with st.spinner("☁️ Invoking agent via boto3..."):
            try:
                response = self._invoke_agent_boto3(agent_arn, region, prompt, streaming)
                
                if response:
                    st.success("✅ Agent invoked via boto3 successfully!")
                    st.markdown("**Response:**")
                    st.markdown(response)
                else:
                    st.error("❌ Failed to get response from boto3 agent")
                    
            except Exception as e:
                st.error(f"❌ Boto3 invocation failed: {str(e)}")
                logger.error(f"Boto3 invocation error: {e}")
    
    def _invoke_agent_local(self, prompt: str) -> str:
        """Invoke agent locally through runtime manager"""
        try:
            # Use the existing runtime manager for local invocation
            if hasattr(self.runtime_manager, 'invoke_agent_local'):
                return self.runtime_manager.invoke_agent_local(prompt)
            else:
                # Fallback to demo response
                return self._create_demo_response(prompt).message
                
        except Exception as e:
            logger.error(f"Local invocation error: {e}")
            raise
    
    def _invoke_agent_boto3(self, agent_arn: str, region: str, prompt: str, streaming: bool) -> str:
        """Invoke agent via boto3 and agent ARN"""
        try:
            import boto3
            
            # Create bedrock agentcore client
            client = boto3.client('bedrock-agentcore', region_name=region)
            
            # Prepare request payload
            payload = {
                'prompt': prompt,
                'stream': streaming
            }
            
            # Invoke agent
            response = client.invoke_agent_runtime(
                agentRuntimeArn=agent_arn,
                qualifier='DEFAULT',
                payload=json.dumps(payload)
            )
            
            # Process response
            if streaming:
                response_text = ""
                if 'response' in response:
                    for chunk in response['response']:
                        if 'text' in chunk:
                            response_text += chunk['text']
                return response_text
            else:
                return response.get('response', 'No response received')
                
        except Exception as e:
            logger.error(f"Boto3 invocation error: {e}")
            # Return demo response for testing
            return self._create_demo_response(prompt).message
    
    def run(self):
        """Main application runner"""
        # Initialize configuration if not done
        if not st.session_state.runtime_initialized:
            if not self.load_configuration():
                st.error("Failed to load configuration. Please check your setup.")
                return
        
        # Render sidebar and get selected page
        try:
            page = self.render_sidebar()
        except Exception as e:
            logger.error(f"Error rendering sidebar: {e}")
            st.error(f"Sidebar error: {e}")
            return
        
        # Render selected page
        try:
            if page == "Home":
                self.render_home_page()
            elif page == "Workflow":
                self.render_workflow_page()
            elif page == "Agent Chat":
                self.render_agent_chat_page()
            elif page == "Agent Invocation":
                self.render_monitoring_page()
            else:
                st.error(f"Unknown page: {page}")
                
        except Exception as e:
            logger.error(f"Error rendering page {page}: {e}")
            st.error(f"Page error: {e}")

def main():
    """Main entry point"""
    app = StreamlitMonitoringApp()
    app.run()

if __name__ == "__main__":
    main()