#!/usr/bin/env python3
"""
AWS Monitoring Agent - Streamlit Application
This application demonstrates the pain points of traditional AWS log troubleshooting
and runs the actual monitoring_agent.py --interactive mode within the Streamlit interface.
"""

import os
import sys
import json
import time
import uuid
import logging
import streamlit as st
import subprocess
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime
import pandas as pd
from queue import Queue, Empty

# Add current directory to path for imports
sys.path.insert(0, ".")
sys.path.insert(1, "..")

from utils import load_config
from constants import *

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)
logger = logging.getLogger(__name__)

# Set page config with dark theme
st.set_page_config(
    page_title="AWS Monitoring Agent",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply dark theme CSS
st.markdown("""
<style>
    /* Dark theme styling */
    .stApp {
        background-color: #0e1117;
        color: #fafafa;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background-color: #262730;
    }
    
    /* Header styling */
    .css-10trblm {
        color: #fafafa;
    }
    
    /* Code blocks */
    .stCode {
        background-color: #1e1e1e;
        border: 1px solid #333;
        color: #f8f8f2;
    }
    
    /* Terminal output styling */
    .stCode > div {
        background-color: #1a1a1a !important;
        color: #00ff00 !important;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace !important;
    }
    
    /* Success messages */
    .stSuccess {
        background-color: #1e3a1e;
        border-color: #4caf50;
        color: #4caf50;
    }
    
    /* Error messages */
    .stError {
        background-color: #3a1e1e;
        border-color: #f44336;
        color: #f44336;
    }
    
    /* Warning messages */
    .stWarning {
        background-color: #3a331e;
        border-color: #ff9800;
        color: #ff9800;
    }
    
    /* Info messages */
    .stInfo {
        background-color: #1e2a3a;
        border-color: #2196f3;
        color: #2196f3;
    }
    
    /* Button styling */
    .stButton > button {
        background-color: #262730;
        color: #fafafa;
        border: 1px solid #444;
        border-radius: 6px;
    }
    
    .stButton > button:hover {
        background-color: #333;
        border-color: #666;
    }
    
    /* Primary button */
    .stButton > button[kind="primary"] {
        background-color: #0066cc;
        border-color: #0066cc;
        color: white;
    }
    
    .stButton > button[kind="primary"]:hover {
        background-color: #0052a3;
        border-color: #0052a3;
    }
    
    /* Chat input */
    .stChatInput {
        background-color: #262730;
        border: 1px solid #444;
    }
    
    /* Chat messages */
    .stChatMessage {
        background-color: #1a1a1a;
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #262730;
    }
    
    .stTabs [data-baseweb="tab"] {
        color: #fafafa;
        background-color: #262730;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #0066cc;
        color: white;
    }
    
    /* Metrics */
    .css-1xarl3l {
        background-color: #1a1a1a;
        border: 1px solid #333;
        border-radius: 8px;
    }
    
    /* Remove Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Custom terminal styling */
    .terminal-output {
        background-color: #000000;
        color: #ffffff;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 13px;
        padding: 20px;
        border-radius: 8px;
        border: 1px solid #333;
        max-height: 600px;
        overflow-y: auto;
        white-space: pre-wrap;
        word-wrap: break-word;
        line-height: 1.4;
    }
</style>
""", unsafe_allow_html=True)

class MonitoringAgentRunner:
    """Class to handle running the monitoring agent interactively"""
    
    def __init__(self):
        self.process = None
        self.output_queue = Queue()
        self.session_id = f"streamlit-{int(time.time())}-{uuid.uuid4().hex[:8]}"
        
    def start_agent(self):
        """Start the monitoring agent process"""
        try:
            # Start the monitoring agent in interactive mode
            cmd = [
                sys.executable, 
                "monitoring_agent.py", 
                "--interactive"
            ]
            
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=0,  # Unbuffered
                universal_newlines=True,
                env=dict(os.environ, PYTHONUNBUFFERED="1")  # Force Python to be unbuffered
            )
            
            # Start thread to read output
            self.output_thread = threading.Thread(target=self._read_output)
            self.output_thread.daemon = True
            self.output_thread.start()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start monitoring agent: {e}")
            return False
    
    def _read_output(self):
        """Read output from the monitoring agent process"""
        if not self.process:
            return
            
        for line in iter(self.process.stdout.readline, ''):
            if line:
                self.output_queue.put(line.rstrip())
    
    def send_message(self, message: str):
        """Send a message to the monitoring agent"""
        if self.process and self.process.stdin:
            try:
                self.process.stdin.write(f"{message}\n")
                self.process.stdin.flush()
                return True
            except Exception as e:
                logger.error(f"Failed to send message: {e}")
                return False
        return False
    
    def get_output(self, timeout=1):
        """Get output from the monitoring agent"""
        outputs = []
        try:
            while True:
                try:
                    output = self.output_queue.get(timeout=timeout)
                    outputs.append(output)
                except Empty:
                    break
        except Exception as e:
            logger.error(f"Error getting output: {e}")
        return outputs
    
    def is_running(self):
        """Check if the agent process is still running"""
        return self.process and self.process.poll() is None
    
    def stop_agent(self):
        """Stop the monitoring agent process"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

class MonitoringStreamlitApp:
    """Main Streamlit application for AWS monitoring agent"""
    
    def __init__(self):
        """Initialize the Streamlit app"""
        self.config_data = self._load_config()
        self.setup_session_state()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            return load_config('config.yaml')
        except Exception as e:
            st.error(f"Failed to load configuration: {e}")
            return {}
    
    def setup_session_state(self):
        """Initialize session state variables"""
        if 'agent_runner' not in st.session_state:
            st.session_state.agent_runner = None
        if 'chat_history' not in st.session_state:
            st.session_state.chat_history = []
        if 'agent_output_history' not in st.session_state:
            st.session_state.agent_output_history = []
        if 'agent_started' not in st.session_state:
            st.session_state.agent_started = False
    
    def _filter_terminal_output(self, output_lines: List[str]) -> str:
        """Show raw terminal output without filtering for debugging"""
        if not output_lines:
            return ""
        
        # Return all output without filtering, preserving formatting
        return '\n'.join(output_lines[-100:])  # Show last 100 lines
    
    def render_header(self):
        """Render the application header"""
        st.markdown("""
        <div style='text-align: center; padding: 20px;'>
            <h1 style='color: #00ff00; font-size: 3em; margin-bottom: 10px;'>🔍 AWS Monitoring Agent</h1>
            <h3 style='color: #0066cc; font-weight: 300;'>Transform Your AWS Log Troubleshooting Experience</h3>
            <hr style='border: 1px solid #333; margin: 20px 0;'>
        </div>
        """, unsafe_allow_html=True)
    
    def render_pain_points_section(self):
        """Render the pain points section on the home page"""
        st.header("🚨 Traditional AWS Log Troubleshooting Pain Points")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### Current Challenges:
            
            **📊 Manual Dashboard Navigation**
            - Navigate through multiple CloudWatch dashboards
            - Manually identify anomalies and patterns
            - Time-consuming visual inspection
            
            **🔍 Log Group Exploration**
            - Sift through numerous log groups
            - Search across multiple log streams
            - Complex query syntax required
            
            **📋 Manual Analysis**
            - Correlate logs with metrics manually
            - Time-intensive root cause analysis
            - No automated insights
            """)
        
        with col2:
            st.markdown("""
            ### Traditional Workflow Issues:
            
            **⏱️ Time Consumption**
            - Hours spent on troubleshooting
            - Delayed incident resolution
            - Resource-intensive process
            
            **📝 Documentation Overhead**
            - Manual ticket creation
            - Formatting and assignment delays
            - Context loss during handoffs
            
            **🔄 Repetitive Tasks**
            - Same troubleshooting steps repeated
            - No learning from past incidents
            - Manual remediation planning
            """)
    
    def render_traditional_workflow(self):
        """Render the traditional workflow visualization"""
        st.header("📋 Traditional Troubleshooting Workflow")
        
        # Create workflow steps with pain points
        workflow_steps = [
            ("🚨 Notification", "Alert received via email/Slack", "Manual monitoring required"),
            ("📊 Dashboards", "Navigate CloudWatch dashboards", "Time-consuming navigation"),
            ("🔍 Log Sifting", "Search through log groups/streams", "Complex queries needed"),
            ("📋 Analysis", "Manual correlation of logs/metrics", "Prone to human error"),
            ("🕵️ Root Cause", "Identify underlying issues", "Requires deep expertise"),
            ("🔍 Solutions", "Research fixes and workarounds", "Repetitive research"),
            ("📝 Jira Ticket", "Create detailed incident ticket", "Manual documentation"),
            ("👥 Assignment", "Route to appropriate team", "Delays in handoffs")
        ]
        
        st.markdown("### Pain Point Journey:")
        
        for i, (step, description, pain_point) in enumerate(workflow_steps):
            col1, col2, col3 = st.columns([2, 4, 4])
            
            with col1:
                st.markdown(f"**{step}**")
            with col2:
                st.markdown(f"*{description}*")
            with col3:
                st.markdown(f"❌ {pain_point}")
            
            if i < len(workflow_steps) - 1:
                st.markdown("⬇️")
        
        st.markdown("---")
        st.error("### ⏱️ Total Time: 2-6 Hours Per Incident")
    
    def render_agentcore_solution(self):
        """Render the AgentCore solution section"""
        st.header("🚀 AgentCore Monitoring Agent Solution")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### 🧠 AgentCore Primitives:
            
            **🛡️ Identity & Gateway**
            - Secure agent authentication via Cognito
            - MCP protocol for tool integration
            - Role-based access control
            
            **💾 Memory Management**
            - Contextual memory retention
            - Learning from past incidents
            - User preference tracking
            
            **🔧 Runtime & Observability**
            - Scalable agent execution
            - OpenTelemetry integration
            - Session tracking and monitoring
            """)
        
        with col2:
            st.markdown("""
            ### ⚡ Automated Workflow:
            
            **🔍 Intelligent Analysis**
            - AI-powered log pattern recognition
            - Automated anomaly detection
            - Cross-service correlation
            
            **📊 Smart Insights**
            - Dynamic metric correlation
            - Predictive problem detection
            - Real-time root cause analysis
            
            **🎯 Automated Actions**
            - Suggested remediation steps
            - Automated ticket creation
            - Intelligent team routing
            """)
        
        st.success("### ⚡ New Timeline: 5-15 Minutes Per Incident")
    
    def render_agent_control_panel(self):
        """Render the agent control panel"""
        st.sidebar.header("🤖 Agent Control")
        
        if not st.session_state.agent_started:
            if st.sidebar.button("🚀 Start Monitoring Agent", type="primary"):
                st.session_state.agent_runner = MonitoringAgentRunner()
                with st.spinner("Starting monitoring agent..."):
                    success = st.session_state.agent_runner.start_agent()
                    if success:
                        st.session_state.agent_started = True
                        st.sidebar.success("Agent started successfully!")
                        st.rerun()
                    else:
                        st.sidebar.error("Failed to start agent")
        else:
            # Show agent status
            if st.session_state.agent_runner and st.session_state.agent_runner.is_running():
                st.sidebar.success("🟢 Agent Running")
                
                if st.sidebar.button("🛑 Stop Agent", type="secondary"):
                    st.session_state.agent_runner.stop_agent()
                    st.session_state.agent_started = False
                    st.session_state.agent_runner = None
                    st.rerun()
            else:
                st.sidebar.error("🔴 Agent Stopped")
                st.session_state.agent_started = False
        
        # Show session info
        if st.session_state.agent_runner:
            st.sidebar.info(f"Session ID: {st.session_state.agent_runner.session_id}")
    
    def render_interactive_demo(self):
        """Render the interactive monitoring agent demo"""
        st.header("💬 Live Monitoring Agent Interface")
        
        if not st.session_state.agent_started:
            st.warning("⚠️ Please start the monitoring agent using the control panel in the sidebar.")
            return
        
        # Display agent output in real-time
        output_container = st.container()
        
        with output_container:
            st.subheader("🖥️ Agent Terminal Output")
            
            # Get latest output from agent more frequently for real-time streaming
            if st.session_state.agent_runner:
                new_outputs = st.session_state.agent_runner.get_output(timeout=0.05)
                if new_outputs:
                    st.session_state.agent_output_history.extend(new_outputs)
                    # Only refresh if there's actually new output
                    st.rerun()
                
                # Display raw output history with terminal styling
                if st.session_state.agent_output_history:
                    # Show raw output without filtering
                    raw_output = self._filter_terminal_output(st.session_state.agent_output_history)
                    if raw_output:
                        # Use HTML to preserve formatting and make text more readable
                        formatted_output = raw_output.replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>')
                        st.markdown(
                            f'<div class="terminal-output">{formatted_output}</div>',
                            unsafe_allow_html=True
                        )
                    else:
                        st.info("🤖 Agent is processing...")
                else:
                    st.info("⏳ Waiting for agent output...")
        
        # Chat input
        st.subheader("💬 Chat with Agent")
        
        # Display chat history
        for message in st.session_state.chat_history:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
        
        # Add controls for output streaming
        if st.button("🔄 Refresh Output"):
            st.rerun()
    
    def render_demo_scenarios(self):
        """Render predefined demo scenarios"""
        st.sidebar.header("🎯 Demo Scenarios")
        
        scenarios = [
            {
                "title": "🔥 Lambda Errors",
                "prompt": "I'm seeing errors in my Lambda function logs. Can you help me analyze what's going wrong?"
            },
            {
                "title": "🌐 API Gateway Issues", 
                "prompt": "My API Gateway is returning 5xx errors intermittently. What could be causing this?"
            },
            {
                "title": "⚡ EC2 Performance",
                "prompt": "My EC2 instances are showing high CPU usage. Help me investigate the root cause."
            },
            {
                "title": "🗄️ RDS Connections",
                "prompt": "I'm getting database connection timeout errors. Can you analyze the RDS logs?"
            },
            {
                "title": "📊 CloudWatch Metrics",
                "prompt": "Show me how to analyze CloudWatch metrics for anomalies in my application."
            }
        ]
        
        st.sidebar.markdown("**Quick Test Scenarios:**")
        
        for scenario in scenarios:
            if st.sidebar.button(scenario["title"], key=f"scenario_{scenario['title']}"):
                if st.session_state.agent_runner and st.session_state.agent_runner.is_running():
                    # Add scenario to chat
                    st.session_state.chat_history.append({
                        "role": "user", 
                        "content": scenario["prompt"]
                    })
                    
                    # Send to agent
                    st.session_state.agent_runner.send_message(scenario["prompt"])
                    st.rerun()
                else:
                    st.sidebar.warning("Start the agent first!")
    
    def render_chat_input(self):
        """Render the chat input interface (must be outside tabs)"""
        if not st.session_state.agent_started:
            return
        
        st.markdown("### 💬 Chat with Monitoring Agent")
        st.markdown("*Ask about AWS monitoring, logs, or troubleshooting...*")
        
        # Input for sending messages to agent
        if prompt := st.chat_input("Ask about AWS monitoring, logs, or troubleshooting..."):
            if st.session_state.agent_runner and st.session_state.agent_runner.is_running():
                # Add user message to chat history
                st.session_state.chat_history.append({"role": "user", "content": prompt})
                
                # Send message to agent
                success = st.session_state.agent_runner.send_message(prompt)
                if success:
                    # Show processing indicator
                    with st.spinner("Processing your request..."):
                        # Give agent more time to process and get response
                        time.sleep(3)  
                        
                        # Try to get output multiple times to ensure we capture response
                        all_new_outputs = []
                        for _ in range(5):  # Try 5 times over 5 seconds
                            new_outputs = st.session_state.agent_runner.get_output(timeout=1)
                            if new_outputs:
                                all_new_outputs.extend(new_outputs)
                            time.sleep(1)
                    
                    if all_new_outputs:
                        # Update output history first
                        st.session_state.agent_output_history.extend(all_new_outputs)
                        
                        # Find agent response (typically starts with "agent>")
                        agent_responses = [line for line in all_new_outputs if line.startswith("agent>")]
                        if agent_responses:
                            # Get the last agent response and clean it up
                            latest_response = agent_responses[-1].replace("agent>", "").strip()
                            
                            if latest_response:
                                st.session_state.chat_history.append({
                                    "role": "assistant", 
                                    "content": latest_response
                                })
                        else:
                            # Filter meaningful outputs
                            meaningful_outputs = []
                            for line in all_new_outputs:
                                if (line and not line.startswith("you>") 
                                    and not line.startswith("session_id:")
                                    and not line.startswith("🧪")
                                    and not any(skip in line for skip in ['DEBUG', 'INFO:', 'Request: POST'])):
                                    meaningful_outputs.append(line)
                            
                            if meaningful_outputs:
                                response_text = "\n".join(meaningful_outputs)
                                st.session_state.chat_history.append({
                                    "role": "assistant", 
                                    "content": response_text
                                })
                    else:
                        st.warning("No response received from agent. Please try again.")
                        
                    # Force rerun to display new messages
                    st.rerun()
                else:
                    st.error("Failed to send message to agent")
            else:
                st.error("Agent is not running")
    
    def render_agent_capabilities(self):
        """Render agent capabilities section"""
        st.header("🤖 Monitoring Agent Capabilities")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            #### 📊 **CloudWatch Monitoring**
            - List and analyze CloudWatch dashboards
            - Fetch recent logs for AWS services
            - Retrieve and summarize CloudWatch alarms
            - Analyze log groups for patterns and errors
            
            #### 🔍 **Intelligent Analysis**  
            - AI-powered log pattern recognition
            - Automated anomaly detection
            - Cross-service correlation
            - Root cause analysis
            """)
            
        with col2:
            st.markdown("""
            #### 🎥 **Supported AWS Services**
            - EC2/Compute Instances
            - Lambda Functions 
            - RDS Databases
            - EKS Kubernetes
            - API Gateway
            - S3 Storage
            - VPC Networking
            - AWS Bedrock (AI/ML)
            
            #### 🎯 **Automated Actions**
            - Suggested remediation steps
            - Automated Jira ticket creation
            - Intelligent team routing
            - Real-time insights
            """)
        
        st.markdown("---")
        st.success("⚡ **Performance**: Reduces troubleshooting time from hours to minutes")

    def render_footer(self):
        """Render a clean, minimal footer"""
        st.markdown("<hr style='border: 1px solid #333; margin: 40px 0 20px 0;'>", unsafe_allow_html=True)
        st.markdown(
            "<div style='text-align: center; color: #666; font-size: 0.8em; padding: 10px;'>\n"
            "AWS Monitoring Agent powered by AgentCore Runtime\n"
            "</div>",
            unsafe_allow_html=True
        )

    def run(self):
        """Run the main Streamlit application"""
        self.render_header()
        
        # Sidebar configuration
        self.render_agent_control_panel()
        self.render_demo_scenarios()
        
        # Main content tabs - simplified
        tab1, tab2 = st.tabs([
            "💬 Live Agent Demo", 
            "🔧 Agent Capabilities"
        ])
        
        with tab1:
            self.render_interactive_demo()
        
        with tab2:
            self.render_agent_capabilities()
        
        # Chat input outside of tabs (required by Streamlit)
        self.render_chat_input()
        
        # Footer
        self.render_footer()

def main():
    """Main function to run the Streamlit app"""
    try:
        app = MonitoringStreamlitApp()
        app.run()
    except Exception as e:
        st.error(f"Application error: {e}")
        logger.error(f"Application error: {e}")

if __name__ == "__main__":
    main()