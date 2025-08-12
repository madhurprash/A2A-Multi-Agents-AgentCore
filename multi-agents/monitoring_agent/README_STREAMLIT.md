# AWS Monitoring Agent - Streamlit Demo

This Streamlit application demonstrates the transformation from traditional AWS log troubleshooting to an AI-powered monitoring agent using AgentCore primitives.

## Features

### 🏠 Pain Points Overview
- Visualizes traditional AWS troubleshooting challenges
- Shows time-consuming manual processes
- Highlights inefficiencies in current workflows

### 📊 Traditional Workflow Analysis
- Step-by-step breakdown of traditional troubleshooting
- Timeline analysis showing 2-6 hours per incident
- Pain point identification at each stage

### 🚀 AgentCore Solution
- AgentCore primitives explanation (Identity, Gateway, Memory, Runtime, Observability)
- AI-powered automation capabilities
- Demonstrates 90% improvement in resolution time

### 💬 Live Interactive Demo
- **Runs actual `monitoring_agent.py --interactive` within Streamlit**
- Real-time terminal output display
- Interactive chat interface with the monitoring agent
- Pre-built demo scenarios for testing

## Prerequisites

1. **Environment Setup**: Ensure you have all the required dependencies from the main monitoring agent
2. **AWS Configuration**: Valid AWS credentials and proper IAM roles
3. **AgentCore Setup**: Gateway, Cognito, and other AgentCore primitives configured
4. **Python Environment**: Python 3.11+ recommended

## Installation

1. **Install Streamlit dependencies**:
   ```bash
   pip install -r streamlit_requirements.txt
   ```

2. **Ensure monitoring agent dependencies are installed**:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

### Method 1: Direct Streamlit Run
```bash
streamlit run streamlit_monitoring_app.py
```

### Method 2: Using UV (recommended)
```bash
uv run streamlit run streamlit_monitoring_app.py
```

The application will open in your browser at `http://localhost:8501`

## Using the Application

### 1. Start the Monitoring Agent
- Use the sidebar "🤖 Agent Control" panel
- Click "🚀 Start Monitoring Agent" to launch the interactive agent process
- Monitor the agent status (🟢 Running / 🔴 Stopped)

### 2. Explore Pain Points
- Navigate through the tabs to understand traditional challenges
- Compare with AgentCore solution benefits
- Review workflow transformations

### 3. Interactive Demo
- Go to the "💬 Live Demo" tab
- Use the chat interface to interact with the actual monitoring agent
- Try pre-built scenarios from the sidebar
- Watch real-time terminal output from the monitoring agent

### 4. Demo Scenarios
Use the sidebar scenarios to test different use cases:
- 🔥 Lambda function errors
- 🌐 API Gateway issues  
- ⚡ EC2 performance problems
- 🗄️ RDS connection issues
- 📊 CloudWatch metrics analysis

## Architecture

### Components
1. **MonitoringAgentRunner**: Manages the subprocess running `monitoring_agent.py --interactive`
2. **MonitoringStreamlitApp**: Main Streamlit application with multiple tabs
3. **Real-time Communication**: Queue-based communication with the monitoring agent process

### Data Flow
```
User Input → Streamlit Interface → Agent Process → MCP Gateway → AWS Services
                ↓                      ↓              ↓
         Real-time Display ← Output Queue ← Agent Response
```

## Configuration

The app uses the same `config.yaml` as the monitoring agent:
- Agent model configuration
- Gateway settings
- Memory configuration
- AWS service settings

## Troubleshooting

### Agent Won't Start
- Check that `monitoring_agent.py` is in the same directory
- Verify all dependencies are installed
- Check AWS credentials and permissions
- Review the terminal output for error messages

### No Agent Response
- Ensure the agent process is running (check status indicator)
- Verify gateway connectivity
- Check network connectivity to AWS services
- Review agent logs in the terminal output

### Streamlit Issues
- Clear browser cache and refresh
- Restart the Streamlit application
- Check for port conflicts (default: 8501)

## Key Features Demonstrated

### Traditional Pain Points
- ⏱️ 2-6 hours per incident resolution
- 🔄 Manual, repetitive processes
- 📊 Complex dashboard navigation
- 📋 Time-intensive analysis
- 📝 Manual documentation

### AgentCore Benefits
- ⚡ 5-15 minutes resolution time
- 🤖 AI-powered automation
- 🧠 Learning from past incidents
- 🔍 Intelligent root cause analysis
- 📊 Automated insights and recommendations

## Development

To modify the application:
1. Edit `streamlit_monitoring_app.py` for UI changes
2. Modify `monitoring_agent.py` for agent logic changes
3. Update `config.yaml` for configuration changes
4. Test with `streamlit run streamlit_monitoring_app.py --server.runOnSave true` for auto-reload

## Notes

- The application runs the actual monitoring agent process, not a simulation
- Real AWS services are accessed through the agent
- Session IDs are automatically generated for tracking
- Agent memory and learning capabilities are preserved across interactions
- Terminal output is displayed in real-time for transparency

## Demo Script

For presentations, follow this flow:
1. **Pain Points** → Show traditional challenges (Tab 1)
2. **Workflow** → Demonstrate time-intensive process (Tab 2)  
3. **Solution** → Explain AgentCore benefits (Tab 3)
4. **Live Demo** → Start agent and demonstrate capabilities (Tab 4)
5. **Scenarios** → Use sidebar scenarios to show different use cases