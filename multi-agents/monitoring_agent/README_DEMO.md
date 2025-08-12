# AgentCore AWS Monitoring Demo

A comprehensive Streamlit application showcasing AgentCore's intelligent AWS troubleshooting and monitoring capabilities.

## 🎯 Demo Overview

This interactive demo demonstrates how AgentCore transforms traditional AWS troubleshooting from hours of manual work into minutes of intelligent automation. Experience the complete workflow from pain point identification to automated resolution.

## 🚀 Quick Start

### Option 1: Automated Launcher (Recommended)
```bash
# Navigate to the monitoring agent directory
cd multi-agents/monitoring_agent

# Run the automated launcher
python run_demo.py
```

### Option 2: Manual Launch
```bash
# Install requirements
pip install -r requirements_streamlit.txt

# Launch Streamlit
streamlit run enhanced_streamlit_app.py
```

## 📋 Prerequisites

- Python 3.11+
- Required packages (automatically installed by launcher):
  - streamlit>=1.28.0
  - plotly>=5.17.0
  - pandas>=2.0.0
  - numpy>=1.24.0
  - boto3>=1.29.0
  - pyyaml>=6.0

## 🌟 Demo Features

### 🏠 Home Page - Pain Point Analysis
- **Current Challenges**: Traditional AWS troubleshooting workflow pain points
- **AgentCore Solution**: Intelligent automation benefits and time savings
- **Business Impact**: Quantified efficiency improvements (90% time reduction, 5x faster resolution)
- **Interactive Metrics**: Live demonstration statistics

### 🔄 Workflow Transformation
- **Before/After Comparison**: Traditional vs AgentCore workflow visualization
- **Time Analysis**: Detailed breakdown of time savings (180 minutes → 9 minutes)
- **AgentCore Primitives**: Deep dive into Gateway, Identity, Toolbox, Runtime, Observability
- **Code Examples**: Real implementation snippets for each primitive

### 🤖 Agent Chat Interface
- **Real Agent Integration**: Connect to actual AgentCore monitoring agents via ARN
- **Intelligent Responses**: Contextual analysis of AWS logs, metrics, and performance
- **Streaming Support**: Real-time response generation with typing indicators
- **Demo Mode**: Sophisticated mock responses for demonstration purposes
- **Sample Queries**: Pre-configured examples for optimal demo experience

### 📊 Monitoring Dashboard  
- **Live Metrics**: Real-time agent performance and system health
- **Interactive Charts**: Response time trends, success rates, issue resolution
- **System Status**: Agent health monitoring and resource utilization
- **Activity Logs**: Recent actions and automated remediation steps

## 🎭 Demo Modes

### Live Mode
- Connects to real AgentCore agents using configured ARNs
- Executes actual AWS API calls via MCP gateway
- Streams real responses from monitoring agent logic
- Requires proper AWS credentials and agent configuration

### Demo Mode (Default)
- Uses sophisticated mock responses based on query analysis
- Simulates realistic AWS troubleshooting scenarios
- Perfect for presentations and demonstrations
- No AWS credentials required

## 🔧 Configuration

### Agent Configuration
The demo automatically detects agents from:

1. **config.yaml**: Main configuration file
   ```yaml
   agent_information:
     monitoring_agent_model_info:
       gateway_config:
         agent_arn: "arn:aws:bedrock-agentcore:us-east-1:123456789012:agent/agent-id"
   ```

2. **.bedrock_agentcore.yaml**: AgentCore runtime configuration
   ```yaml
   agents:
     monitoring_agent:
       bedrock_agentcore:
         agent_arn: "arn:aws:bedrock-agentcore:us-east-1:123456789012:agent/agent-id"
   ```

### AWS Credentials
For live mode, ensure AWS credentials are configured:
```bash
aws configure
# OR
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
export AWS_DEFAULT_REGION=us-east-1
```

## 🎪 Demo Script & Talking Points

### Introduction (2 minutes)
> "Today I'll show you how AgentCore transforms AWS troubleshooting from a painful, time-consuming process into intelligent automation. Let's start by looking at the current pain points everyone faces."

**Navigate to Home Page**
- Highlight the 90% time reduction and 5x faster resolution
- Point out business impact: $67,000 potential savings per incident

### Problem Statement (3 minutes)
> "Let me show you exactly what changes with AgentCore's workflow transformation."

**Navigate to Workflow Page**
- Walk through traditional workflow: 180 minutes of manual work
- Compare with AgentCore workflow: 9 minutes of intelligent automation
- Emphasize the AgentCore primitives working together

### Live Demonstration (10 minutes)
> "Now let's see this in action. I'll demonstrate real troubleshooting scenarios."

**Navigate to Agent Chat**
- Start with: "Analyze CloudWatch logs for errors in the last 24 hours"
- Show the comprehensive analysis with:
  - Error pattern identification
  - Root cause analysis
  - Automated Jira ticket creation
  - Remediation recommendations
- Try: "Show me performance metrics and identify any anomalies"
- Demonstrate correlation analysis and predictive insights

### System Monitoring (5 minutes)
> "Behind the scenes, AgentCore provides comprehensive monitoring of the entire process."

**Navigate to Monitoring Page**
- Show real-time metrics and performance trends
- Highlight system health monitoring
- Demonstrate the business intelligence layer

## 💡 Best Demo Queries

### Error Analysis
```
"Analyze CloudWatch logs for errors in the last 24 hours and correlate with performance metrics"
"What's causing the spike in database connection timeouts?"
"Find patterns in recent 5xx errors and suggest remediation"
```

### Performance Investigation
```
"Why is our application response time 3x slower than baseline?"
"Identify performance bottlenecks in the user authentication service"
"Show me memory usage trends and predict capacity needs"
```

### Correlation Analysis
```
"Correlate the recent deployment with performance degradation"
"What infrastructure changes coincide with error rate increases?"
"Find similar incidents from the past and their resolutions"
```

### Documentation & Ticketing
```
"Create a detailed Jira ticket for the current database issues"
"Generate an executive summary of today's performance problems"
"Document the root cause analysis for this incident"
```

## 🎯 Key Demo Messages

1. **Speed**: "Minutes instead of hours for complete analysis"
2. **Intelligence**: "AI identifies patterns humans would miss"
3. **Comprehensiveness**: "Full correlation across all AWS services"
4. **Automation**: "From detection to documentation, fully automated"
5. **Business Value**: "Quantifiable ROI and improved customer experience"

## 🔍 Technical Implementation

### Agent Invocation
The demo uses the actual monitoring agent logic from `monitoring_agent.py`:

```python
# Real agent invocation
response_text = ask_agent(message, session_id)

# Falls back to sophisticated demo responses
response = self._create_enhanced_demo_response(message)
```

### MCP Gateway Integration
Connects to AgentCore Gateway via MCP protocol:
```python
mcp_client = MCPClient(create_streamable_http_transport)
gateway_tools = mcp_client.list_tools_sync()
```

### Session Management
Maintains OTEL-compatible session tracking:
```python
ctx = baggage.set_baggage("session_id", session_id)
token = context.attach(ctx)
```

## 📊 Demo Analytics

The application tracks:
- User interaction patterns
- Query types and frequency
- Response quality metrics
- Session duration and engagement
- Feature usage statistics

## 🛠️ Customization

### Adding New Demo Scenarios
Extend `_create_enhanced_demo_response()` with new patterns:

```python
def _generate_custom_scenario_response(self, message: str) -> str:
    return """🔍 **Custom Scenario Analysis**
    
    Your custom analysis here...
    """
```

### Styling Customization
Modify the CSS in the `st.markdown()` sections for custom branding:

```python
st.markdown("""
<style>
    .main-header {
        color: #YOUR_BRAND_COLOR;
    }
</style>
""", unsafe_allow_html=True)
```

## 🚨 Troubleshooting

### Common Issues

**Port Already in Use**
```bash
streamlit run enhanced_streamlit_app.py --server.port=8502
```

**Missing Dependencies**
```bash
pip install -r requirements_streamlit.txt
```

**Agent Connection Failed**
- Check AWS credentials
- Verify agent ARN in configuration
- Ensure MCP gateway is accessible
- Fall back to demo mode for presentations

**Configuration Not Found**
- Ensure `config.yaml` exists
- Check file paths in `constants.py`
- Verify YAML syntax

## 📞 Support

For issues with the demo:
1. Check the troubleshooting section above
2. Verify all prerequisites are installed
3. Check the application logs in the terminal
4. Use demo mode for presentations if live mode fails

## 🎉 Demo Success Tips

1. **Pre-flight Check**: Always test the demo beforehand
2. **Backup Plan**: Keep demo mode available if live connections fail
3. **Narrative Flow**: Follow the suggested demo script progression
4. **Interactive Elements**: Encourage audience questions and custom queries
5. **Business Focus**: Emphasize ROI and business value throughout

---

*This demo showcases AgentCore's real-world capabilities for intelligent AWS monitoring and troubleshooting automation.*