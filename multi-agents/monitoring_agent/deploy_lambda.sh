#!/bin/bash

# Deploy Lambda function for AgentCore Gateway monitoring tools
# Usage: ./deploy_lambda.sh [function-name] [region]

set -e

# Set AWS CLI command
AWS_CLI=/usr/local/bin/aws

FUNCTION_NAME="${1:-monitoring-agent-lambda}"
REGION="${2:-us-east-1}"
ROLE_NAME="MonitoringLambdaRole"

echo "🚀 Deploying Lambda function: $FUNCTION_NAME in region: $REGION"

# Create temporary deployment directory
DEPLOY_DIR=$(mktemp -d)
echo "📦 Creating deployment package in: $DEPLOY_DIR"

# Copy Lambda function code
cp lambda_function.py "$DEPLOY_DIR/"

# Create requirements.txt
cat > "$DEPLOY_DIR/requirements.txt" << EOF
boto3>=1.26.0
EOF

# Install dependencies
echo "📥 Installing dependencies..."
cd "$DEPLOY_DIR"
pip install -r requirements.txt -t .

# Create deployment zip
echo "📦 Creating deployment package..."
zip -r lambda-deployment.zip . -x "*.pyc" "*/__pycache__/*"

# Get current AWS account ID
ACCOUNT_ID=$("$AWS_CLI" sts get-caller-identity --query Account --output text)
echo "🔐 Using AWS Account ID: $ACCOUNT_ID"

# Create IAM role if it doesn't exist
echo "🔐 Setting up IAM role: $ROLE_NAME"

# Trust policy for Lambda
cat > trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create role
if "$AWS_CLI" iam get-role --role-name "$ROLE_NAME" --region "$REGION" 2>/dev/null; then
    echo "✅ IAM role $ROLE_NAME already exists"
else
    echo "🔐 Creating IAM role: $ROLE_NAME"
    "$AWS_CLI" iam create-role \
        --role-name "$ROLE_NAME" \
        --assume-role-policy-document file://trust-policy.json \
        --region "$REGION"
    
    # Wait for role to be created
    sleep 10
fi

# Attach policies
echo "🔐 Attaching policies to IAM role..."
"$AWS_CLI" iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole \
    --region "$REGION"

"$AWS_CLI" iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess \
    --region "$REGION"

"$AWS_CLI" iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsReadOnlyAccess \
    --region "$REGION"

# Create custom policy for cross-account access
cat > cross-account-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:FilterLogEvents",
                "logs:GetLogEvents",
                "cloudwatch:DescribeAlarms",
                "cloudwatch:ListDashboards",
                "cloudwatch:GetDashboard",
                "cloudwatch:DescribeAlarmsForMetric",
                "cloudwatch:GetMetricStatistics"
            ],
            "Resource": "*"
        }
    ]
}
EOF

# Check if custom policy exists and create/update it
POLICY_ARN="arn:aws:iam::$ACCOUNT_ID:policy/MonitoringLambdaCrossAccountPolicy"
if "$AWS_CLI" iam get-policy --policy-arn "$POLICY_ARN" 2>/dev/null; then
    echo "🔐 Updating existing policy: MonitoringLambdaCrossAccountPolicy"
    # Create new version
    "$AWS_CLI" iam create-policy-version \
        --policy-arn "$POLICY_ARN" \
        --policy-document file://cross-account-policy.json \
        --set-as-default
else
    echo "🔐 Creating custom policy: MonitoringLambdaCrossAccountPolicy"
    "$AWS_CLI" iam create-policy \
        --policy-name MonitoringLambdaCrossAccountPolicy \
        --policy-document file://cross-account-policy.json \
        --description "Policy for monitoring Lambda to access CloudWatch across accounts"
fi

# Attach custom policy
"$AWS_CLI" iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "$POLICY_ARN" \
    --region "$REGION"

ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$ROLE_NAME"

# Create or update Lambda function
if "$AWS_CLI" lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" 2>/dev/null; then
    echo "🔄 Updating existing Lambda function: $FUNCTION_NAME"
    "$AWS_CLI" lambda update-function-code \
        --function-name "$FUNCTION_NAME" \
        --zip-file fileb://lambda-deployment.zip \
        --region "$REGION"
    
    "$AWS_CLI" lambda update-function-configuration \
        --function-name "$FUNCTION_NAME" \
        --timeout 300 \
        --memory-size 512 \
        --region "$REGION"
else
    echo "🆕 Creating new Lambda function: $FUNCTION_NAME"
    "$AWS_CLI" lambda create-function \
        --function-name "$FUNCTION_NAME" \
        --runtime python3.9 \
        --role "$ROLE_ARN" \
        --handler lambda_function.lambda_handler \
        --zip-file fileb://lambda-deployment.zip \
        --timeout 300 \
        --memory-size 512 \
        --description "Monitoring agent Lambda for AgentCore Gateway" \
        --region "$REGION"
fi

# Add permission for AgentCore Gateway to invoke the function
echo "🔐 Adding invoke permissions for AgentCore Gateway..."
"$AWS_CLI" lambda add-permission \
    --function-name "$FUNCTION_NAME" \
    --statement-id agentcore-gateway-invoke \
    --action lambda:InvokeFunction \
    --principal bedrock-agentcore.amazonaws.com \
    --region "$REGION" 2>/dev/null || echo "⚠️  Permission may already exist"

# Get function ARN
FUNCTION_ARN=$("$AWS_CLI" lambda get-function \
    --function-name "$FUNCTION_NAME" \
    --region "$REGION" \
    --query 'Configuration.FunctionArn' \
    --output text)

echo "✅ Lambda function deployed successfully!"
echo "📋 Function ARN: $FUNCTION_ARN"
echo "🔧 Function Name: $FUNCTION_NAME"
echo "🌍 Region: $REGION"
echo ""
echo "📝 Next steps:"
echo "1. Update your config.yaml with the function name: $FUNCTION_NAME"
echo "2. Make sure your AgentCore Gateway IAM role has permission to invoke Lambda functions"
echo "3. Run your monitoring agent to test the Lambda integration"

# Cleanup
cd - > /dev/null
rm -rf "$DEPLOY_DIR"
echo "🧹 Cleaned up temporary files"