# This file contain utility functions that are used across the mutli agent
# solution
import re
import os
import json
import yaml
import time
import boto3
import zipfile
import logging
from io import BytesIO
from constants import *
from pathlib import Path
from typing import Union, Dict, Optional
from bedrock_agentcore_starter_toolkit.operations.gateway import GatewayClient

# set a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

PYTHON_TIMEOUT: int = 180
PYTHON_RUNTIME: str = "python3.12"

# Initialize S3 client
s3_client = boto3.client('s3')
# Initialize the bedrock runtime client. This is used to 
# query search results from the FMC and Meraki KBs
bedrock_agent_runtime_client = boto3.client('bedrock-agent-runtime') 

def load_config(config_file: Union[Path, str]) -> Optional[Dict]:
    """
    Load configuration from a local file.

    :param config_file: Path to the local file
    :return: Dictionary with the loaded configuration
    """
    try:
        config_data: Optional[Dict] = None
        logger.info(f"Loading config from local file system: {config_file}")
        content = Path(config_file).read_text()
        config_data = yaml.safe_load(content)
        logger.info(f"Loaded config from local file system: {config_data}")
    except Exception as e:
        logger.error(f"Error loading config from local file system: {e}")
        config_data = None
    return config_data

def load_and_combine_tools(tools_config, config_file_path=None):
    """Load and combine tools from multiple sources"""
    all_tools = []
    
    config_dir = os.path.dirname(config_file_path) if config_file_path else os.getcwd()
    
    # Load tools from each configured source
    for tool_source in tools_config:
        print(f"Checking for tool source: {tool_source}")
        if tool_source.endswith('.json'):
            # Resolve relative paths relative to config file location
            if not os.path.isabs(tool_source):
                tool_source = os.path.join(config_dir, tool_source)
                print(f"Found tool source: {tool_source}")
            try:
                # Load JSON file
                with open(tool_source, 'r') as file:
                    tools_data = json.load(file)
                    all_tools.extend(tools_data.get('tools', []))
                print(f"Successfully loaded {len(tools_data.get('tools', []))} tools from {tool_source}")
            except FileNotFoundError:
                print(f"Warning: Could not find tools file: {tool_source}")
            except json.JSONDecodeError as e:
                print(f"Warning: Invalid JSON in tools file {tool_source}: {e}")
    
    return all_tools

import boto3
import json
import time
from boto3.session import Session
import botocore
import requests
import os
import time

def setup_cognito_user_pool():
    boto_session = Session()
    region = boto_session.region_name
    
    # Initialize Cognito client
    cognito_client = boto3.client('cognito-idp', region_name=region)
    
    try:
        # Create User Pool
        user_pool_response = cognito_client.create_user_pool(
            PoolName='MCPServerPool',
            Policies={
                'PasswordPolicy': {
                    'MinimumLength': 8
                }
            }
        )
        pool_id = user_pool_response['UserPool']['Id']
        
        # Create App Client
        app_client_response = cognito_client.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName='MCPServerPoolClient',
            GenerateSecret=False,
            ExplicitAuthFlows=[
                'ALLOW_USER_PASSWORD_AUTH',
                'ALLOW_REFRESH_TOKEN_AUTH'
            ]
        )
        client_id = app_client_response['UserPoolClient']['ClientId']
        
        # Create User
        cognito_client.admin_create_user(
            UserPoolId=pool_id,
            Username='testuser',
            TemporaryPassword='Temp123!',
            MessageAction='SUPPRESS'
        )
        
        # Set Permanent Password
        cognito_client.admin_set_user_password(
            UserPoolId=pool_id,
            Username='testuser',
            Password='MyPassword123!',
            Permanent=True
        )
        
        # Authenticate User and get Access Token
        auth_response = cognito_client.initiate_auth(
            ClientId=client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': 'testuser',
                'PASSWORD': 'MyPassword123!'
            }
        )
        bearer_token = auth_response['AuthenticationResult']['AccessToken']
        
        # Output the required values
        print(f"Pool id: {pool_id}")
        print(f"Discovery URL: https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/openid-configuration")
        print(f"Client ID: {client_id}")
        print(f"Bearer Token: {bearer_token}")
        
        # Return values if needed for further processing
        return {
            'pool_id': pool_id,
            'client_id': client_id,
            'bearer_token': bearer_token,
            'discovery_url':f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/openid-configuration"
        }
        
    except Exception as e:
        print(f"Error: {e}")
        return None

def get_or_create_user_pool(cognito, USER_POOL_NAME):
    response = cognito.list_user_pools(MaxResults=60)
    for pool in response["UserPools"]:
        if pool["Name"] == USER_POOL_NAME:
            user_pool_id = pool["Id"]
            response = cognito.describe_user_pool(
                UserPoolId=user_pool_id
            )
        
            # Get the domain from user pool description
            user_pool = response.get('UserPool', {})
            domain = user_pool.get('Domain')
        
            if domain:
                region = user_pool_id.split('_')[0] if '_' in user_pool_id else REGION
                domain_url = f"https://{domain}.auth.{region}.amazoncognito.com"
                print(f"Found domain for user pool {user_pool_id}: {domain} ({domain_url})")
            else:
                print(f"No domains found for user pool {user_pool_id}")
            return pool["Id"]
    print('Creating new user pool')
    created = cognito.create_user_pool(PoolName=USER_POOL_NAME)
    user_pool_id = created["UserPool"]["Id"]
    user_pool_id_without_underscore_lc = user_pool_id.replace("_", "").lower()
    cognito.create_user_pool_domain(
        Domain=user_pool_id_without_underscore_lc,
        UserPoolId=user_pool_id
    )
    print("Domain created as well")
    return created["UserPool"]["Id"]

def get_or_create_resource_server(cognito, user_pool_id, RESOURCE_SERVER_ID, RESOURCE_SERVER_NAME, SCOPES):
    try:
        existing = cognito.describe_resource_server(
            UserPoolId=user_pool_id,
            Identifier=RESOURCE_SERVER_ID
        )
        return RESOURCE_SERVER_ID
    except cognito.exceptions.ResourceNotFoundException:
        print('creating new resource server')
        cognito.create_resource_server(
            UserPoolId=user_pool_id,
            Identifier=RESOURCE_SERVER_ID,
            Name=RESOURCE_SERVER_NAME,
            Scopes=SCOPES
        )
        return RESOURCE_SERVER_ID

def get_or_create_m2m_client(cognito, user_pool_id, CLIENT_NAME, RESOURCE_SERVER_ID):
    response = cognito.list_user_pool_clients(UserPoolId=user_pool_id, MaxResults=60)
    for client in response["UserPoolClients"]:
        if client["ClientName"] == CLIENT_NAME:
            describe = cognito.describe_user_pool_client(UserPoolId=user_pool_id, ClientId=client["ClientId"])
            return client["ClientId"], describe["UserPoolClient"]["ClientSecret"]
    print('creating new m2m client')
    created = cognito.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName=CLIENT_NAME,
        GenerateSecret=True,
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthScopes=[f"{RESOURCE_SERVER_ID}/gateway:read", f"{RESOURCE_SERVER_ID}/gateway:write"],
        AllowedOAuthFlowsUserPoolClient=True,
        SupportedIdentityProviders=["COGNITO"],
        ExplicitAuthFlows=["ALLOW_REFRESH_TOKEN_AUTH"]
    )
    return created["UserPoolClient"]["ClientId"], created["UserPoolClient"]["ClientSecret"]

def get_token(user_pool_id: str, client_id: str, client_secret: str, scope_string: str, REGION: str) -> dict:
    """
    This is the function that is used to get the token for the cognito IdP in case
    the user wants to refresh the token that is used to connect to the gateway
    for inbound authentication
    """
    try:
        user_pool_id_without_underscore = user_pool_id.replace("_", "")
        url = f"https://{user_pool_id_without_underscore}.auth.{REGION}.amazoncognito.com/oauth2/token"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope_string,

        }
        print(client_id)
        print(client_secret)
        # we will get the token as the egress auth
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as err:
        return {"error": str(err)}
    
def create_agentcore_role(agent_name):
    iam_client = boto3.client('iam')
    agentcore_role_name = f'agentcore-{agent_name}-role'
    boto_session = Session()
    region = boto_session.region_name
    account_id = boto3.client("sts").get_caller_identity()["Account"]
    role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BedrockPermissions",
                "Effect": "Allow",
                "Action": [
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:DescribeLogStreams",
                    "logs:CreateLogGroup"
                ],
                "Resource": [
                    f"arn:aws:logs:{region}:{account_id}:log-group:/aws/bedrock-agentcore/runtimes/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:DescribeLogGroups"
                ],
                "Resource": [
                    f"arn:aws:logs:{region}:{account_id}:log-group:*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": [
                    f"arn:aws:logs:{region}:{account_id}:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*"
                ]
            },
            {
            "Effect": "Allow",
            "Action": [
                "xray:PutTraceSegments",
                "xray:PutTelemetryRecords",
                "xray:GetSamplingRules",
                "xray:GetSamplingTargets"
                ],
             "Resource": [ "*" ]
             },
             {
                "Effect": "Allow",
                "Resource": "*",
                "Action": "cloudwatch:PutMetricData",
                "Condition": {
                    "StringEquals": {
                        "cloudwatch:namespace": "bedrock-agentcore"
                    }
                }
            },
             {
                "Effect": "Allow",
                "Resource": "*",
                "Action": "s3:GetObject",
            },
             {
                "Effect": "Allow",
                "Resource": "*",
                "Action": "lambda:InvokeFunction"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:*",
                    "iam:PassRole"
                ],
                "Resource": "*"
            },
            {
                "Sid": "GetAgentAccessToken",
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:GetWorkloadAccessToken",
                    "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                    "bedrock-agentcore:GetWorkloadAccessTokenForUserId"
                ],
                "Resource": [
                  f"arn:aws:bedrock-agentcore:{region}:{account_id}:workload-identity-directory/default",
                  f"arn:aws:bedrock-agentcore:{region}:{account_id}:workload-identity-directory/default/workload-identity/{agent_name}-*"
                ]
            }
        ]
    }
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeRolePolicy",
                "Effect": "Allow",
                "Principal": {
                    "Service": "bedrock-agentcore.amazonaws.com"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": f"{account_id}"
                    },
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:bedrock-agentcore:{region}:{account_id}:*"
                    }
                }
            }
        ]
    }

    assume_role_policy_document_json = json.dumps(
        assume_role_policy_document
    )
    role_policy_document = json.dumps(role_policy)
    # Create IAM Role for the Lambda function
    try:
        agentcore_iam_role = iam_client.create_role(
            RoleName=agentcore_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document_json
        )

        # Pause to make sure role is created
        time.sleep(10)
    except iam_client.exceptions.EntityAlreadyExistsException:
        print("Role already exists -- deleting and creating it again")
        policies = iam_client.list_role_policies(
            RoleName=agentcore_role_name,
            MaxItems=100
        )
        print("policies:", policies)
        for policy_name in policies['PolicyNames']:
            iam_client.delete_role_policy(
                RoleName=agentcore_role_name,
                PolicyName=policy_name
            )
        print(f"deleting {agentcore_role_name}")
        iam_client.delete_role(
            RoleName=agentcore_role_name
        )
        print(f"recreating {agentcore_role_name}")
        agentcore_iam_role = iam_client.create_role(
            RoleName=agentcore_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document_json
        )

    # Attach the AWSLambdaBasicExecutionRole policy
    print(f"attaching role policy {agentcore_role_name}")
    try:
        iam_client.put_role_policy(
            PolicyDocument=role_policy_document,
            PolicyName="AgentCorePolicy",
            RoleName=agentcore_role_name
        )
    except Exception as e:
        print(e)

    return agentcore_iam_role

def create_agentcore_gateway_role(gateway_name, role_policy: Dict):
    """
    This is the function that provides access to bedrock agent core
    This means that each of the agent will have access to bedrock, bedrock agentcore, 
    getting the credentials from an OAuth provider, secrets, etc
    
    This function also takes in the role policy that is needed to configure the 
    permissions that the IAM role will have that is accessing the gateway
    """
    iam_client = boto3.client('iam')
    agentcore_gateway_role_name = f'agentcore-{gateway_name}-role'
    boto_session = Session()
    region = boto_session.region_name
    account_id = boto3.client("sts").get_caller_identity()["Account"]
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeRolePolicy",
                "Effect": "Allow",
                "Principal": {
                    "Service": "bedrock-agentcore.amazonaws.com"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": f"{account_id}"
                    },
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:bedrock-agentcore:{region}:{account_id}:*"
                    }
                }
            }
        ]
    }

    assume_role_policy_document_json = json.dumps(
        assume_role_policy_document
    )

    role_policy_document = json.dumps(role_policy)
    # Create IAM Role for the Lambda function
    try:
        agentcore_iam_role = iam_client.create_role(
            RoleName=agentcore_gateway_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document_json
        )

        # Pause to make sure role is created
        time.sleep(10)
    except iam_client.exceptions.EntityAlreadyExistsException:
        print("Role already exists -- deleting and creating it again")
        policies = iam_client.list_role_policies(
            RoleName=agentcore_gateway_role_name,
            MaxItems=100
        )
        print("policies:", policies)
        for policy_name in policies['PolicyNames']:
            iam_client.delete_role_policy(
                RoleName=agentcore_gateway_role_name,
                PolicyName=policy_name
            )
        print(f"deleting {agentcore_gateway_role_name}")
        iam_client.delete_role(
            RoleName=agentcore_gateway_role_name
        )
        print(f"recreating {agentcore_gateway_role_name}")
        agentcore_iam_role = iam_client.create_role(
            RoleName=agentcore_gateway_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document_json
        )

    # Attach the AWSLambdaBasicExecutionRole policy
    print(f"attaching role policy {agentcore_gateway_role_name}")
    try:
        iam_client.put_role_policy(
            PolicyDocument=role_policy_document,
            PolicyName="AgentCorePolicy",
            RoleName=agentcore_gateway_role_name
        )
    except Exception as e:
        print(e)

    return agentcore_iam_role


def create_agentcore_gateway_role_s3_smithy(gateway_name):
    iam_client = boto3.client('iam')
    agentcore_gateway_role_name = f'agentcore-{gateway_name}-role'
    boto_session = Session()
    region = boto_session.region_name
    account_id = boto3.client("sts").get_caller_identity()["Account"]
    role_policy = {
        "Version": "2012-10-17",
        "Statement": [{
                "Sid": "VisualEditor0",
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:*",
                    "bedrock:*",
                    "agent-credential-provider:*",
                    "iam:PassRole",
                    "secretsmanager:GetSecretValue",
                    "lambda:InvokeFunction",
                    "s3:*",
                ],
                "Resource": "*"
            }
        ]
    }

    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeRolePolicy",
                "Effect": "Allow",
                "Principal": {
                    "Service": "bedrock-agentcore.amazonaws.com"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": f"{account_id}"
                    },
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:bedrock-agentcore:{region}:{account_id}:*"
                    }
                }
            }
        ]
    }

    assume_role_policy_document_json = json.dumps(
        assume_role_policy_document
    )

    role_policy_document = json.dumps(role_policy)
    # Create IAM Role for the Lambda function
    try:
        agentcore_iam_role = iam_client.create_role(
            RoleName=agentcore_gateway_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document_json
        )

        # Pause to make sure role is created
        time.sleep(10)
    except iam_client.exceptions.EntityAlreadyExistsException:
        print("Role already exists -- deleting and creating it again")
        policies = iam_client.list_role_policies(
            RoleName=agentcore_gateway_role_name,
            MaxItems=100
        )
        print("policies:", policies)
        for policy_name in policies['PolicyNames']:
            iam_client.delete_role_policy(
                RoleName=agentcore_gateway_role_name,
                PolicyName=policy_name
            )
        print(f"deleting {agentcore_gateway_role_name}")
        iam_client.delete_role(
            RoleName=agentcore_gateway_role_name
        )
        print(f"recreating {agentcore_gateway_role_name}")
        agentcore_iam_role = iam_client.create_role(
            RoleName=agentcore_gateway_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document_json
        )

    # Attach the AWSLambdaBasicExecutionRole policy
    print(f"attaching role policy {agentcore_gateway_role_name}")
    try:
        iam_client.put_role_policy(
            PolicyDocument=role_policy_document,
            PolicyName="AgentCorePolicy",
            RoleName=agentcore_gateway_role_name
        )
    except Exception as e:
        print(e)

    return agentcore_iam_role

def create_gateway_lambda(lambda_function_code_path) -> dict[str, int]:
    boto_session = Session()
    region = boto_session.region_name

    return_resp = {"lambda_function_arn": "Pending", "exit_code": 1}
    
    # Initialize Cognito client
    lambda_client = boto3.client('lambda', region_name=region)
    iam_client = boto3.client('iam', region_name=region)

    role_name = 'gateway_lambda_iamrole'
    role_arn = ''
    lambda_function_name = 'gateway_lambda'

    print("Reading code from zip file")
    with open(lambda_function_code_path, 'rb') as f:
        lambda_function_code = f.read()

    try:
        print("Creating IAM role for lambda function")

        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
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
            }),
            Description="IAM role to be assumed by lambda function"
        )

        role_arn = response['Role']['Arn']

        print("Attaching policy to the IAM role")

        response = iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
        )

        print(f"Role '{role_name}' created successfully: {role_arn}")
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == "EntityAlreadyExists":
            response = iam_client.get_role(RoleName=role_name)
            role_arn = response['Role']['Arn']
            print(f"IAM role {role_name} already exists. Using the same ARN {role_arn}")
        else:
            error_message = error.response['Error']['Code'] + "-" + error.response['Error']['Message']
            print(f"Error creating role: {error_message}")
            return_resp['lambda_function_arn'] = error_message

    if role_arn != "":
        print("Creating lambda function")
        # Create lambda function    
        try:
            lambda_response = lambda_client.create_function(
                FunctionName=lambda_function_name,
                Role=role_arn,
                Runtime='python3.12',
                Handler='lambda_function_code.lambda_handler',
                Code = {'ZipFile': lambda_function_code},
                Description='Lambda function example for Bedrock AgentCore Gateway',
                PackageType='Zip'
            )

            return_resp['lambda_function_arn'] = lambda_response['FunctionArn']
            return_resp['exit_code'] = 0
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == "ResourceConflictException":
                response = lambda_client.get_function(FunctionName=lambda_function_name)
                lambda_arn = response['Configuration']['FunctionArn']
                print(f"AWS Lambda function {lambda_function_name} already exists. Using the same ARN {lambda_arn}")
                return_resp['lambda_function_arn'] = lambda_arn
            else:
                error_message = error.response['Error']['Code'] + "-" + error.response['Error']['Message']
                print(f"Error creating lambda function: {error_message}")
                return_resp['lambda_function_arn'] = error_message

    return return_resp

def delete_gateway(gateway_client,gatewayId): 
    print("Deleting all targets for gateway", gatewayId)
    list_response = gateway_client.list_gateway_targets(
            gatewayIdentifier = gatewayId,
            maxResults=100
    )
    for item in list_response['items']:
        targetId = item["targetId"]
        print("Deleting target ", targetId)
        gateway_client.delete_gateway_target(
            gatewayIdentifier = gatewayId,
            targetId = targetId
        )
    print("Deleting gateway ", gatewayId)
    gateway_client.delete_gateway(gatewayIdentifier = gatewayId)

def delete_all_gateways(gateway_client):
    try:
        list_response = gateway_client.list_gateways(
            maxResults=100
        )
        for item in list_response['items']:
            gatewayId= item["gatewayId"]
            delete_gateway(gatewayId)
    except Exception as e:
        print(e)

def load_or_create_gateway_credentials(gateway_config):
    """
    Load existing gateway credentials or return None if not found
    
    Args:
        gateway_config (dict): Gateway configuration containing credentials settings
        
    Returns:
        dict or None: Credentials dictionary if found, None otherwise
    """
    credentials_config = gateway_config.get('credentials')
    storage_path = credentials_config.get('storage_path', 'gateway_credentials.json')
    use_existing = credentials_config.get('use_existing', True)
    if use_existing and os.path.exists(storage_path):
        try:
            with open(storage_path, 'r') as f:
                credentials = json.load(f)
            logger.info(f"Loaded existing gateway credentials from {storage_path}")
            return credentials
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.warning(f"Failed to load existing credentials: {e}")
            return None
    return None

def save_gateway_credentials(gateway_config, mcp_url, access_token):
    """
    Save gateway credentials to storage
    
    Args:
        gateway_config (dict): Gateway configuration containing credentials settings
        mcp_url (str): MCP URL
        access_token (str): Access token
    """
    credentials_config = gateway_config.get('credentials', {})
    storage_path = credentials_config.get('storage_path', 'gateway_credentials.json')
    credentials = {
        "mcp_url": mcp_url,
        "access_token": access_token,
        "created_at": time.time()
    }
    with open(storage_path, 'w') as f:
        json.dump(credentials, f, indent=4)
    logger.info(f"Saved gateway credentials to {storage_path}")

def create_gateway_from_config(agent_config, config_data):
    """
    Create a gateway from configuration data
    
    Args:
        agent_config (dict): Agent configuration containing gateway_config
        config_data (dict): Full configuration data (for context)
    
    Returns:
        tuple: (mcp_url, access_token)
    """
    try:
        gateway_config = agent_config.get('gateway_config')
        if not gateway_config:
            raise ValueError("No gateway configuration found in agent config")
        
        # Check for existing credentials first
        existing_credentials = load_or_create_gateway_credentials(gateway_config)
        if existing_credentials:
            return existing_credentials.get('mcp_url'), existing_credentials.get('access_token')
        
        # Extract basic gateway information
        gateway_name = gateway_config.get('name', 'DefaultGateway')
        gateway_desc = gateway_config.get('description', 'Default Gateway Description')
        protocol_type = gateway_config.get('protocol_type', 'MCP')
        
        # Initialize gateway client
        client = GatewayClient(region_name=REGION_NAME)
        
        # Handle inbound authentication
        inbound_auth = gateway_config.get('inbound_auth')
        auth_type = inbound_auth.get('type', 'cognito')
        
        if auth_type == 'cognito':
            # Setup Cognito authorizer
            cognito_config = inbound_auth.get('cognito')
            cognito_result = client.create_oauth_authorizer_with_cognito(
                gateway_name,
                user_pool_name=cognito_config.get('user_pool_name', f'{gateway_name}-pool'),
                resource_server_id=cognito_config.get('resource_server_id', f'{gateway_name}-id'),
                resource_server_name=cognito_config.get('resource_server_name', f'{gateway_name}-name'),
                client_name=cognito_config.get('client_name', f'{gateway_name}-client'),
                scopes=cognito_config.get('scopes', [
                    {"name": "gateway:read", "description": "Read access"},
                    {"name": "gateway:write", "description": "Write access"}
                ])
            )
            authorizer_config = cognito_result["authorizer_config"]
        else:
            raise ValueError(f"Unsupported inbound auth type: {auth_type}")
        # Create gateway
        gateway = client.create_mcp_gateway(
            name=gateway_name,
            description=gateway_desc,
            protocol_type=protocol_type,
            authorizer_config=authorizer_config
        )
        # Process targets
        targets = gateway_config.get('targets', [])
        for target_config in targets:
            target_name = target_config.get('name', 'DefaultTarget')
            target_type = target_config.get('type', 'lambda')
            target_desc = target_config.get('description', 'Default Target')
            
            if target_type == 'lambda':
                # Handle Lambda target
                lambda_config = target_config.get('lambda', {})
                lambda_arn = lambda_config.get('arn', '')
                
                # Replace ACCOUNT_ID placeholder
                if 'ACCOUNT_ID' in lambda_arn:
                    account_id = boto3.client("sts").get_caller_identity()["Account"]
                    lambda_arn = lambda_arn.replace('ACCOUNT_ID', account_id)
                
                # Load tools configuration
                tools_config_paths = lambda_config.get('tools_config', [])
                tools = load_and_combine_tools(tools_config_paths)
                # Create lambda target
                lambda_target = client.create_mcp_gateway_target(
                    gateway=gateway,
                    target_type="lambda",
                    target_name=target_name,
                    target_description=target_desc,
                    lambda_arn=lambda_arn,
                    tools=tools
                )
            else:
                logger.warning(f"Unsupported target type: {target_type}")
        # Get access token and MCP URL
        if auth_type == 'cognito':
            access_token = client.get_access_token_for_cognito(cognito_result["client_info"])
        else:
            access_token = None
        mcp_url = gateway.get_mcp_url()
        # Save credentials
        save_gateway_credentials(gateway_config, mcp_url, access_token)
        return mcp_url, access_token
    except Exception as e:
        logger.error(f"Error creating gateway: {e}")
        raise

def create_gateway(lambda_arn, tool_config, gateway_name, gateway_desc):
    """
    Legacy function for backward compatibility
    Create a gateway with the provided configuration
    
    Args:
        lambda_arn (str): Lambda ARN
        tool_config (list): Tool configuration
        gateway_name (str): Gateway name
        gateway_desc (str): Gateway description
    
    Returns:
        tuple: (mcp_url, access_token)
    """
    client = GatewayClient(region_name=REGION_NAME)
    
    # Setup authorizer - this is for the inbound auth
    cognito_result = client.create_oauth_authorizer_with_cognito(gateway_name)
    # Setup gateway configuration
    lambda_config = {
        "arn": lambda_arn,
        "tools": tool_config
    }
    # Create gateway
    gateway = client.create_mcp_gateway(
        name=gateway_name,
        authorizer_config=cognito_result["authorizer_config"]
    )
    # Create lambda target
    lambda_target = client.create_mcp_gateway_target(
        gateway=gateway,
        target_type="lambda"
    )
    # Get access token and MCP URL
    access_token = client.get_access_token_for_cognito(cognito_result["client_info"])
    mcp_url = gateway.get_mcp_url()
    return mcp_url, access_token

# This is the comprehensive callback function that is used as a callback for all
# agents that are developed using the Strands SDK

# Callback handlers are a powerful feature of the Strands Agents SDK that allow you to intercept and process events as 
# they happen during agent execution. This enables real-time monitoring, custom output formatting, and integration 
# with external systems.
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
        
        if tool_use_id not in TOOL_USE_IDS:
            tool_name = tool.get('name', 'unknown_tool')
            tool_input = tool.get('input', {})
            
            logger.info(f"\n🔧 USING TOOL: {tool_name}")
            if "input" in tool:
                logger.info(f"📥 TOOL INPUT: {tool_input}")
            TOOL_USE_IDS.append(tool_use_id)
    
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