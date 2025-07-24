"""
Gateway integration module for Keycloak authentication
Replaces Cognito authentication in the monitoring agent with Keycloak
"""

import os
import json
import time
import boto3
import logging
from typing import Dict, Optional, Tuple
from setup_keycloack_auth import setup_keycloak_auth, refresh_keycloak_token

logger = logging.getLogger(__name__)

def setup_keycloak_gateway(gateway_config_info: Dict, gateway_name: str, role_arn: str, region_name: str) -> Tuple[str, str, str]:
    """
    Setup AgentCore Gateway with Keycloak authentication instead of Cognito
    
    Args:
        gateway_config_info: Gateway configuration dictionary
        gateway_name: Name for the gateway
        role_arn: IAM role ARN for the gateway
        region_name: AWS region name
        
    Returns:
        Tuple of (gateway_id, mcp_url, access_token)
    """
    try:
        logger.info("🔧 Setting up AgentCore Gateway with Keycloak authentication...")
        
        # Step 1: Setup Keycloak authentication
        print("Setting up Keycloak...")
        inbound_auth_config: Dict = gateway_config_info.get('inbound_auth', {})
        keycloak_config: Dict = inbound_auth_config.get('keycloak', {})
        
        if not keycloak_config:
            raise ValueError("Keycloak configuration not found in gateway_config_info['inbound_auth']['keycloak']")
        
        logger.info(f"Going to use the inbound auth mechanism through Keycloak: {keycloak_config}")
        
        # Setup Keycloak authentication
        keycloak_result = setup_keycloak_auth(gateway_config_info)
        
        client_id = keycloak_result['client_id']
        access_token = keycloak_result['access_token']
        discovery_url = keycloak_result['discovery_url']
        auth_config = keycloak_result['auth_config']
        
        print(f"Keycloak setup complete:")
        print(f"- Client ID: {client_id}")
        print(f"- Discovery URL: {discovery_url}")
        print(f"- Access Token: {access_token[:20]}...")
        
        # Step 2: Setup AWS Bedrock AgentCore Gateway
        print("Setting up AWS Bedrock AgentCore Gateway...")
        gateway_client = boto3.client('bedrock-agentcore-control', region_name=region_name)
        
        # Check if gateway already exists
        gateway_id = None
        mcp_url = None
        
        try:
            next_token = None
            found_gateway = False
            
            while not found_gateway:
                if next_token:
                    list_response = gateway_client.list_gateways(nextToken=next_token)
                else:
                    list_response = gateway_client.list_gateways()
                
                for gateway in list_response.get('items', []):
                    if gateway['name'] == gateway_name:
                        gateway_id = gateway['gatewayId']
                        # Get the full gateway details to retrieve URL
                        get_response = gateway_client.get_gateway(gatewayIdentifier=gateway_id)
                        mcp_url = get_response.get('gatewayUrl')
                        print(f"Gateway '{gateway_name}' already exists: {gateway_id}")
                        print(f"Gateway URL: {mcp_url}")
                        found_gateway = True
                        break
                
                # Check if there are more pages
                next_token = list_response.get('nextToken')
                if not next_token:
                    break
                    
        except Exception as e:
            print(f"Error checking existing gateways: {e}")
        
        # Create gateway only if it doesn't exist
        if not gateway_id or not mcp_url:
            try:
                print("Creating new gateway with Keycloak authentication...")
                create_response = gateway_client.create_gateway(
                    name=gateway_name,
                    roleArn=role_arn,
                    protocolType="MCP",  # MCP_PROTOCOL constant
                    authorizerType="CUSTOM_JWT",  # AUTH_TYPE_CUSTOM_JWT constant
                    authorizerConfiguration=auth_config['customJWTAuthorizer'],
                    description='AgentCore Gateway with Keycloak authentication for monitoring tools'
                )
                gateway_id = create_response.get("gatewayId")
                mcp_url = create_response.get("gatewayUrl")
                
                if not mcp_url:
                    print(f"❌ Warning: Gateway URL is None in create response")
                    print(f"Full create response: {create_response}")
                    # Try to get the gateway URL using the gateway ID
                    if gateway_id:
                        try:
                            get_response = gateway_client.get_gateway(gatewayIdentifier=gateway_id)
                            mcp_url = get_response.get('gatewayUrl')
                            print(f"Retrieved gateway URL via get_gateway: {mcp_url}")
                        except Exception as get_error:
                            print(f"Error getting gateway URL: {get_error}")
                
                print(f"Gateway created: {gateway_id}")
                print(f"Gateway URL: {mcp_url}")
                
            except Exception as e:
                if "ConflictException" in str(e) and "already exists" in str(e):
                    print(f"Gateway '{gateway_name}' already exists. Attempting to use existing gateway...")
                    # Handle existing gateway case similar to original code
                    raise e
                else:
                    raise e
        
        if not mcp_url:
            raise ValueError("mcp_url cannot be None - gateway setup failed")
        
        print(f"✅ Keycloak Gateway setup completed successfully!")
        print(f"Gateway ID: {gateway_id}")
        print(f"MCP Server URL: {mcp_url}")
        print(f"Access Token: {access_token[:20]}...")
        
        return gateway_id, mcp_url, access_token
        
    except Exception as e:
        logger.error(f"❌ Error setting up Keycloak gateway: {e}")
        raise

def create_keycloak_gateway_credentials(gateway_id: str, mcp_url: str, access_token: str, 
                                      keycloak_result: Dict, credentials_path: str) -> None:
    """
    Create and save gateway credentials with Keycloak information
    
    Args:
        gateway_id: AWS Gateway ID
        mcp_url: MCP server URL
        access_token: Keycloak access token
        keycloak_result: Complete Keycloak setup result
        credentials_path: Path to save credentials file
    """
    try:
        # Create comprehensive credentials dictionary
        credentials = {
            "gateway_id": gateway_id,
            "mcp_url": mcp_url,
            "access_token": access_token,
            "auth_type": "keycloak",
            "keycloak": {
                "url": keycloak_result['keycloak_url'],
                "realm_name": keycloak_result['realm_name'],
                "client_id": keycloak_result['client_id'],
                "client_secret": keycloak_result['client_secret'],
                "discovery_url": keycloak_result['discovery_url'],
                "scopes": keycloak_result['scopes']
            },
            "created_at": time.time(),
            "updated_at": time.time()
        }
        
        # Write the credentials to a JSON file
        with open(credentials_path, 'w') as cred_file:
            json.dump(credentials, cred_file, indent=4)
        
        print(f"Keycloak gateway credentials saved to {os.path.abspath(credentials_path)}")
        logger.info(f"✅ Saved credentials to {credentials_path}")
        
    except Exception as e:
        logger.error(f"❌ Error saving credentials: {e}")
        raise

def refresh_keycloak_gateway_token(gateway_config_info: Dict, credentials_path: str) -> Optional[str]:
    """
    Refresh the Keycloak access token for the gateway
    
    Args:
        gateway_config_info: Gateway configuration dictionary
        credentials_path: Path to credentials file
        
    Returns:
        New access token or None if failed
    """
    try:
        print("🔄 Refreshing Keycloak access token...")
        
        # Get new token from Keycloak
        new_token = refresh_keycloak_token(gateway_config_info)
        
        if new_token:
            # Update credentials file
            try:
                with open(credentials_path, 'r') as cred_file:
                    credentials = json.load(cred_file)
                
                credentials['access_token'] = new_token
                credentials['updated_at'] = time.time()
                
                with open(credentials_path, 'w') as cred_file:
                    json.dump(credentials, cred_file, indent=4)
                
                print("✅ Successfully refreshed and updated Keycloak access token")
                logger.info("✅ Token refresh completed")
                return new_token
                
            except Exception as file_error:
                logger.error(f"❌ Error updating credentials file: {file_error}")
                return new_token  # Return token even if file update fails
        else:
            print("❌ Failed to refresh Keycloak token")
            return None
            
    except Exception as e:
        logger.error(f"❌ Error refreshing Keycloak token: {e}")
        return None

def validate_keycloak_credentials(credentials_dict: Dict) -> bool:
    """
    Validate that Keycloak credentials dictionary contains all required fields
    
    Args:
        credentials_dict: Dictionary containing credentials
        
    Returns:
        True if valid, False otherwise
    """
    required_fields = ['gateway_id', 'mcp_url', 'access_token']
    keycloak_fields = ['url', 'realm_name', 'client_id', 'client_secret', 'discovery_url']
    
    # Check main fields
    if not all(field in credentials_dict and credentials_dict[field] for field in required_fields):
        return False
    
    # Check auth type
    if credentials_dict.get('auth_type') != 'keycloak':
        return False
    
    # Check Keycloak specific fields
    keycloak_config = credentials_dict.get('keycloak', {})
    if not all(field in keycloak_config and keycloak_config[field] for field in keycloak_fields):
        return False
    
    return True

def load_keycloak_gateway_credentials(credentials_path: str) -> Optional[Dict]:
    """
    Load and validate Keycloak gateway credentials from file
    
    Args:
        credentials_path: Path to credentials file
        
    Returns:
        Credentials dictionary or None if invalid/missing
    """
    try:
        if not os.path.exists(credentials_path):
            return None
        
        with open(credentials_path, 'r') as cred_file:
            credentials = json.load(cred_file)
        
        if validate_keycloak_credentials(credentials):
            logger.info(f"✅ Loaded valid Keycloak credentials from {credentials_path}")
            return credentials
        else:
            logger.warning(f"❌ Invalid Keycloak credentials in {credentials_path}")
            return None
            
    except Exception as e:
        logger.error(f"❌ Error loading credentials: {e}")
        return None

# Configuration helper for easy integration
def get_keycloak_config_template() -> Dict:
    """
    Get a template configuration for Keycloak integration
    
    Returns:
        Template configuration dictionary
    """
    return {
        "inbound_auth": {
            "keycloak": {
                "url": "${KEYCLOAK_URL}",
                "admin_user": "${KEYCLOAK_ADMIN_USER}",
                "admin_pass": "${KEYCLOAK_ADMIN_PASS}", 
                "realm_name": "monitoring-realm",
                "client_id": "agentcore-gateway-client",
                "scopes": ["gateway:read", "gateway:write"],
                "create_realm": True
            }
        },
        "credentials": {
            "use_existing": False,
            "create_new_access_token": False,
            "use_keycloak": True
        }
    }