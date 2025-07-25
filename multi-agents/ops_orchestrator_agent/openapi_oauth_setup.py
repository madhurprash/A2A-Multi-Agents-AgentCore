import boto3
import json
import os
from typing import Dict, List, Optional
from utils import upload_smithy_to_s3

def create_oauth2_credential_provider(
    gateway_client,
    provider_name: str,
    auth_config: Dict
) -> str:
    """
    Create an OAuth2 credential provider for OpenAPI authentication.
    
    Args:
        gateway_client: Bedrock AgentCore gateway client
        provider_name: Name for the credential provider
        auth_config: OAuth configuration containing client_id, client_secret, discovery_url, etc.
    
    Returns:
        ARN of the created credential provider
    """
    try:
        provider_config = {
            "customOauth2ProviderConfig": {
                "oauthDiscovery": {
                    "discoveryUrl": auth_config["discovery_url"]
                },
                "clientId": auth_config["client_id"],
                "clientSecret": auth_config["client_secret"]
            }
        }
        
        if "scopes" in auth_config:
            provider_config["customOauth2ProviderConfig"]["scopes"] = auth_config["scopes"]

        response = gateway_client.create_oauth2_credential_provider(
            name=provider_name,
            description=f"OAuth2 provider for {provider_name}",
            config=provider_config
        )
        
        print(f"✅ Created OAuth2 credential provider: {provider_name}")
        return response["credentialProviderArn"]
        
    except Exception as e:
        print(f"❌ Failed to create OAuth2 credential provider {provider_name}: {e}")
        raise

def upload_openapi_spec_to_s3(spec_file_path: str, bucket_name: str, object_key: str) -> str:
    """
    Upload OpenAPI specification to S3.
    
    Args:
        spec_file_path: Path to the OpenAPI spec file
        bucket_name: S3 bucket name
        object_key: S3 object key
    
    Returns:
        S3 URI of the uploaded spec
    """
    from constants import REGION_NAME
    
    try:
        s3_client = boto3.client('s3', region_name=REGION_NAME)
        
        # Check if bucket exists, create if it doesn't
        try:
            s3_client.head_bucket(Bucket=bucket_name)
        except s3_client.exceptions.NoSuchBucket:
            print(f"Creating S3 bucket: {bucket_name}")
            if REGION_NAME == 'us-east-1':
                s3_client.create_bucket(Bucket=bucket_name)
            else:
                s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': REGION_NAME}
                )
        
        # Upload the OpenAPI spec
        print(f"Uploading {spec_file_path} to s3://{bucket_name}/{object_key}")
        s3_client.upload_file(spec_file_path, bucket_name, object_key)
        
        s3_uri = f"s3://{bucket_name}/{object_key}"
        print(f"✅ Successfully uploaded OpenAPI spec to: {s3_uri}")
        return s3_uri
        
    except Exception as e:
        print(f"❌ Failed to upload OpenAPI spec to S3: {e}")
        raise

def create_openapi_oauth_target(
    gateway_id: str,
    target_name: str,
    openapi_spec_s3_uri: str,
    credential_provider_arn: str,
    scopes: Optional[List[str]] = None
) -> str:
    """
    Create a gateway target for OpenAPI with OAuth authentication.
    
    Args:
        gateway_id: Gateway identifier
        target_name: Name for the target
        openapi_spec_s3_uri: S3 URI of the OpenAPI specification
        credential_provider_arn: ARN of the OAuth2 credential provider
        scopes: Optional list of OAuth scopes
    
    Returns:
        Target ID of the created target
    """
    from constants import REGION_NAME
    
    try:
        agentcore_client = boto3.client('bedrock-agentcore-control', region_name=REGION_NAME)
        
        # Create credential provider configuration for OAuth
        credential_info = [
            {
                "credentialProviderType": "OAUTH2",
                "credentialProvider": {
                    "oauth2CredentialProvider": {
                        "providerArn": credential_provider_arn
                    }
                }
            }
        ]
        
        if scopes:
            credential_info[0]["credentialProvider"]["oauth2CredentialProvider"]["scopes"] = scopes
        
        # Create target configuration for OpenAPI
        target_config = {
            "mcp": {
                "openApiSchema": {
                    "s3": {
                        "uri": openapi_spec_s3_uri
                    }
                }
            }
        }
        
        # Create the gateway target
        response = agentcore_client.create_gateway_target(
            gatewayIdentifier=gateway_id,
            name=target_name,
            description=f"OpenAPI OAuth target for {target_name}",
            targetConfiguration=target_config,
            credentialProviderConfigurations=credential_info,
        )
        
        print(f"✅ Created OpenAPI OAuth target: {target_name} (ID: {response['targetId']})")
        return response["targetId"]
        
    except Exception as e:
        print(f"❌ Failed to create OpenAPI OAuth target {target_name}: {e}")
        raise

def setup_openapi_oauth_targets(gateway_id: str, bucket_name: str) -> List[Dict]:
    """
    Set up OpenAPI OAuth targets for GitHub and Jira APIs.
    
    Args:
        gateway_id: Gateway identifier
        bucket_name: S3 bucket for storing OpenAPI specs
    
    Returns:
        List of created target information
    """
    created_targets = []
    
    # Configuration for different API providers
    api_configs = {
        "github": {
            "spec_file": "tools/github_api_spec.yaml",
            "target_name": "GitHubAPI",
            "auth_config": {
                "discovery_url": "https://github.com/.well-known/oauth_authorization_server",
                "client_id": os.environ.get("GITHUB_CLIENT_ID", "your_github_client_id"),
                "client_secret": os.environ.get("GITHUB_CLIENT_SECRET", "your_github_client_secret"),
                "scopes": ["repo", "issues", "pull_requests"]
            }
        },
        "jira": {
            "spec_file": "tools/jira_api_spec.yaml", 
            "target_name": "JiraAPI",
            "auth_config": {
                "discovery_url": "https://auth.atlassian.com/.well-known/oauth_authorization_server",
                "client_id": os.environ.get("JIRA_CLIENT_ID", "your_jira_client_id"),
                "client_secret": os.environ.get("JIRA_CLIENT_SECRET", "your_jira_client_secret"),
                "scopes": ["read:jira-work", "write:jira-work"]
            }
        }
    }
    
    # Note: This is a simplified setup. In production, you'll need:
    # 1. Actual OAuth app credentials from GitHub/Jira
    # 2. Proper discovery URLs for your OAuth providers
    # 3. Correct scopes for your use case
    
    gateway_client = boto3.client('bedrock-agentcore-control')
    
    for api_name, config in api_configs.items():
        try:
            print(f"\n🔧 Setting up {api_name.upper()} OpenAPI OAuth target...")
            
            # Skip if spec file doesn't exist
            if not os.path.exists(config["spec_file"]):
                print(f"⚠️  OpenAPI spec file not found: {config['spec_file']}")
                continue
            
            # Upload OpenAPI spec to S3
            object_key = f"openapi-specs/{api_name}_api_spec.yaml"
            s3_uri = upload_openapi_spec_to_s3(config["spec_file"], bucket_name, object_key)
            
            # Create OAuth2 credential provider
            provider_name = f"{api_name}_oauth_provider"
            
            # Note: In a real implementation, you would uncomment this:
            # provider_arn = create_oauth2_credential_provider(
            #     gateway_client, provider_name, config["auth_config"]
            # )
            
            # For demo purposes, using a placeholder ARN
            provider_arn = f"arn:aws:bedrock-agentcore:us-west-2:123456789012:oauth2-credential-provider/{provider_name}"
            print(f"📝 Would create OAuth2 provider with ARN: {provider_arn}")
            
            # Create OpenAPI target with OAuth
            # Note: In a real implementation, you would uncomment this:
            # target_id = create_openapi_oauth_target(
            #     gateway_id,
            #     config["target_name"],
            #     s3_uri,
            #     provider_arn,
            #     config["auth_config"].get("scopes")
            # )
            
            # For demo purposes, using a placeholder target ID
            target_id = f"target_{api_name}_oauth"
            print(f"📝 Would create OAuth target with ID: {target_id}")
            
            created_targets.append({
                'id': target_id,
                'name': config["target_name"],
                'type': 'openapi_oauth',
                's3_uri': s3_uri,
                'provider_arn': provider_arn,
                'api': api_name
            })
            
            print(f"✅ Configured {api_name.upper()} OpenAPI OAuth target")
            
        except Exception as e:
            print(f"❌ Failed to set up {api_name.upper()} OAuth target: {e}")
            continue
    
    return created_targets

def get_oauth_access_token(
    auth_config: Dict,
    scope: str = "InvokeGateway"
) -> Optional[str]:
    """
    Get an OAuth access token for gateway invocation.
    
    Args:
        auth_config: OAuth configuration
        scope: Required scope for the token
    
    Returns:
        Access token or None if failed
    """
    import requests
    
    try:
        token_url = auth_config.get("token_endpoint")
        if not token_url:
            print("❌ Token endpoint not provided in auth_config")
            return None
        
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "client_credentials",
            "client_id": auth_config["client_id"],
            "client_secret": auth_config["client_secret"],
            "scope": scope,
        }
        
        response = requests.post(token_url, headers=headers, data=data)
        response.raise_for_status()
        
        token_data = response.json()
        access_token = token_data.get("access_token")
        
        if access_token:
            print("✅ Successfully obtained OAuth access token")
            return access_token
        else:
            print("❌ No access token in response")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to get OAuth access token: {e}")
        return None

if __name__ == "__main__":
    print("🚀 OpenAPI OAuth Setup for Bedrock AgentCore Gateway")
    print("=" * 60)
    
    # Example usage - you would call this from your main setup script
    gateway_id = "your-gateway-id"
    bucket_name = "your-s3-bucket"
    
    targets = setup_openapi_oauth_targets(gateway_id, bucket_name)
    
    print(f"\n📊 Summary: Created {len(targets)} OpenAPI OAuth targets")
    for target in targets:
        print(f"  - {target['name']} ({target['api'].upper()}): {target['id']}")