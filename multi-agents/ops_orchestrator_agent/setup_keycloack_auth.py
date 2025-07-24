import os
import time
import json
import requests
import logging
from typing import Dict, Optional, Tuple
from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak.exceptions import KeycloakError

logger = logging.getLogger(__name__)

class KeycloakGatewayAuth:
    """
    Keycloak authentication handler for AWS Bedrock AgentCore Gateway
    Replaces Cognito authentication with Keycloak OpenID Connect
    """
    
    def __init__(self, config: Dict):
        """
        Initialize Keycloak authentication with configuration
        
        Args:
            config: Dictionary containing Keycloak configuration
        """
        self.keycloak_config = config.get('keycloak', {})
        self.keycloak_url = self.keycloak_config.get('url', os.getenv("KEYCLOAK_URL", "http://localhost:8080/"))
        self.admin_user = self.keycloak_config.get('admin_user', os.getenv("KEYCLOAK_ADMIN_USER", "admin"))
        self.admin_pass = self.keycloak_config.get('admin_pass', os.getenv("KEYCLOAK_ADMIN_PASS", "admin"))
        self.realm_name = self.keycloak_config.get('realm_name', "monitoring-realm")
        self.client_id = self.keycloak_config.get('client_id', "agentcore-gateway-client")
        self.scopes = self.keycloak_config.get('scopes', ["gateway:read", "gateway:write"])
        self.create_realm = self.keycloak_config.get('create_realm', True)
        
        self.client_secret = None
        self.keycloak_admin = None
        self.oidc_client = None
        
        logger.info(f"Initialized Keycloak auth for realm: {self.realm_name}")
    
    def setup_admin_client(self) -> KeycloakAdmin:
        """Setup Keycloak admin client"""
        try:
            self.keycloak_admin = KeycloakAdmin(
                server_url=f"{self.keycloak_url}auth/",
                username=self.admin_user,
                password=self.admin_pass,
                realm_name="master",
                user_realm_name="master",
                verify=True
            )
            logger.info("✅ Connected to Keycloak admin interface")
            return self.keycloak_admin
        except Exception as e:
            logger.error(f"❌ Failed to connect to Keycloak admin: {e}")
            raise
    
    def get_or_create_realm(self) -> str:
        """Create realm if it doesn't exist or get existing one"""
        try:
            existing_realms = [r["realm"] for r in self.keycloak_admin.get_realms()]
            
            if self.realm_name not in existing_realms:
                if self.create_realm:
                    self.keycloak_admin.create_realm({
                        "realm": self.realm_name, 
                        "enabled": True,
                        "displayName": f"AgentCore Gateway Realm - {self.realm_name}"
                    })
                    logger.info(f"✅ Created realm: {self.realm_name}")
                else:
                    raise ValueError(f"Realm '{self.realm_name}' does not exist and create_realm is False")
            else:
                logger.info(f"ℹ️ Using existing realm: {self.realm_name}")
                
            return self.realm_name
        except Exception as e:
            logger.error(f"❌ Error with realm setup: {e}")
            raise
    
    def get_or_create_client(self) -> Tuple[str, str]:
        """Create OIDC client or get existing one, return client_id and secret"""
        try:
            # Check if client already exists
            existing_clients = self.keycloak_admin.get_clients()
            existing_client = None
            
            for client in existing_clients:
                if client.get('clientId') == self.client_id:
                    existing_client = client
                    break
            
            if existing_client:
                client_uuid = existing_client['id']
                logger.info(f"ℹ️ Using existing client: {self.client_id}")
            else:
                # Create new client
                client_payload = {
                    "clientId": self.client_id,
                    "enabled": True,
                    "protocol": "openid-connect",
                    "publicClient": False,
                    "standardFlowEnabled": False,
                    "directAccessGrantsEnabled": False,
                    "serviceAccountsEnabled": True,
                    "redirectUris": [],
                    "description": "AgentCore Gateway OIDC Client"
                }
                
                client_uuid = self.keycloak_admin.create_client(client_payload)
                logger.info(f"✅ Created client: {self.client_id}")
            
            # Get client secret
            self.client_secret = self.keycloak_admin.get_client_secrets(client_uuid)["value"]
            logger.info(f"✅ Retrieved client secret")
            
            return self.client_id, self.client_secret
            
        except Exception as e:
            logger.error(f"❌ Error with client setup: {e}")
            raise
    
    def setup_client_scopes(self, client_uuid: str):
        """Setup custom scopes for the client"""
        try:
            for scope_name in self.scopes:
                # Check if client scope exists
                existing_scopes = self.keycloak_admin.get_client_scopes()
                scope_exists = any(scope.get('name') == scope_name for scope in existing_scopes)
                
                if not scope_exists:
                    # Create client scope
                    self.keycloak_admin.create_client_scope({
                        "name": scope_name,
                        "protocol": "openid-connect",
                        "description": f"AgentCore Gateway scope: {scope_name}"
                    })
                    logger.info(f"✅ Created scope: {scope_name}")
                
                # Get scope ID and attach to client
                scopes = self.keycloak_admin.get_client_scopes()
                scope_id = None
                for scope in scopes:
                    if scope.get('name') == scope_name:
                        scope_id = scope['id']
                        break
                
                if scope_id:
                    # Add scope to client as default scope
                    self.keycloak_admin.add_default_client_scope(client_uuid, scope_id)
                    logger.info(f"✅ Attached scope '{scope_name}' to client")
                
        except Exception as e:
            logger.error(f"❌ Error setting up scopes: {e}")
            raise
    
    def get_discovery_url(self) -> str:
        """Get OpenID Connect discovery URL"""
        discovery_url = f"{self.keycloak_url}realms/{self.realm_name}/.well-known/openid-configuration"
        logger.info(f"Discovery URL: {discovery_url}")
        return discovery_url
    
    def setup_oidc_client(self) -> KeycloakOpenID:
        """Setup OpenID Connect client for token operations"""
        try:
            self.oidc_client = KeycloakOpenID(
                server_url=f"{self.keycloak_url}auth/",
                realm_name=self.realm_name,
                client_id=self.client_id,
                client_secret_key=self.client_secret,
                verify=True
            )
            logger.info("✅ Setup OIDC client")
            return self.oidc_client
        except Exception as e:
            logger.error(f"❌ Error setting up OIDC client: {e}")
            raise
    
    def get_access_token(self) -> str:
        """Get access token using client credentials grant"""
        try:
            token_response = self.oidc_client.token(grant_type="client_credentials")
            access_token = token_response["access_token"]
            logger.info(f"✅ Obtained access token: {access_token[:20]}...")
            return access_token
        except Exception as e:
            logger.error(f"❌ Error getting access token: {e}")
            raise
    
    def get_agentcore_auth_config(self) -> Dict:
        """Get AWS Bedrock AgentCore gateway authorizer configuration"""
        discovery_url = self.get_discovery_url()
        
        auth_config = {
            "customJWTAuthorizer": {
                "discoveryUrl": discovery_url,
                "allowedClients": [self.client_id]
            }
        }
        
        logger.info("✅ Generated AgentCore auth config")
        return auth_config
    
    def setup_complete_auth(self) -> Dict:
        """
        Complete Keycloak authentication setup
        Returns dictionary with all necessary credentials and config
        """
        try:
            logger.info("🔧 Starting complete Keycloak authentication setup...")
            
            # Step 1: Setup admin client
            self.setup_admin_client()
            
            # Step 2: Create/get realm
            self.get_or_create_realm()
            
            # Step 3: Create/get client and secret
            client_id, client_secret = self.get_or_create_client()
            
            # Get client UUID for scope operations
            clients = self.keycloak_admin.get_clients()
            client_uuid = None
            for client in clients:
                if client.get('clientId') == self.client_id:
                    client_uuid = client['id']
                    break
            
            # Step 4: Setup scopes
            if client_uuid:
                self.setup_client_scopes(client_uuid)
            
            # Step 5: Setup OIDC client
            self.setup_oidc_client()
            
            # Step 6: Get access token
            access_token = self.get_access_token()
            
            # Step 7: Generate auth config
            auth_config = self.get_agentcore_auth_config()
            discovery_url = self.get_discovery_url()
            
            # Return complete configuration
            result = {
                "keycloak_url": self.keycloak_url,
                "realm_name": self.realm_name,
                "client_id": client_id,
                "client_secret": client_secret,
                "access_token": access_token,
                "discovery_url": discovery_url,
                "auth_config": auth_config,
                "scopes": self.scopes,
                "created_at": time.time()
            }
            
            logger.info("✅ Complete Keycloak authentication setup finished!")
            return result
            
        except Exception as e:
            logger.error(f"❌ Error in complete auth setup: {e}")
            raise

def setup_keycloak_auth(config: Dict) -> Dict:
    """
    Main function to setup Keycloak authentication
    
    Args:
        config: Configuration dictionary containing Keycloak settings
        
    Returns:
        Dictionary with authentication credentials and configuration
    """
    keycloak_auth = KeycloakGatewayAuth(config)
    return keycloak_auth.setup_complete_auth()

def refresh_keycloak_token(config: Dict) -> Optional[str]:
    """
    Refresh Keycloak access token
    
    Args:
        config: Configuration dictionary containing Keycloak settings
        
    Returns:
        New access token or None if failed
    """
    try:
        keycloak_auth = KeycloakGatewayAuth(config)
        keycloak_auth.setup_admin_client()
        
        # Get existing client details
        clients = keycloak_auth.keycloak_admin.get_clients()
        client_uuid = None
        for client in clients:
            if client.get('clientId') == keycloak_auth.client_id:
                client_uuid = client['id']
                break
        
        if not client_uuid:
            logger.error(f"Client {keycloak_auth.client_id} not found")
            return None
        
        # Get client secret
        keycloak_auth.client_secret = keycloak_auth.keycloak_admin.get_client_secrets(client_uuid)["value"]
        
        # Setup OIDC client and get new token
        keycloak_auth.setup_oidc_client()
        return keycloak_auth.get_access_token()
        
    except Exception as e:
        logger.error(f"❌ Error refreshing token: {e}")
        return None

# Legacy compatibility - can be used directly if called as script
if __name__ == "__main__":
    # Default configuration for standalone execution
    default_config = {
        "keycloak": {
            "url": os.getenv("KEYCLOAK_URL", "http://localhost:8080/"),
            "admin_user": os.getenv("KEYCLOAK_ADMIN_USER", "admin"),
            "admin_pass": os.getenv("KEYCLOAK_ADMIN_PASS", "admin"),
            "realm_name": "monitoring-realm",
            "client_id": "agentcore-gateway-client",
            "scopes": ["gateway:read", "gateway:write"],
            "create_realm": True
        }
    }
    
    try:
        result = setup_keycloak_auth(default_config)
        print("\n" + "="*60)
        print("🔑 KEYCLOAK AUTHENTICATION SETUP COMPLETE")
        print("="*60)
        print(f"Keycloak URL: {result['keycloak_url']}")
        print(f"Realm: {result['realm_name']}")
        print(f"Client ID: {result['client_id']}")
        print(f"Client Secret: {result['client_secret'][:20]}...")
        print(f"Access Token: {result['access_token'][:20]}...")
        print(f"Discovery URL: {result['discovery_url']}")
        print("\nUse this auth_config in your AgentCore Gateway:")
        print(json.dumps(result['auth_config'], indent=2))
        print("="*60)
        
        # Save credentials to file for later use
        credentials_file = "keycloak_gateway_credentials.json"
        with open(credentials_file, 'w') as f:
            json.dump(result, f, indent=4)
        print(f"Credentials saved to: {credentials_file}")
        
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        raise