import os
import time
import json
import requests
import logging
from typing import Dict, Optional, Tuple
from keycloak.exceptions import KeycloakError
from keycloak import KeycloakAdmin, KeycloakOpenID

# steps to run keycloak:
# docker run -p 127.0.0.1:8080:8080 \
#   -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
#   -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
#   quay.io/keycloak/keycloak:26.3.2 start-dev --http-relative-path /auth
#  export KEYCLOAK_URL="http://localhost:8080/auth/" && export KEYCLOAK_ADMIN_USER="admin" && export KEYCLOAK_ADMIN_PASS="admin" && python ops_orchestrator_multi_agent.py 

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
            # In this case, we will set up the keycloak admin, but this could be 
            # anything. This is an example of providing an external OIDC support for
            # the agentcore gateway solution
            self.keycloak_admin = KeycloakAdmin(
                server_url=self.keycloak_url,
                username=self.admin_user,
                password=self.admin_pass,
                realm_name="master",
                user_realm_name="master",
                verify=True
            )
            print("✅ Connected to Keycloak admin interface (master realm)")
            
            # After realm creation, we need to switch to the target realm for client operations
            return self.keycloak_admin
        except Exception as e:
            print(f"❌ Failed to connect to Keycloak admin: {e}")
            raise
    
    def get_or_create_realm(self) -> str:
        """Create realm if it doesn't exist or get existing one
        A realm is a fundamental security and administrative domain within a Keycloak server
        instance. thi represents an isolation space where you can manage users, credentials, roles, groups and clients.
        """
        try:
            existing_realms = [r["realm"] for r in self.keycloak_admin.get_realms()]
            
            if self.realm_name not in existing_realms:
                if self.create_realm:
                    self.keycloak_admin.create_realm({
                        "realm": self.realm_name, 
                        "enabled": True,
                        "displayName": f"AgentCore Gateway Realm for OpenAI agents - {self.realm_name}"
                    })
                    print(f"✅ Created realm: {self.realm_name}")
                else:
                    print(f"Realm '{self.realm_name}' does not exist and create_realm is False")
            else:
                print(f"ℹ️ Using existing realm: {self.realm_name}")
            return self.realm_name
        except Exception as e:
            print(f"❌ Error with realm setup: {e}")
            raise
    
    def get_realm_admin_client(self):
        """Get admin client that can manage the target realm from master"""
        # The master realm admin can manage all realms
        self.keycloak_admin_realm = self.keycloak_admin
        print(f"✅ Using master admin for realm: {self.realm_name}")
        return self.keycloak_admin_realm
    
    def get_or_create_client(self) -> Tuple[str, str]:
        """Create OIDC client or get existing one, return client_id and secret
        OpenID Connect (OIDC) is an identity auth layer on top of OAuth2.0 that issues 
        JWT (JSON web tokens) for user based identity support.
        """
        try:
            # Use master realm admin client with raw API calls for cross-realm management
            self.get_realm_admin_client()
            admin_client = self.keycloak_admin
            
            # Check if client already exists in the target realm using raw API
            clients_url = f"admin/realms/{self.realm_name}/clients"
            existing_clients = admin_client.connection.raw_get(clients_url).json()
            existing_client = None
            
            for client in existing_clients:
                if client.get('clientId') == self.client_id:
                    existing_client = client
                    break
            
            if existing_client:
                client_uuid = existing_client['id']
                print(f"ℹ️ Found existing client: {self.client_id}")
                
                # Delete existing client to ensure clean setup
                delete_url = f"admin/realms/{self.realm_name}/clients/{client_uuid}"
                admin_client.connection.raw_delete(delete_url)
                print(f"🗑️ Deleted existing client: {self.client_id}")
            
            # Create new client (whether existing was deleted or not)
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
            
            # Create client using raw API
            create_response = admin_client.connection.raw_post(clients_url, data=json.dumps(client_payload))
            if create_response.status_code != 201:
                raise Exception(f"Failed to create client: {create_response.text}")
            
            # Extract client UUID from Location header
            location = create_response.headers.get('Location', '')
            client_uuid = location.split('/')[-1]
            print(f"✅ Created client: {self.client_id}")
            
            # Get client secret using raw API
            secret_url = f"admin/realms/{self.realm_name}/clients/{client_uuid}/client-secret"
            secret_response = admin_client.connection.raw_get(secret_url)
            self.client_secret = secret_response.json()["value"]
            print(f"✅ Retrieved client secret")
            return self.client_id, self.client_secret
        except Exception as e:
            logger.error(f"❌ Error with client setup: {e}")
            raise
    
    def setup_client_scopes(self, client_uuid: str):
        """Attach configured scopes to a specific Keycloak client."""
        try:
            admin_client = self.keycloak_admin
            
            for scope_name in self.scopes:
                # 1️⃣ Ensure the scope exists in the target realm using raw API
                scopes_url = f"admin/realms/{self.realm_name}/client-scopes"
                scopes_response = admin_client.connection.raw_get(scopes_url)
                scopes = scopes_response.json()
                
                if not any(s['name'] == scope_name for s in scopes):
                    scope_payload = {
                        "name": scope_name,
                        "protocol": "openid-connect",
                        "description": f"AgentCore Gateway scope: {scope_name}"
                    }
                    admin_client.connection.raw_post(scopes_url, data=json.dumps(scope_payload))
                    logger.info(f"✅ Created scope: {scope_name}")

                # 2️⃣ Look up the scope ID
                scopes_response = admin_client.connection.raw_get(scopes_url)
                scopes = scopes_response.json()
                scope = next(s for s in scopes if s['name'] == scope_name)
                scope_id = scope['id']

                # 3️⃣ Attach as default client scope using raw API
                attach_url = f"admin/realms/{self.realm_name}/clients/{client_uuid}/default-client-scopes/{scope_id}"
                admin_client.connection.raw_put(attach_url, data='')
                logger.info(f"✅ Attached default scope '{scope_name}' to client {client_uuid}")

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
                server_url=self.keycloak_url,
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
            print(f"🔍 Debug: Attempting token request for client: {self.client_id}")
            print(f"🔍 Debug: Realm: {self.realm_name}")
            print(f"🔍 Debug: Keycloak URL: {self.keycloak_url}")
            print(f"🔍 Debug: Client secret length: {len(self.client_secret) if self.client_secret else 'None'}")
            
            token_response = self.oidc_client.token(grant_type="client_credentials")
            access_token = token_response["access_token"]
            logger.info(f"✅ Obtained access token: {access_token[:20]}...")
            return access_token
        except Exception as e:
            logger.error(f"❌ Error getting access token: {e}")
            print(f"🔍 Debug: Token endpoint might be: {self.keycloak_url}realms/{self.realm_name}/protocol/openid-connect/token")
            raise
    
    def get_agentcore_auth_config(self) -> Dict:
        """Get AWS Bedrock AgentCore gateway authorizer configuration"""
        discovery_url = self.get_discovery_url()
        # This will create the agentcore auth config
        # that will be used to set up the inbound authentication
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
            
            # Get client UUID for scope operations using raw API
            clients_url = f"admin/realms/{self.realm_name}/clients"
            clients_response = self.keycloak_admin.connection.raw_get(clients_url)
            clients = clients_response.json()
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
        
        # Get existing client details using raw API
        keycloak_auth.get_realm_admin_client()
        clients_url = f"admin/realms/{keycloak_auth.realm_name}/clients"
        clients_response = keycloak_auth.keycloak_admin.connection.raw_get(clients_url)
        clients = clients_response.json()
        client_uuid = None
        for client in clients:
            if client.get('clientId') == keycloak_auth.client_id:
                client_uuid = client['id']
                break
        
        if not client_uuid:
            logger.error(f"Client {keycloak_auth.client_id} not found")
            return None
        
        # Get client secret using raw API
        secret_url = f"admin/realms/{keycloak_auth.realm_name}/clients/{client_uuid}/client-secret"
        secret_response = keycloak_auth.keycloak_admin.connection.raw_get(secret_url)
        keycloak_auth.client_secret = secret_response.json()["value"]
        
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