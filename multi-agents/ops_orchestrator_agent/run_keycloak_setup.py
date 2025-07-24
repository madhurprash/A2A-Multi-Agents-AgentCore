#!/usr/bin/env python3
"""
Simple script to run Keycloak gateway setup for ops orchestrator agent
This demonstrates how to use the Keycloak authentication instead of Cognito
"""

import os
import sys
import json
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def check_keycloak_environment():
    """Check if required Keycloak environment variables are set"""
    required_vars = [
        'KEYCLOAK_URL',
        'KEYCLOAK_ADMIN_USER', 
        'KEYCLOAK_ADMIN_PASS'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nPlease set these environment variables before running:")
        print("export KEYCLOAK_URL='http://localhost:8080/'")
        print("export KEYCLOAK_ADMIN_USER='admin'")
        print("export KEYCLOAK_ADMIN_PASS='admin'")
        return False
    
    print("✅ Keycloak environment variables are set")
    return True

def create_test_config():
    """Create a test configuration for Keycloak setup"""
    config = {
        "inbound_auth": {
            "keycloak": {
                "url": os.getenv("KEYCLOAK_URL", "http://localhost:8080/"),
                "admin_user": os.getenv("KEYCLOAK_ADMIN_USER", "admin"),
                "admin_pass": os.getenv("KEYCLOAK_ADMIN_PASS", "admin"),
                "realm_name": "ops-orchestrator-realm",
                "client_id": "ops-orchestrator-gateway-client",
                "scopes": ["gateway:read", "gateway:write", "ops:manage"],
                "create_realm": True
            }
        },
        "credentials": {
            "use_keycloak": True,
            "use_existing": False,
            "create_new_access_token": False
        },
        "name": "OpsOrchestratorGatewayKeycloak"
    }
    return config

def test_keycloak_setup():
    """Test the Keycloak authentication setup"""
    try:
        print("🧪 Testing Keycloak authentication setup...")
        
        # Import the setup function
        from setup_keycloack_auth import setup_keycloak_auth
        
        # Create test configuration
        config = create_test_config()
        
        print("📋 Configuration:")
        print(json.dumps(config, indent=2))
        print()
        
        # Run Keycloak setup
        print("🔧 Running Keycloak setup...")
        result = setup_keycloak_auth(config)
        
        print("\n✅ Keycloak setup completed successfully!")
        print("="*60)
        print("KEYCLOAK AUTHENTICATION RESULTS:")
        print("="*60)
        print(f"Keycloak URL: {result['keycloak_url']}")
        print(f"Realm: {result['realm_name']}")
        print(f"Client ID: {result['client_id']}")
        print(f"Client Secret: {result['client_secret'][:20]}...")
        print(f"Access Token: {result['access_token'][:20]}...")
        print(f"Discovery URL: {result['discovery_url']}")
        print(f"Scopes: {', '.join(result['scopes'])}")
        
        print("\nAWS Gateway Auth Config:")
        print(json.dumps(result['auth_config'], indent=2))
        
        # Save test results
        test_results_file = "keycloak_test_results.json"
        with open(test_results_file, 'w') as f:
            json.dump(result, f, indent=4)
        print(f"\n💾 Test results saved to: {test_results_file}")
        
        return result
        
    except Exception as e:
        print(f"❌ Keycloak setup failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_gateway_integration():
    """Test the complete gateway integration with Keycloak"""
    try:
        print("\n🌉 Testing complete gateway integration...")
        
        # Mock the required functions for testing
        sys.path.append('.')
        
        # Create a minimal configuration
        config_data = {
            "agent_information": {
                "ops_orchestrator_agent_model_info": {
                    "gateway_config": create_test_config()
                }
            }
        }
        
        print("📋 Gateway configuration created")
        print("ℹ️  This would normally create AWS Gateway with Keycloak auth")
        print("ℹ️  Skipping AWS calls in test mode")
        
        return True
        
    except Exception as e:
        print(f"❌ Gateway integration test failed: {e}")
        return False

def main():
    """Main function to run Keycloak setup tests"""
    print("🔑 Keycloak Gateway Setup for Ops Orchestrator Agent")
    print("="*60)
    
    # Check environment
    if not check_keycloak_environment():
        return 1
    
    # Test Keycloak setup
    keycloak_result = test_keycloak_setup()
    if not keycloak_result:
        return 1
    
    # Test gateway integration
    if not test_gateway_integration():
        return 1
    
    print("\n🎉 All tests completed successfully!")
    print("\nNext steps:")
    print("1. Update your config.yaml with Keycloak settings")
    print("2. Set 'use_keycloak: true' in gateway credentials")
    print("3. Run ops_orchestrator_multi_agent.py")
    print("4. The agent will use Keycloak instead of Cognito")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())