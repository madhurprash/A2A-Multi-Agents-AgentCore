#!/usr/bin/env python3
"""
AWS Bedrock AgentCore Gateway Troubleshooting Script

This script helps diagnose and fix common issues with gateway creation,
particularly InternalServerException errors with Keycloak authentication.
"""

import os
import sys
import json
import time
import boto3
import requests
from typing import Dict, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def check_keycloak_server() -> bool:
    """Check if Keycloak server is running and accessible"""
    print("🔍 Checking Keycloak server connectivity...")
    
    keycloak_url = os.getenv('KEYCLOAK_URL', 'http://localhost:8080/auth/')
    realm_name = 'monitoring-realm'
    discovery_url = f"{keycloak_url}realms/{realm_name}/.well-known/openid-configuration"
    
    try:
        response = requests.get(discovery_url, timeout=10)
        if response.status_code == 200:
            print(f"✅ Keycloak server accessible at {discovery_url}")
            config = response.json()
            print(f"   - Issuer: {config.get('issuer', 'Unknown')}")
            print(f"   - Token endpoint: {config.get('token_endpoint', 'Unknown')}")
            return True
        else:
            print(f"❌ Keycloak server returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to Keycloak server at {keycloak_url}")
        print("   Please ensure Keycloak is running with:")
        print("   docker run -p 127.0.0.1:8080:8080 \\")
        print("     -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \\")
        print("     -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \\")
        print("     quay.io/keycloak/keycloak:26.3.2 start-dev --http-relative-path /auth")
        return False
    except Exception as e:
        print(f"❌ Error checking Keycloak: {e}")
        return False

def check_aws_credentials() -> bool:
    """Check if AWS credentials are properly configured"""
    print("🔍 Checking AWS credentials...")
    
    try:
        session = boto3.Session()
        credentials = session.get_credentials()
        
        if credentials is None:
            print("❌ No AWS credentials found")
            print("   Please configure AWS credentials using:")
            print("   - aws configure")
            print("   - AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
            print("   - IAM roles (if running on EC2)")
            return False
        
        # Test credentials by making a simple call
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        
        print(f"✅ AWS credentials configured")
        print(f"   - Account: {identity.get('Account')}")
        print(f"   - User/Role: {identity.get('Arn')}")
        return True
        
    except Exception as e:
        print(f"❌ AWS credentials error: {e}")
        return False

def check_iam_permissions() -> bool:
    """Check if IAM permissions are sufficient for AgentCore operations"""
    print("🔍 Checking IAM permissions...")
    
    try:
        session = boto3.Session()
        region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        
        # Test bedrock-agentcore-control access
        agentcore_client = session.client('bedrock-agentcore-control', region_name=region)
        
        # Try to list gateways (basic permission test)
        agentcore_client.list_gateways()
        print("✅ Basic AgentCore permissions verified")
        
        # Test IAM access
        iam_client = session.client('iam', region_name=region)
        iam_client.list_roles(MaxItems=1)
        print("✅ IAM permissions verified")
        
        return True
        
    except Exception as e:
        error_str = str(e)
        if "AccessDenied" in error_str or "UnauthorizedOperation" in error_str:
            print("❌ Insufficient IAM permissions")
            print("   Required permissions:")
            print("   - bedrock-agentcore-control:ListGateways")
            print("   - bedrock-agentcore-control:CreateGateway")
            print("   - bedrock-agentcore-control:GetGateway")
            print("   - iam:CreateRole")
            print("   - iam:AttachRolePolicy")
            print("   - iam:PassRole")
        else:
            print(f"❌ Error checking permissions: {e}")
        return False

def check_agentcore_service_availability() -> bool:
    """Check if AgentCore service is available in the current region"""
    print("🔍 Checking AgentCore service availability...")
    
    region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
    supported_regions = ['us-east-1', 'us-west-2', 'ap-southeast-2', 'eu-central-1']
    
    if region not in supported_regions:
        print(f"⚠️ AgentCore may not be available in {region}")
        print(f"   Supported regions: {', '.join(supported_regions)}")
        print(f"   Consider switching to a supported region")
        return False
    
    try:
        session = boto3.Session()
        agentcore_client = session.client('bedrock-agentcore-control', region_name=region)
        
        # Simple service availability test
        agentcore_client.list_gateways()
        print(f"✅ AgentCore service available in {region}")
        return True
        
    except Exception as e:
        if "EndpointConnectionError" in str(e):
            print(f"❌ AgentCore service not available in {region}")
            print(f"   Try switching to a supported region: {', '.join(supported_regions)}")
        else:
            print(f"❌ Error checking service availability: {e}")
        return False

def check_network_connectivity() -> bool:
    """Check network connectivity to AWS services"""
    print("🔍 Checking network connectivity...")
    
    test_urls = [
        "https://bedrock-agentcore-control.us-east-1.amazonaws.com",
        "https://iam.amazonaws.com",
        "https://sts.amazonaws.com"
    ]
    
    all_good = True
    for url in test_urls:
        try:
            response = requests.head(url, timeout=10)
            if response.status_code in [200, 403, 405]:  # 403/405 are expected for some services
                print(f"✅ {url} - reachable")
            else:
                print(f"⚠️ {url} - status {response.status_code}")
                all_good = False
        except Exception as e:
            print(f"❌ {url} - {e}")
            all_good = False
    
    return all_good

def suggest_fixes() -> None:
    """Provide suggestions for fixing common issues"""
    print("\n🔧 TROUBLESHOOTING SUGGESTIONS")
    print("=" * 50)
    
    print("\n1. For InternalServerException errors:")
    print("   - Ensure Keycloak server is running and accessible")
    print("   - Validate auth configuration structure")
    print("   - Try deleting any failed gateway resources")
    print("   - Contact AWS support (AgentCore is in preview)")
    
    print("\n2. For Keycloak connectivity issues:")
    print("   - Start Keycloak with the provided Docker command")
    print("   - Check KEYCLOAK_URL environment variable")
    print("   - Verify firewall/network settings")
    
    print("\n3. For AWS permission issues:")
    print("   - Ensure IAM user/role has required permissions")
    print("   - Check AWS credentials configuration")
    print("   - Verify region supports AgentCore service")
    
    print("\n4. For region-specific issues:")
    print("   - Switch to supported regions: us-east-1, us-west-2, ap-southeast-2, eu-central-1")
    print("   - Update AWS_DEFAULT_REGION environment variable")
    
    print("\n5. Emergency workarounds:")
    print("   - Try creating gateway without Keycloak (if alternative auth available)")
    print("   - Use different gateway name to avoid conflicts")
    print("   - Wait and retry (preview service may have temporary issues)")

def main():
    """Run comprehensive troubleshooting checks"""
    print("🚀 AWS Bedrock AgentCore Gateway Troubleshooting")
    print("=" * 60)
    print("This script will check common issues with gateway creation")
    print()
    
    checks = [
        ("Keycloak Server", check_keycloak_server),
        ("AWS Credentials", check_aws_credentials),
        ("IAM Permissions", check_iam_permissions),
        ("AgentCore Service", check_agentcore_service_availability),
        ("Network Connectivity", check_network_connectivity)
    ]
    
    results = {}
    for name, check_func in checks:
        print(f"\n{'─' * 20} {name} {'─' * 20}")
        try:
            results[name] = check_func()
        except Exception as e:
            print(f"❌ Error during {name} check: {e}")
            results[name] = False
        time.sleep(1)  # Brief pause between checks
    
    # Summary
    print(f"\n{'═' * 60}")
    print("📊 TROUBLESHOOTING SUMMARY")
    print(f"{'═' * 60}")
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{name:.<30} {status}")
    
    print(f"\nOverall: {passed}/{total} checks passed")
    
    if passed == total:
        print("🎉 All checks passed! Gateway creation should work.")
    else:
        print("⚠️ Some issues detected. See suggestions below.")
        suggest_fixes()
    
    print(f"\n{'═' * 60}")
    print("For additional help:")
    print("- Check AWS service health dashboard")
    print("- Review CloudWatch logs")
    print("- Contact AWS support for preview service issues")
    print("- Join AgentCore Discord: https://discord.gg/bedrockagentcore-preview")

if __name__ == "__main__":
    main()