#!/usr/bin/env python3
"""
Script to store API keys from .env file into AWS Secrets Manager.
This should be run once to migrate from .env to Secrets Manager.
"""
import os
import json
import boto3
import argparse
from typing import Dict, Any
from dotenv import load_dotenv
from botocore.exceptions import ClientError

def _create_or_update_secret(
    secrets_client,
    secret_name: str, 
    secret_value: str,
    description: str = ""
) -> bool:
    """
    Create or update a secret in AWS Secrets Manager.
    
    Args:
        secrets_client: Boto3 Secrets Manager client
        secret_name: Name of the secret
        secret_value: Value to store
        description: Optional description for the secret
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Try to update existing secret first
        response = secrets_client.update_secret(
            SecretId=secret_name,
            SecretString=secret_value,
            Description=description
        )
        print(f"✅ Updated existing secret: {secret_name}")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            # Secret doesn't exist, create it
            try:
                response = secrets_client.create_secret(
                    Name=secret_name,
                    SecretString=secret_value,
                    Description=description
                )
                print(f"✅ Created new secret: {secret_name}")
                return True
            except ClientError as create_error:
                print(f"❌ Failed to create secret {secret_name}: {create_error}")
                return False
        else:
            print(f"❌ Failed to update secret {secret_name}: {e}")
            return False
    except Exception as e:
        print(f"❌ Unexpected error with secret {secret_name}: {e}")
        return False

def _load_secrets_from_env() -> Dict[str, str]:
    """Load secrets from .env file."""
    load_dotenv()
    
    secrets = {}
    
    # Define the API keys to migrate
    api_keys = [
        'OPENAI_API_KEY',
        'TAVILY_API_KEY', 
        'JIRA_API_KEY'
    ]
    
    for key in api_keys:
        value = os.getenv(key)
        if value:
            secrets[key] = value
            print(f"📋 Found {key} in environment")
        else:
            print(f"⚠️  {key} not found in environment")
    
    return secrets

def _setup_secrets_in_aws(region_name: str = 'us-east-1', dry_run: bool = False) -> None:
    """
    Setup secrets in AWS Secrets Manager.
    
    Args:
        region_name: AWS region to create secrets in
        dry_run: If True, only show what would be done without making changes
    """
    print(f"🚀 Setting up secrets in AWS Secrets Manager (region: {region_name})")
    
    if dry_run:
        print("🔍 DRY RUN MODE - No changes will be made")
    
    # Load secrets from .env
    secrets = _load_secrets_from_env()
    
    if not secrets:
        print("❌ No secrets found in .env file")
        return
    
    if dry_run:
        print("\n📋 Would create/update the following secrets:")
        for key, value in secrets.items():
            secret_name = f"prod/{key.lower().replace('_', '/')}"
            print(f"  - {secret_name}: {'***' + value[-4:] if len(value) > 4 else '***'}")
        return
    
    # Initialize AWS Secrets Manager client
    try:
        secrets_client = boto3.client('secretsmanager', region_name=region_name)
        print(f"✅ Connected to AWS Secrets Manager in {region_name}")
    except Exception as e:
        print(f"❌ Failed to connect to AWS Secrets Manager: {e}")
        return
    
    # Mapping of environment variable names to secret names
    secret_mapping = {
        'OPENAI_API_KEY': 'prod/openai/api-key',
        'TAVILY_API_KEY': 'prod/tavily/api-key',
        'JIRA_API_KEY': 'prod/jira/api-key'
    }
    
    success_count = 0
    
    for env_key, secret_value in secrets.items():
        secret_name = secret_mapping.get(env_key)
        if not secret_name:
            print(f"⚠️  No mapping found for {env_key}, skipping...")
            continue
        
        description = f"API key for {env_key.replace('_', ' ').title()} - migrated from .env file"
        
        if _create_or_update_secret(secrets_client, secret_name, secret_value, description):
            success_count += 1
    
    print(f"\n🎉 Successfully processed {success_count}/{len(secrets)} secrets")
    
    if success_count == len(secrets):
        print("\n✅ All secrets migrated successfully!")
        print("🔒 You can now remove the API keys from your .env file")
        print("💡 The application will automatically use Secrets Manager")
    else:
        print(f"\n⚠️  Only {success_count} out of {len(secrets)} secrets were processed successfully")

def _verify_secrets_access(region_name: str = 'us-east-1') -> None:
    """
    Verify that secrets can be accessed from AWS Secrets Manager.
    """
    print(f"🔍 Verifying access to secrets in AWS Secrets Manager (region: {region_name})")
    
    try:
        secrets_client = boto3.client('secretsmanager', region_name=region_name)
        
        secret_names = [
            'prod/openai/api-key',
            'prod/tavily/api-key',
            'prod/jira/api-key'
        ]
        
        for secret_name in secret_names:
            try:
                response = secrets_client.get_secret_value(SecretId=secret_name)
                secret_value = response['SecretString']
                print(f"✅ Can access {secret_name}: {'***' + secret_value[-4:] if len(secret_value) > 4 else '***'}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    print(f"⚠️  Secret {secret_name} not found")
                else:
                    print(f"❌ Failed to access {secret_name}: {e}")
            except Exception as e:
                print(f"❌ Unexpected error accessing {secret_name}: {e}")
                
    except Exception as e:
        print(f"❌ Failed to connect to AWS Secrets Manager: {e}")

def main():
    """Main function with command line interface."""
    parser = argparse.ArgumentParser(
        description="Setup API keys in AWS Secrets Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
    # Show what would be done (dry run)
    python setup_secrets.py --dry-run
    
    # Create/update secrets in us-east-1 (default)
    python setup_secrets.py --setup
    
    # Create/update secrets in specific region
    python setup_secrets.py --setup --region us-west-2
    
    # Verify access to existing secrets
    python setup_secrets.py --verify
"""
    )
    
    parser.add_argument(
        '--setup',
        action='store_true',
        help='Create/update secrets in AWS Secrets Manager'
    )
    
    parser.add_argument(
        '--verify',
        action='store_true', 
        help='Verify access to existing secrets'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    
    parser.add_argument(
        '--region',
        type=str,
        default='us-east-1',
        help='AWS region (default: us-east-1)'
    )
    
    args = parser.parse_args()
    
    if not any([args.setup, args.verify, args.dry_run]):
        parser.print_help()
        return
    
    if args.dry_run:
        _setup_secrets_in_aws(args.region, dry_run=True)
    elif args.setup:
        _setup_secrets_in_aws(args.region, dry_run=False)
    elif args.verify:
        _verify_secrets_access(args.region)

if __name__ == "__main__":
    main()