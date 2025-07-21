#!/usr/bin/env python3
"""
Script to delete all Amazon Bedrock AgentCore Gateways in your AWS account.
WARNING: This will permanently delete all gateways. Use with caution.
"""

import boto3
import sys
from botocore.exceptions import ClientError, BotoCoreError
import argparse
import time

def list_all_gateways(client, region_name=None):
    """
    List all gateways in the account
    """
    try:
        print(f"🔍 Listing gateways in region: {region_name or client._client_config.region_name}")
        
        # Use direct API calls instead of paginator since the response structure is known
        gateways = []
        next_token = None
        
        while True:
            kwargs = {'maxResults': 50}  # Maximum allowed per API spec
            if next_token:
                kwargs['nextToken'] = next_token
            
            response = client.list_gateways(**kwargs)
            
            # The response uses 'items' not 'gateways'
            if 'items' in response:
                gateways.extend(response['items'])
            
            # Check for pagination
            next_token = response.get('nextToken')
            if not next_token:
                break
        
        print(f"📊 Found {len(gateways)} gateways")
        
        for gateway in gateways:
            print(f"  - Gateway ID: {gateway.get('gatewayId', 'N/A')}")
            print(f"    Name: {gateway.get('name', 'N/A')}")
            print(f"    Status: {gateway.get('status', 'N/A')}")
            print(f"    Protocol Type: {gateway.get('protocolType', 'N/A')}")
            print(f"    Authorizer Type: {gateway.get('authorizerType', 'N/A')}")
            print(f"    Description: {gateway.get('description', 'N/A')}")
            print(f"    Created: {gateway.get('createdAt', 'N/A')}")
            print(f"    Updated: {gateway.get('updatedAt', 'N/A')}")
            print()
        
        return gateways
    
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        print(f"❌ Error listing gateways: {error_code} - {str(e)}")
        return []
    except Exception as e:
        print(f"❌ Unexpected error listing gateways: {str(e)}")
        return []

def delete_gateway(client, gateway_id, force=False):
    """
    Delete a single gateway
    """
    try:
        print(f"🗑️  Deleting gateway: {gateway_id}")
        
        # The API uses 'gatewayIdentifier' not 'gatewayId'
        kwargs = {
            'gatewayIdentifier': gateway_id
        }
        
        # Some APIs have a force/skip parameter for deletion
        if force:
            # Try common parameter names for force deletion
            for param_name in ['force', 'forceDelete', 'skipResourceInUseCheck']:
                try:
                    kwargs[param_name] = True
                    break
                except:
                    continue
        
        response = client.delete_gateway(**kwargs)
        print(f"✅ Successfully initiated deletion of gateway: {gateway_id}")
        return True
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        if error_code == 'ConflictException' or 'in use' in error_message.lower():
            print(f"⚠️  Gateway {gateway_id} is in use. Try with --force flag if available.")
        elif error_code == 'ResourceNotFoundException':
            print(f"⚠️  Gateway {gateway_id} not found (may have been already deleted)")
        else:
            print(f"❌ Error deleting gateway {gateway_id}: {error_code} - {error_message}")
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error deleting gateway {gateway_id}: {str(e)}")
        return False

def delete_all_gateways_in_region(region_name, force=False, dry_run=False):
    """
    Delete all gateways in a specific region
    """
    try:
        print(f"\n🌍 Processing region: {region_name}")
        client = boto3.client('bedrock-agentcore-control', region_name=region_name)
        
        # List all gateways
        gateways = list_all_gateways(client, region_name)
        
        if not gateways:
            print(f"✅ No gateways found in {region_name}")
            return True
        
        if dry_run:
            print(f"🧪 DRY RUN: Would delete {len(gateways)} gateways in {region_name}")
            return True
        
        # Confirm deletion
        if not force:
            response = input(f"\n⚠️  Are you sure you want to delete {len(gateways)} gateways in {region_name}? (yes/no): ")
            if response.lower() not in ['yes', 'y']:
                print("❌ Deletion cancelled")
                return False
        
        # Delete each gateway
        deleted_count = 0
        failed_count = 0
        
        for gateway in gateways:
            gateway_id = gateway.get('gatewayId')
            if gateway_id:
                if delete_gateway(client, gateway_id, force):
                    deleted_count += 1
                else:
                    failed_count += 1
                
                # Small delay to avoid rate limiting
                time.sleep(0.1)
        
        print(f"\n📊 Summary for {region_name}:")
        print(f"  ✅ Successfully deleted: {deleted_count}")
        print(f"  ❌ Failed to delete: {failed_count}")
        
        return failed_count == 0
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == 'OptInRequired':
            print(f"⚠️  Bedrock AgentCore is not available in region {region_name}")
        else:
            print(f"❌ Error accessing region {region_name}: {error_code} - {str(e)}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error in region {region_name}: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Delete all Amazon Bedrock AgentCore Gateways",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List gateways without deleting (dry run)
  python delete_bedrock_gateways.py --dry-run

  # Delete all gateways in current region with confirmation
  python delete_bedrock_gateways.py

  # Force delete all gateways in specific region
  python delete_bedrock_gateways.py --region us-east-1 --force

  # Delete gateways in multiple regions
  python delete_bedrock_gateways.py --regions us-east-1,us-west-2 --force

WARNING: This script will permanently delete gateways. Use with caution!
        """
    )
    
    parser.add_argument('--region', type=str, 
                       help='Specific AWS region (default: current session region)')
    parser.add_argument('--regions', type=str,
                       help='Comma-separated list of regions to process')
    parser.add_argument('--all-regions', action='store_true',
                       help='Process all available regions')
    parser.add_argument('--force', action='store_true',
                       help='Skip confirmation prompts and force deletion')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be deleted without actually deleting')
    
    args = parser.parse_args()
    
    # Determine regions to process
    regions_to_process = []
    
    if args.all_regions:
        # Get all regions where Bedrock AgentCore might be available
        ec2 = boto3.client('ec2')
        all_regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
        # AgentCore is currently available in limited regions
        bedrock_regions = ['us-east-1', 'us-west-2', 'ap-southeast-2', 'eu-central-1']
        regions_to_process = [r for r in bedrock_regions if r in all_regions]
    elif args.regions:
        regions_to_process = [r.strip() for r in args.regions.split(',')]
    elif args.region:
        regions_to_process = [args.region]
    else:
        # Use current session region
        session = boto3.Session()
        regions_to_process = [session.region_name or 'us-east-1']
    
    print("🚀 Amazon Bedrock AgentCore Gateway Deletion Script")
    print("=" * 55)
    
    if args.dry_run:
        print("🧪 DRY RUN MODE - No actual deletions will be performed")
    
    print(f"📍 Regions to process: {', '.join(regions_to_process)}")
    
    if not args.dry_run and not args.force:
        print("\n⚠️  WARNING: This will permanently delete ALL gateways!")
        response = input("Are you absolutely sure you want to continue? (type 'DELETE' to confirm): ")
        if response != 'DELETE':
            print("❌ Operation cancelled")
            sys.exit(0)
    
    # Process each region
    success_regions = []
    failed_regions = []
    
    for region in regions_to_process:
        try:
            if delete_all_gateways_in_region(region, args.force, args.dry_run):
                success_regions.append(region)
            else:
                failed_regions.append(region)
        except KeyboardInterrupt:
            print("\n❌ Operation cancelled by user")
            break
        except Exception as e:
            print(f"❌ Fatal error processing {region}: {str(e)}")
            failed_regions.append(region)
    
    # Final summary
    print("\n" + "=" * 55)
    print("📊 FINAL SUMMARY")
    print("=" * 55)
    
    if success_regions:
        print(f"✅ Successfully processed regions: {', '.join(success_regions)}")
    
    if failed_regions:
        print(f"❌ Failed regions: {', '.join(failed_regions)}")
    
    if args.dry_run:
        print("🧪 This was a dry run - no actual deletions were performed")
    
    print("\n✨ Script completed")

if __name__ == "__main__":
    main()