#!/usr/bin/env python3
"""Utility functions for agent configuration and URL generation."""

import logging
import urllib.parse
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
import boto3
from boto3.session import Session

logger = logging.getLogger(__name__)


def _load_yaml_config(file_path: str) -> Dict[str, Any]:
    """Load YAML configuration from file.
    
    Args:
        file_path: Path to the YAML configuration file
        
    Returns:
        Dictionary containing the loaded configuration
        
    Raises:
        FileNotFoundError: If the config file doesn't exist
        yaml.YAMLError: If the YAML is invalid
    """
    logger.debug(f"Loading YAML configuration from: {file_path}")
    config_path = Path(file_path)
    
    if not config_path.exists():
        logger.error(f"Configuration file not found: {file_path}")
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    
    logger.debug(f"Configuration file exists at: {config_path.absolute()}")
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config_data = yaml.safe_load(f)
    
    logger.debug(f"Configuration loaded successfully. Top-level keys: {list(config_data.keys())}")
    return config_data


def _build_agent_url(agent_arn: str) -> str:
    """Build agent invocation URL from ARN that is generated using agentcore runtime.
    
    Args:
        agent_arn: The Bedrock AgentCore ARN
        
    Returns:
        The HTTP URL for invoking the agent (without /invocations suffix)
    """
    session = Session()
    region = session.region_name or "us-west-2"
    endpoint = f"https://bedrock-agentcore.{region}.amazonaws.com"
    escaped = urllib.parse.quote(agent_arn, safe="")
    return f"{endpoint}/runtimes/{escaped}/invocations?qualifier=DEFAULT"


def _get_client_secret(identity_group: str) -> str:
    """Get OAuth client secret from AWS Secrets Manager using Bedrock AgentCore identity.
    
    Args:
        identity_group: The identity group name (monitoring-agent)
        
    Returns:
        The client secret string
        
    Raises:
        Exception: If client secret cannot be retrieved
    """
    secrets_client = boto3.client('secretsmanager', region_name='us-west-2')
    
    try:
        print(f"Identity group is monitoring, fetching the client secret...")
        # Get client secret from the referenced secrets manager
        # The client secret is stored in Secrets Manager as shown in the provider config
        response = secrets_client.get_secret_value(SecretId=f"bedrock-agentcore-identity!default/oauth2/{identity_group}")
        import json
        secret_data = json.loads(response['SecretString'])
        print(f"Fetched the secrets data from the identity secrets provider: {secret_data}")
        client_secret = secret_data.get('client_secret')
        
        if not client_secret:
            raise Exception("client_secret not found in the secret data")
            
        return client_secret
    except Exception as e:
        raise Exception(
            f"Failed to retrieve client secret for identity group '{identity_group}': {str(e)}. "
            "Please ensure the client secret from the Bedrock AgentCore OAuth provider is stored in "
            f"Secrets Manager under 'bedrock-agentcore-identity!default/oauth2/{identity_group}'"
        )

from urllib.parse import urlparse, urlunparse

def _normalize_cognito_token_endpoint(url: str) -> str:
    """
    Cognito user pool token endpoint must be .../<poolId>/oauth2/token.
    Normalize if discovery returns .../<poolId>/token (rare/misread).
    """
    try:
        p = urlparse(url)
        if p.netloc.startswith("cognito-idp.") and p.path.endswith("/token") and "/oauth2/" not in p.path:
            fixed_path = p.path.replace("/token", "/oauth2/token")
            return urlunparse((p.scheme, p.netloc, fixed_path, "", "", ""))
    except Exception:
        pass
    return url

import requests

def get_token(
    *,
    user_pool_id: str,
    client_id: str,
    client_secret: str,
    scope_string: str,
    region: Optional[str] = None,
    discovery_url: Optional[str] = None,
    timeout: int = 15,
) -> Dict:
    """
    Retrieve an OAuth2 access token from an Amazon Cognito *user pool* using the client_credentials grant.

    Args:
        user_pool_id: e.g., "us-west-2_4tapKqA3u"
        client_id, client_secret: your *confidential* app client credentials
        scope_string: space-separated resource server scopes, e.g.
            "monitoring-agentcore-gateway-id/gateway.read monitoring-agentcore-gateway-id/gateway.write"
        region: optional; if omitted, derived from user_pool_id (before the underscore)
        discovery_url: optional; if provided, takes precedence to fetch token_endpoint
        timeout: request timeout (seconds)

    Returns:
        dict with 'access_token' on success, or {'error': '...'} on failure.
    """
    logger.debug(f"get_token called with:")
    logger.debug(f"  user_pool_id: {user_pool_id}")
    logger.debug(f"  client_id: {client_id}")
    logger.debug(f"  client_secret: {'*' * (len(client_secret) - 4) + client_secret[-4:] if client_secret else 'None'}")
    logger.debug(f"  scope_string: {scope_string}")
    logger.debug(f"  region: {region}")
    logger.debug(f"  discovery_url: {discovery_url}")
    logger.debug(f"  timeout: {timeout}")
    
    try:
        # 1) Determine token endpoint
        token_endpoint: str
        if discovery_url:
            logger.debug(f"Fetching discovery document from: {discovery_url}")
            disc = requests.get(discovery_url, timeout=timeout)
            logger.debug(f"Discovery request status: {disc.status_code}")
            logger.debug(f"Discovery response headers: {dict(disc.headers)}")
            
            if disc.status_code != 200:
                logger.error(f"Discovery request failed with status {disc.status_code}")
                logger.error(f"Response body: {disc.text}")
            
            disc.raise_for_status()
            
            discovery_data = disc.json()
            logger.debug(f"Discovery document keys: {list(discovery_data.keys())}")
            
            token_endpoint = discovery_data.get("token_endpoint", "")
            logger.debug(f"Raw token_endpoint from discovery: {token_endpoint}")
            
            if not token_endpoint:
                logger.error(f"Discovery document missing token_endpoint. Available keys: {list(discovery_data.keys())}")
                return {"error": f"discovery missing token_endpoint at {discovery_url}"}
            
            token_endpoint = _normalize_cognito_token_endpoint(token_endpoint)
            logger.debug(f"Normalized token_endpoint: {token_endpoint}")
        else:
            # Build canonical user-pool endpoint: https://cognito-idp.<region>.amazonaws.com/<poolId>/oauth2/token
            if region is None:
                # Derive region from the pool id prefix (before the underscore)
                if "_" not in user_pool_id:
                    return {"error": f"Cannot derive region from user_pool_id '{user_pool_id}'"}
                region = user_pool_id.split("_", 1)[0]
            token_endpoint = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/oauth2/token"

        logger.debug(f"Final token_endpoint: {token_endpoint}")
        
        form = {
            "grant_type": "client_credentials",
            "scope": scope_string,  # space-separated
        }
        logger.debug(f"OAuth form data: {form}")

        # 2) Try HTTP Basic client authentication (preferred)
        logger.debug("Attempting OAuth token request with HTTP Basic auth")
        resp = requests.post(
            token_endpoint,
            data=form,
            auth=(client_id, client_secret),
            headers={"Accept": "application/json"},
            timeout=timeout,
        )
        logger.debug(f"Token request status: {resp.status_code}")
        logger.debug(f"Token response headers: {dict(resp.headers)}")
        if resp.status_code != 200:
            logger.error(f"Token request failed with status {resp.status_code}")
            logger.error(f"Response body: {resp.text}")

        # 3) If Basic auth fails *specifically* with invalid_client, retry with form-secret style
        if resp.status_code in (400, 401) and ("invalid_client" in resp.text.lower()):
            logger.debug("Retrying with form-based client authentication due to invalid_client error")
            form_with_secret = {
                **form,
                "client_id": client_id,
                "client_secret": client_secret,
            }
            logger.debug(f"Retry form data: {form_with_secret}")
            resp = requests.post(
                token_endpoint,
                data=form_with_secret,
                headers={"Accept": "application/json",
                         "Content-Type": "application/x-www-form-urlencoded"},
                timeout=timeout,
            )
            logger.debug(f"Retry request status: {resp.status_code}")
            if resp.status_code != 200:
                logger.error(f"Retry request failed with status {resp.status_code}")
                logger.error(f"Retry response body: {resp.text}")

        if resp.status_code >= 400:
            error_response = {
                "error": f"{resp.status_code} {resp.text[:512]}",
                "token_endpoint": token_endpoint,
            }
            logger.error(f"Final token request failed: {error_response}")
            return error_response
        
        token_data = resp.json()
        logger.debug(f"Token request successful. Response keys: {list(token_data.keys())}")
        return token_data

    except requests.RequestException as e:
        error_msg = f"Request exception during token fetch: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg}

def get_agent_config(config_file: str = "config.yaml") -> Dict[str, Any]:
    """Get complete agent configuration including URL and credentials.
    
    Args:
        config_file: Path to the configuration file (default: config.yaml)
        
    Returns:
        Dictionary containing:
        - base_url: The agent invocation URL
        - agent_arn: The agent ARN
        - agent_session_id: Session ID (if available)
        - user_pool_id: Cognito User Pool ID
        - client_id: OAuth client ID
        - client_secret: OAuth client secret
        - scope: OAuth scope
        - discovery_url: OAuth discovery URL
        
    Raises:
        Exception: If configuration cannot be loaded or is invalid
    """
    logger.debug(f"get_agent_config called with config_file: {config_file}")
    
    # Load the configuration file
    config = _load_yaml_config(config_file)
    
    # Extract agent card info
    agent_card_info = config.get('agent_card_info', {})
    logger.debug(f"Agent card info: {agent_card_info}")
    
    agent_arn = agent_card_info.get('agent_arn')
    identity_group = agent_card_info.get('identity_group')
    client_id = agent_card_info.get('client_id')
    discovery_url = agent_card_info.get('discovery_url')
    
    logger.debug(f"Extracted values:")
    logger.debug(f"  agent_arn: {agent_arn}")
    logger.debug(f"  identity_group: {identity_group}")
    logger.debug(f"  client_id: {client_id}")
    logger.debug(f"  discovery_url: {discovery_url}")
    
    if not agent_arn:
        logger.error("agent_arn not found in configuration")
        raise ValueError("agent_arn not found in configuration")
    
    if not identity_group:
        logger.error("identity_group not found in configuration")
        raise ValueError("identity_group not found in configuration")
    
    if not client_id:
        logger.error("client_id not found in configuration")
        raise ValueError("client_id not found in configuration")
    
    if not discovery_url:
        logger.error("discovery_url not found in configuration")
        raise ValueError("discovery_url not found in configuration")
    
    # Build the base URL from the ARN
    base_url = _build_agent_url(agent_arn)
    
    # Get client secret from secrets manager
    client_secret = _get_client_secret(identity_group)
    
    # Extract user pool ID from discovery URL
    # Discovery URL format: https://cognito-idp.region.amazonaws.com/user_pool_id/.well-known/openid_configuration
    import re
    logger.debug(f"Attempting to extract user_pool_id from discovery_url: {discovery_url}")
    logger.debug(f"Discovery URL type: {type(discovery_url)}")
    logger.debug(f"Discovery URL repr: {repr(discovery_url)}")
    
    user_pool_match = re.search(r'/([^/]+)/\.well-known/openid_configuration', discovery_url)
    logger.debug(f"Regex match result: {user_pool_match}")
    
    if not user_pool_match:
        # Try alternative patterns
        user_pool_match = re.search(r'amazonaws\.com/([^/]+)/\.well-known', discovery_url)
        logger.debug(f"Alternative regex match result: {user_pool_match}")
    
    if not user_pool_match:
        raise ValueError(f"Unable to extract user_pool_id from discovery_url: {discovery_url}")
    user_pool_id = user_pool_match.group(1)
    
    # Default scope for monitoring agent gateway access
    scope = f"monitoring-agentcore-gateway-id/gateway.read monitoring-agentcore-gateway-id/gateway.write"
    
    # Generate a session ID that meets the minimum 33 character requirement
    import uuid
    session_uuid = str(uuid.uuid4()).replace('-', '')[:8]
    agent_session_id = f"session-{identity_group}-{session_uuid}"
    
    return {
        'base_url': base_url,
        'agent_arn': agent_arn,
        'agent_session_id': agent_session_id,
        'user_pool_id': user_pool_id,
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': scope,
        'discovery_url': discovery_url
    }