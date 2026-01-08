import logging
from typing import Optional, Dict, Any
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from config import settings
from exceptions import (
    AuthenticationException,
    UserNotFoundException,
    GraphAPIException,
    AccountRevocationException
)
from cache_service import user_cache

logger = logging.getLogger(__name__)


def get_graph_client() -> GraphServiceClient:
    """
    Initialize and return a GraphServiceClient using credentials from settings.

    Returns:
        GraphServiceClient: An instance of the Graph client.

    Raises:
        AuthenticationException: If authentication fails

    Example:
        client = get_graph_client()
        user = await client.users.by_user_id(upn).get()
    """
    try:
        credential = ClientSecretCredential(
            tenant_id=settings.TENANT_ID,
            client_id=settings.BOT_CLIENT_ID,
            client_secret=settings.BOT_CLIENT_SECRET
        )
        client = GraphServiceClient(credentials=credential)
        logger.debug("Graph client initialized successfully")
        return client
    except Exception as e:
        logger.error(f"Failed to initialize Graph client: {e}")
        raise AuthenticationException(
            "Failed to authenticate with Azure AD",
            details={
                "tenant_id": settings.TENANT_ID,
                "error": str(e)
            },
            original_exception=e
        )

async def get_user_details(user_upn: str) -> Optional[Dict[str, Any]]:
    """
    Fetch user details from Microsoft Graph with caching.

    Args:
        user_upn: The User's Principal Name (e.g., user@example.com)

    Returns:
        Dictionary with displayName, department, and jobTitle if found, None otherwise

    Raises:
        GraphAPIException: If Graph API call fails

    Example:
        user = await get_user_details("user@example.com")
        if user:
            print(f"User: {user['displayName']}")
    """
    # Check cache first
    cached = user_cache.get(user_upn)
    if cached:
        logger.debug(f"Cache HIT for user: {user_upn}")
        return cached

    logger.debug(f"Cache MISS for user: {user_upn} - fetching from Graph API")

    client = get_graph_client()

    try:
        # Fetch the user with selected fields
        user = await client.users.by_user_id(user_upn).get(
            select=["displayName", "department", "jobTitle"]
        )

        if user:
            user_details = {
                "displayName": getattr(user, 'display_name', 'Unknown'),
                "department": getattr(user, 'department', 'Unknown'),
                "jobTitle": getattr(user, 'job_title', 'Unknown')
            }

            # Cache the result
            user_cache.set(user_upn, user_details)

            logger.info(f"Successfully fetched details for user: {user_upn}")
            return user_details
        else:
            logger.warning(f"User not found: {user_upn}")
            raise UserNotFoundException(
                f"User not found in Azure AD",
                details={"upn": user_upn}
            )

    except UserNotFoundException:
        raise
    except Exception as e:
        logger.error(f"Error fetching user details for {user_upn}: {e}")
        raise GraphAPIException(
            f"Failed to fetch user details",
            details={"upn": user_upn, "error": str(e)},
            original_exception=e
        )

async def perform_soft_block(user_upn: str) -> bool:
    client = get_graph_client()

    try:
        # Revoke sign-in sessions only (account stays enabled)
        logger.info(f"[SOFT BLOCK] Revoking sign-in sessions for: {user_upn}")
        await client.users.by_user_id(user_upn).revoke_sign_in_sessions.post()
        logger.info(f"[OK] Sign-in sessions revoked for: {user_upn} (account still active)")

        # Clear user from cache
        user_cache.delete(user_upn)

        return True

    except Exception as e:
        logger.error(f"Failed to perform soft block for {user_upn}: {e}")
        raise AccountRevocationException(
            f"Failed to revoke sessions",
            details={
                "upn": user_upn,
                "error": str(e)
            },
            original_exception=e
        )

async def perform_hard_block(user_upn: str) -> bool:
    """
    Revoke sign-in sessions and disable user account (CRITICAL risk - Hard Block).

    This is a destructive operation that:
    1. Revokes all active sign-in sessions
    2. Disables the user account (accountEnabled = False)

    Args:
        user_upn: The User's Principal Name (e.g., user@example.com)

    Returns:
        True if successful

    Raises:
        AccountRevocationException: If revocation fails

    Warning:
        This is a destructive operation. Use with extreme caution.

    Example:
        try:
            success = await perform_hard_block("user@example.com")
            if success:
                logger.info("Account blocked successfully")
        except AccountRevocationException as e:
            logger.error(f"Failed to block account: {e}")
    """
    client = get_graph_client()

    try:
        # Step 1: Revoke sign-in sessions
        logger.info(f"[HARD BLOCK] Revoking sign-in sessions for: {user_upn}")
        await client.users.by_user_id(user_upn).revoke_sign_in_sessions.post()
        logger.info(f"[OK] Sign-in sessions revoked for: {user_upn}")

        # Step 2: Disable the account
        logger.info(f"[HARD BLOCK] Disabling account for: {user_upn}")
        patch_body = {"accountEnabled": False}
        await client.users.by_user_id(user_upn).patch(patch_body)
        logger.info(f"[OK] Account DISABLED for: {user_upn} (cannot re-login)")

        # Clear user from cache (their details are now outdated)
        user_cache.delete(user_upn)

        return True

    except Exception as e:
        logger.error(f"Failed to perform hard block for {user_upn}: {e}")
        raise AccountRevocationException(
            f"Failed to revoke account access",
            details={
                "upn": user_upn,
                "error": str(e)
            },
            original_exception=e
        )