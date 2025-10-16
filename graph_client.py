import os
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient  # Import from msgraph SDK

def get_graph_client():
    """
    Initialize and return a GraphServiceClient using credentials from environment variables.
    
    Environment Variables:
    - TENANT_ID: Azure AD Tenant ID
    - BOT_CLIENT_ID: Azure AD Application (Client) ID
    - BOT_CLIENT_SECRET: Azure AD Client Secret
    
    Returns:
    - GraphServiceClient: An instance of the Graph client.
    
    Raises:
    - ValueError: If any required environment variables are missing.
    - Exception: If authentication fails.
    """
    tenant_id = os.getenv("TENANT_ID")
    client_id = os.getenv("BOT_CLIENT_ID")
    client_secret = os.getenv("BOT_CLIENT_SECRET")
    
    if not all([tenant_id, client_id, client_secret]):
        raise ValueError("Missing required environment variables: TENANT_ID, BOT_CLIENT_ID, or BOT_CLIENT_SECRET")
    
    try:
        credential = ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
        client = GraphServiceClient(credentials=credential)
        print("Graph client initialized successfully.")
        return client
    except Exception as e:
        print(f"Error initializing Graph client: {str(e)}")
        raise  # Re-raise for the caller to handle if needed

async def get_user_details(user_upn):
    """
    Asynchronously fetch user details (displayName, department, jobTitle) for the given User Principal Name (UPN).
    
    Args:
    - user_upn (str): The User's Principal Name (e.g., user@example.com).
    
    Returns:
    - dict: A dictionary with keys 'displayName', 'department', and 'jobTitle' if successful.
    - None: If the user is not found or an error occurs.
    
    Prints:
    - Success or failure messages.
    """
    client = get_graph_client()  # Get the client (this is synchronous)
    
    try:
        # Fetch the user with selected fields
        user = await client.users.by_user_id(user_upn).get(select=["displayName", "department", "jobTitle"])
        
        if user:
            print(f"Successfully fetched details for user: {user_upn}")
            return {
                "displayName": getattr(user, 'display_name', None),  # Use getattr for safety
                "department": getattr(user, 'department', None),
                "jobTitle": getattr(user, 'job_title', None)
            }
        else:
            print(f"User {user_upn} not found.")
            return None
    except Exception as e:
        print(f"Error fetching user details for {user_upn}: {str(e)}")
        return None

async def perform_hard_block(user_upn):
    """
    Asynchronously revoke sign-in sessions and disable the user account by setting accountEnabled to False.
    
    Args:
    - user_upn (str): The User's Principal Name (e.g., user@example.com).
    
    Prints:
    - Success messages for each step.
    - Failure messages if an error occurs.
    
    Note: This operation is destructive and should be used with caution.
    """
    client = get_graph_client()  # Get the client (this is synchronous)
    
    try:
        # Step 1: Revoke sign-in sessions
        await client.users.by_user_id(user_upn).revoke_sign_in_sessions().post()
        print(f"Successfully revoked sign-in sessions for user: {user_upn}")
        
        # Step 2: Disable the account
        patch_body = {"accountEnabled": False}
        await client.users.by_user_id(user_upn).patch(patch_body)
        print(f"Successfully disabled the account for user: {user_upn}")
    except Exception as e:
        print(f"Error performing hard block for user {user_upn}: {str(e)}")