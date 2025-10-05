import os
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.users.item.user_item_request_builder import UserItemRequestBuilder

TENANT_ID = os.getenv("TENANT_ID")
BOT_CLIENT_ID = os.getenv("BOT_CLIENT_ID")
BOT_CLIENT_SECRET = os.getenv("BOT_CLIENT_SECRET")

def get_graph_client():
    if not all([TENANT_ID, BOT_CLIENT_ID, BOT_CLIENT_SECRET]):
        print("ERROR: Kredensial Bot tidak diatur di Environment Variables.")
        return None
    
    credential = ClientSecretCredential(
        tenant_id=TENANT_ID,
        client_id=BOT_CLIENT_ID,
        client_secret=BOT_CLIENT_SECRET
    )
    return GraphServiceClient(credentials=credential, scopes=['https://graph.microsoft.com/.default'])


async def get_user_details(user_upn: str):
    """Mengambil detail user (displayName, department, jobTitle) dari Graph API."""
    graph_client = get_graph_client()
    if not graph_client:
        return {}
    
    try:
        
        query_params = UserItemRequestBuilder.UserItemRequestBuilderGetQueryParameters(
            select=["displayName", "department", "jobTitle"],
        )
        request_configuration = UserItemRequestBuilder.UserItemRequestBuilderGetRequestConfiguration(
            query_parameters=query_params,
        )
        
        user = await graph_client.users.by_user_id(user_upn).get(request_configuration=request_configuration)
        
        if user:
            return {
                "displayName": user.display_name,
                "department": user.department,
                "jobTitle": user.job_title
            }
        return {}
    except Exception as e:
        print(f"Error saat mengambil detail user {user_upn}: {str(e)}")
        return {}