import os
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient

# Ambil konfigurasi dari environment variables
TENANT_ID = os.getenv("TENANT_ID")
BOT_CLIENT_ID = os.getenv("BOT_CLIENT_ID")
BOT_CLIENT_SECRET = os.getenv("BOT_CLIENT_SECRET")

# Fungsi untuk membuat Graph Service Client
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

# Fungsi untuk mengambil detail user
async def get_user_details(user_upn: str):
    """Mengambil detail user (displayName, department, jobTitle) dari Graph API."""
    graph_client = get_graph_client()
    if not graph_client:
        return {}

    try:
        # hanya memilih field yang dibutuhkan
        query_params = {
            "select": ["displayName", "department", "jobTitle"]
        }
        user = await graph_client.users.by_user_id(user_upn).get(query_params=query_params)

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