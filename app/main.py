import os
import requests
import msal
from fastapi import FastAPI
from pydantic import BaseModel

# --- KONFIGURASI DARI ENVIRONMENT VARIABLES ---
# Membaca konfigurasi yang sudah kamu atur di Azure App Service
TENANT_ID = os.getenv("TENANT_ID")
BOT_CLIENT_ID = os.getenv("BOT_CLIENT_ID")
BOT_CLIENT_SECRET = os.getenv("BOT_CLIENT_SECRET")
GRAPH_TEAM_ID = os.getenv("GRAPH_TEAM_ID")
GRAPH_CHANNEL_ID = os.getenv("GRAPH_CHANNEL_ID")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]

# --- FUNGSI OTENTIKASI (Diperbarui untuk Bot) ---
def get_graph_token():
    """Mendapatkan access token untuk Graph API menggunakan identitas Bot."""
    if not all([TENANT_ID, BOT_CLIENT_ID, BOT_CLIENT_SECRET]):
        print("ERROR: Kredensial Bot tidak diatur dengan benar di App Settings.")
        return None
    
    app_msal = msal.ConfidentialClientApplication(
        client_id=BOT_CLIENT_ID,
        authority=AUTHORITY,
        client_credential=BOT_CLIENT_SECRET
    )
    
    result = app_msal.acquire_token_for_client(scopes=GRAPH_SCOPE)
    
    if "access_token" in result:
        return result['access_token']
    else:
        print(f"Gagal mendapatkan token: {result.get('error_description')}")
        return None

# --- FUNGSI PENGIRIM NOTIFIKASI BARU ---
def send_adaptive_card_to_teams(access_token: str, incident_data: dict):
    """Mengirim notifikasi dalam format Adaptive Card ke channel Teams via Graph API."""
    if not all([GRAPH_TEAM_ID, GRAPH_CHANNEL_ID]):
        print("ERROR: Team ID atau Channel ID tidak diatur di App Settings.")
        return

    graph_url = f"https://graph.microsoft.com/v1.0/teams/{GRAPH_TEAM_ID}/channels/{GRAPH_CHANNEL_ID}/messages"
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    # --- INI ADALAH TEMPLATE ADAPTIVE CARD ---
    # Kamu bisa mendesain kartumu sendiri di https://adaptivecards.io/designer/
    adaptive_card_payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "type": "AdaptiveCard",
                    "version": "1.5",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "🚨 Insiden Keamanan DLP Terdeteksi!",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": "Attention"
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Judul Insiden:", "value": incident_data['title']},
                                {"title": "Pengguna:", "value": incident_data['user']},
                                {"title": "Tingkat Bahaya:", "value": incident_data['severity']}
                            ]
                        }
                    ],
                    # Nanti kita bisa tambahkan tombol interaktif di sini
                    # "actions": [ ... ] 
                }
            }
        ]
    }

    response = requests.post(graph_url, headers=headers, json=adaptive_card_payload)
    
    if response.status_code == 201: # 201 Created
        print("Notifikasi Adaptive Card berhasil dikirim ke Teams.")
    else:
        print(f"Gagal mengirim notifikasi: {response.status_code} - {response.text}")

# --- API UTAMA ---
class IncidentPayload(BaseModel):
    incident_title: str
    user_principal_name: str
    severity: str

app = FastAPI(title="DLP Remediation Engine")

@app.post("/remediate")
def remediate_incident(payload: IncidentPayload):
    print(f"--- Menerima Insiden Baru: {payload.incident_title} ---")
    
    token = get_graph_token()
    
    if token:
        incident_details = {
            "title": payload.incident_title,
            "user": payload.user_principal_name,
            "severity": payload.severity
        }
        send_adaptive_card_to_teams(token, incident_details)
        
        # Di sinilah nanti kamu akan menambahkan logika remediasi utama
        # (seperti memanggil Graph API untuk blokir user, hapus sharing link, dll.)
        print("Logika remediasi akan dijalankan di sini.")
    
    return {"status": "success", "message": "Incident received, notification process initiated."}

@app.get("/")
def read_root():
    return {"status": "OK", "message": "API is running!"}