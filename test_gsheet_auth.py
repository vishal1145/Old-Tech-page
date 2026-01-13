import os
import gspread
from oauth2client.service_account import ServiceAccountCredentials

print("Checking for credentials.json...")
if not os.path.exists('credentials.json'):
    print("❌ credentials.json NOT FOUND!")
    exit(1)
print("✅ credentials.json found.")

print("Attempting to authenticate with Google Sheets API...")
try:
    scope = [
        "https://spreadsheets.google.com/feeds",
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive.file",
        "https://www.googleapis.com/auth/drive"
    ]
    creds = ServiceAccountCredentials.from_json_keyfile_name('credentials.json', scope)
    client = gspread.authorize(creds)
    print("✅ Authenticated successfully.")
    
    print("Attempting to add a test tab to the Master Spreadsheet...")
    spreadsheet_id = "1KBllOOa6yIhaC-J1I6sQL74jgwpakCXAkhAZ7lDkx-w"
    sh = client.open_by_key(spreadsheet_id)
    ws = sh.add_worksheet(title="Test_Auth_Tab", rows=10, cols=2)
    print(f"✅ Test tab created! URL: {sh.url}#gid={ws.id}")
    
    # Clean up
    # client.del_spreadsheet(sh.id)
    # print("✅ Test sheet deleted.")
    
except Exception as e:
    print(f"❌ Failed to connect: {e}")
    exit(1)
