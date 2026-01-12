"""
Google Sheets Export Utility Module
Handles exporting diagnosis results to Google Sheets.
"""
import os
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime
import json

# Define scope
SCOPE = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive"
]

# Set Master Spreadsheet ID to bypass service account 0-byte quota
# This sheet must be shared with the service account email
SPREADSHEET_ID = "1KBllOOa6yIhaC-J1I6sQL74jgwpakCXAkhAZ7lDkx-w"

def get_gspread_client():
    """
    Authenticate and return a gspread client.
    Requires 'credentials.json' in the root directory.
    """
    if not os.path.exists('credentials.json'):
        raise FileNotFoundError("credentials.json not found. Please add Google Service Account credentials to the root directory.")
    
    creds = ServiceAccountCredentials.from_json_keyfile_name('credentials.json', SCOPE)
    client = gspread.authorize(creds)
    return client

def create_or_get_sheet(client, title):
    """
    Create a new sheet or get existing one.
    Note: Service accounts create sheets in their own drive. 
    You need to share it with your personal email to see it easily, 
    or we just return the URL.
    """
    try:
        # Try to open existing
        sheet = client.open(title)
        return sheet
    except gspread.SpreadsheetNotFound:
        # Create new
        sheet = client.create(title, folder_id=FOLDER_ID)
        # Make it accessible to anyone with the link (optional, but easier for demo)
        # sheet.share(None, perm_type='anyone', role='reader')
        return sheet

def format_header_row(worksheet):
    """Apply formatting to the header row."""
    worksheet.format('A1:Z1', {
        "backgroundColor": {
            "red": 0.21,
            "green": 0.37,
            "blue": 0.57
        },
        "textFormat": {
            "foregroundColor": {
                "red": 1.0,
                "green": 1.0,
                "blue": 1.0
            },
            "bold": True,
            "fontSize": 11
        },
        "horizontalAlignment": "CENTER"
    })

def export_single_result_to_gsheet(result_data, title=None):
    """
    Export a single diagnosis result to a Google Sheet (tabs in master spreadsheet).
    """
    client = get_gspread_client()
    sh = client.open_by_key(SPREADSHEET_ID)
    
    domain = result_data.get('domain', 'unknown')
    timestamp = datetime.now().strftime('%m%d_%H%M')
    safe_domain = domain.replace('.', '_')[:15]
    prefix = f"{safe_domain}_{timestamp}"
    
    # 1. Overview Tab
    worksheet = sh.add_worksheet(title=f"{prefix}_Overview", rows=20, cols=2)
    
    overview_headers = ["Field", "Value"]
    overview_rows = [
        ["URL", result_data.get('url', 'N/A')],
        ["Domain", result_data.get('domain', 'N/A')],
        ["Technology", result_data.get('tech', 'Unknown')],
        ["Status", result_data.get('status', 'unknown')],
        ["Load Time", result_data.get('load_time', 'N/A')],
        ["FCP (ms)", result_data.get('first_contentful_paint_ms', 'N/A')],
        ["Console Error Count", result_data.get('console_error_count', 0)],
        ["Vulnerability Detected", 'Yes' if result_data.get('vulnerability_detected', False) else 'No'],
        ["Vulnerabilities Count", len(result_data.get('vulnerabilities', []))],
        ["Diagnosis Date", datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
    ]
    
    worksheet.append_row(overview_headers)
    worksheet.append_rows(overview_rows)
    format_header_row(worksheet)
    
    # 2. Technical Observation
    observation = result_data.get('technical_observation')
    if observation:
        ws_obs = sh.add_worksheet(title=f"{prefix}_Tech", rows=10, cols=1)
        ws_obs.append_row(["Technical Observation"])
        ws_obs.append_row([observation])
        format_header_row(ws_obs)

    # 3. Vulnerabilities
    vulnerabilities = result_data.get('vulnerabilities', [])
    if vulnerabilities:
        ws_vuln = sh.add_worksheet(title=f"{prefix}_Vuln", rows=max(len(vulnerabilities)+5, 10), cols=3)
        ws_vuln.append_row(["Type", "Version", "Matched Text"])
        v_rows = [[v.get('type', 'N/A'), v.get('version', 'unknown'), v.get('matched_text', '')[:200]] for v in vulnerabilities]
        ws_vuln.append_rows(v_rows)
        format_header_row(ws_vuln)

    # 4. Console Errors
    console_errors = result_data.get('console_errors', [])
    if console_errors:
        ws_err = sh.add_worksheet(title=f"{prefix}_Errors", rows=max(len(console_errors)+5, 10), cols=2)
        ws_err.append_row(["Error Number", "Error Message"])
        e_rows = [[i, err] for i, err in enumerate(console_errors, 1)]
        ws_err.append_rows(e_rows)
        format_header_row(ws_err)
        
    return f"{sh.url}#gid={worksheet.id}"

def export_bulk_results_to_gsheet(results_list, title=None):
    """
    Export multiple diagnosis results to the master Google Sheet as a new tab.
    """
    client = get_gspread_client()
    sh = client.open_by_key(SPREADSHEET_ID)
    
    timestamp = datetime.now().strftime('%m%d_%H%M%S')
    worksheet = sh.add_worksheet(title=f"Bulk_{timestamp}", rows=len(results_list)+5, cols=11)
    
    headers = [
        "No.", "URL", "Domain", "Technology", "Status", "Load Time", 
        "FCP (ms)", "Console Errors", "Vulnerabilities", 
        "Vulnerability Detected", "Technical Observation"
    ]
    worksheet.append_row(headers)
    
    rows = []
    for idx, result in enumerate(results_list, 1):
        rows.append([
            idx,
            result.get('url', 'N/A'),
            result.get('domain', 'N/A'),
            result.get('tech', 'Unknown'),
            result.get('status', 'unknown'),
            result.get('load_time', 'N/A'),
            result.get('first_contentful_paint_ms', 'N/A'),
            result.get('console_error_count', 0),
            len(result.get('vulnerabilities', [])),
            'Yes' if result.get('vulnerability_detected', False) else 'No',
            result.get('technical_observation', 'N/A')
        ])
    
    if rows:
        worksheet.append_rows(rows)
        
    format_header_row(worksheet)
    return f"{sh.url}#gid={worksheet.id}"

def export_company_list_to_gsheet(results_list, title=None):
    """
    Export all company diagnosis results to the master Google Sheet as a new tab.
    """
    client = get_gspread_client()
    sh = client.open_by_key(SPREADSHEET_ID)
    
    timestamp = datetime.now().strftime('%m%d_%H%M%S')
    worksheet = sh.add_worksheet(title=f"Export_{timestamp}", rows=len(results_list)+5, cols=13)
    
    headers = [
        "Domain", "URL", "Technology", "Status", "Load Time", 
        "FCP (ms)", "Console Errors Count", "Console Errors", 
        "Vulnerabilities Count", "Vulnerabilities", "Vulnerability Detected",
        "Technical Observation", "Diagnosis Date"
    ]
    worksheet.append_row(headers)
    
    rows = []
    for result in results_list:
        # Format vulnerabilities
        vulnerabilities = result.get('vulnerabilities', [])
        vuln_list = ', '.join([f"{v.get('type', 'N/A')} (v{v.get('version', 'unknown')})" 
                              for v in vulnerabilities]) if vulnerabilities else 'None'
        
        # Format console errors
        console_errors = result.get('console_errors', [])
        if console_errors:
            error_summary = []
            for i, error in enumerate(console_errors[:3]):
                truncated_error = error[:100] + '...' if len(error) > 100 else error
                error_summary.append(f"{i+1}. {truncated_error}")
            if len(console_errors) > 3:
                error_summary.append(f"... and {len(console_errors) - 3} more errors")
            console_errors_text = ' | '.join(error_summary)
        else:
            console_errors_text = 'None'
            
        # Date
        diagnosis_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if 'modified' in result:
            try:
                diagnosis_date = datetime.fromtimestamp(result['modified']).strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass
        
        rows.append([
            result.get('domain', 'N/A'),
            result.get('url', 'N/A'),
            result.get('tech', 'Unknown'),
            result.get('status', 'unknown'),
            result.get('load_time', 'N/A'),
            result.get('first_contentful_paint_ms', 'N/A'),
            result.get('console_error_count', 0),
            console_errors_text,
            len(vulnerabilities),
            vuln_list,
            'Yes' if result.get('vulnerability_detected', False) else 'No',
            result.get('technical_observation', 'N/A'),
            diagnosis_date
        ])
        
    if rows:
        worksheet.append_rows(rows)
    
    format_header_row(worksheet)
    return f"{sh.url}#gid={worksheet.id}"
