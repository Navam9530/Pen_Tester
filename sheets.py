import json
import logging
import gspread
from datetime import datetime
from google.oauth2.service_account import Credentials

logger = logging.getLogger(__name__)

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

def authenticate_sheets(service_account_file):
    """authenticate with google sheets"""
    try:
        creds = Credentials.from_service_account_file(service_account_file, scopes=SCOPES)
        client = gspread.authorize(creds)
        logger.info("Successfully authenticated with google sheets")
        return client
    except Exception:
        logger.exception("Failed to authenticate with google sheets")
        return None

def get_or_create_worksheet(spreadsheet, title):
    """get a worksheet by title or create it if it doesn't exist"""
    try:
        worksheet = spreadsheet.worksheet(title)
        return worksheet
    except gspread.WorksheetNotFound:
        worksheet = spreadsheet.add_worksheet(title=title, rows=1000, cols=20)
        return worksheet

def safe_json_dump(data):
    """safely dump data to json string"""
    if data is None:
        return ""
    try:
        return json.dumps(data)
    except (TypeError, ValueError):
        return str(data)

def process_apis_called(data, scan_id):
    """flatten apis_called_when_loaded"""
    apis = data.get("apis_called_when_loaded", [])
    if not apis:
        return []
    
    rows = []
    # Header
    rows.append([
        "scan_id", "method", "url", "path", "query_params", 
        "headers", "payload", "response_status", "response_headers", 
        "response_body", "ingestion_timestamp"
    ])
    
    for api in apis:
        row = [
            scan_id,
            api.get('method', ''),
            api.get('url', ''),
            api.get('path', ''),
            safe_json_dump(api.get('query_params', {})),
            safe_json_dump(api.get('headers', {})),
            safe_json_dump(api.get('payload')),
            str(api.get('response_status', 0)),
            safe_json_dump(api.get('response_headers', {})),
            str(api.get('response_body', ''))[:5000], # Trucate body if too long for a single cell
            datetime.now().isoformat()
        ]
        rows.append(row)
    return rows

def process_api_attacks(data, scan_id):
    """flatten attacks from apis_found_in_source_code"""
    apis = data.get("apis_found_in_source_code", [])
    if not apis:
        return []

    rows = []
    rows.append([
        "scan_id", "api_name", "attack_name", "attack_status", "ingestion_timestamp"
    ])
    
    for api in apis:
        api_name = api.get("api_name", "")
        for attack in api.get("attacks", []):
            rows.append([
                scan_id,
                api_name,
                attack.get("name", ""),
                str(attack.get("status", False)),
                datetime.now().isoformat()
            ])
    return rows

def process_api_vulns(data, scan_id):
    """flatten vulnerabilities from apis_found_in_source_code"""
    apis = data.get("apis_found_in_source_code", [])
    if not apis:
        return []

    rows = []
    rows.append([
        "scan_id", "api_name", "vulnerability_name", "severity", "description", "ingestion_timestamp"
    ])

    for api in apis:
        api_name = api.get("api_name", "")
        for vuln in api.get("vulnerabilities", []):
            rows.append([
                scan_id,
                api_name,
                vuln.get("name", ""),
                str(vuln.get("severity", 0)),
                vuln.get("description", ""),
                datetime.now().isoformat()
            ])
    return rows

def process_sca_vulns(data, scan_id):
    """flatten software_composition_analysis vulnerabilities"""
    sca_files = data.get("software_composition_analysis", [])
    if not sca_files:
        return []

    rows = []
    rows.append([
        "scan_id", "file_name", "vulnerability_name", "severity", "description", "ingestion_timestamp"
    ])
    
    for file_obj in sca_files:
        file_name = file_obj.get("file_name", "")
        for vuln in file_obj.get("vulnerabilities", []):
            rows.append([
                scan_id,
                file_name,
                vuln.get("name", ""),
                str(vuln.get("severity", 0)),
                vuln.get("description", ""),
                datetime.now().isoformat()
            ])
    return rows

def process_scan_metadata(data, scan_id):
    """create mapping for scan_id to website_url"""
    url = data.get("url", "")
    if not url:
        return []
    
    rows = []
    rows.append([
        "scan_id", "website_url", "ingestion_timestamp"
    ])
    rows.append([
        scan_id,
        url,
        datetime.now().isoformat()
    ])
    return rows

def process_report(data, scan_id):
    """process the final report"""
    report_text = data.get("report", "")
    if not report_text:
        return []
    
    rows = []
    rows.append([
        "scan_id", "report_text", "ingestion_timestamp"
    ])
    rows.append([
        scan_id,
        report_text,
        datetime.now().isoformat()
    ])
    return rows

def push_to_sheets(data, spreadsheet_name, service_account_file="service_account.json"):
    """
    Push data to Google Sheets.
    Creates tabs if they don't exist and appends/updates data.
    """
    client = authenticate_sheets(service_account_file)
    if not client:
        logger.error("Skipping Google Sheets push due to authentication failure.")
        return

    try:
        # Try to open existing sheet, or create if not found
        try:
            spreadsheet = client.open(spreadsheet_name)
            logger.info(f"Opened existing spreadsheet: {spreadsheet_name}")
        except gspread.SpreadsheetNotFound:
            # Note: Creating a spreadsheet requires appropriate permissions? 
            # Usually service account needs to create and then share, or user creates and shares.
            # We'll try to create it.
            logger.info(f"Spreadsheet '{spreadsheet_name}' not found. Attempting to create new one.")
            try:
                spreadsheet = client.create(spreadsheet_name)
                logger.info(f"Created new spreadsheet: {spreadsheet_name}.")
            except Exception as create_error:
                if "403" in str(create_error) and "quota" in str(create_error).lower():
                    logger.error(f"Failed to create spreadsheet due to storage quota. \nACTION REQUIRED: Please manually create a Google Sheet named '{spreadsheet_name}' and share it with the 'client_email' found in your 'service_account.json'.")
                    return
                raise create_error

        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Process and upload each dataset
        datasets = {
            "apis_called_when_loaded": process_apis_called(data, scan_id),
            "api_attacks": process_api_attacks(data, scan_id),
            "api_vulnerabilities": process_api_vulns(data, scan_id),
            "sca_vulnerabilities": process_sca_vulns(data, scan_id),
            "scan_reports": process_report(data, scan_id),
            "scan_ids_urls": process_scan_metadata(data, scan_id)
        }

        for sheet_name, rows in datasets.items():
            if not rows:
                continue
            
            ws = get_or_create_worksheet(spreadsheet, sheet_name)
            
            # Check if header exists
            existing_data = ws.get_all_values()
            if not existing_data:
                # Write all rows including header
                ws.append_rows(rows)
            else:
                # Append rows excluding header
                ws.append_rows(rows[1:])
            
            logger.info(f"Updated worksheet: {sheet_name}")

    except Exception:
        logger.exception("Error pushing to Google Sheets")
