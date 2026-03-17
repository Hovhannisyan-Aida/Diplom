from app.crud import scan as crud_scan
from app.crud import vulnerability as crud_vulnerability
from app.models.scan import ScanStatus
from app.db.session import SessionLocal
from scanners.sql_injection import SQLInjectionScanner
from scanners.xss_scanner import XSSScanner
from scanners.security_headers import SecurityHeadersScanner
from scanners.crypto_scanner import CryptoScanner
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, force=True)
logger = logging.getLogger(__name__)

def run_vulnerability_scan(scan_id: int):
    db = SessionLocal()
    scan = None

    try:
        print(f"STARTING SCAN {scan_id}", flush=True)
        
        scan = crud_scan.get_scan(db, scan_id)
        if not scan:
            print(f"Scan {scan_id} not found", flush=True)
            return
        
        scan.status = ScanStatus.in_progress
        scan.started_at = datetime.utcnow()
        db.commit()
        
        target_url = scan.target_url
        all_vulnerabilities = []
        custom_options = dict(scan.custom_options) if scan.custom_options else {}
        language = custom_options.get('language', 'en')

        if scan.scan_type.value == "quick":
            print(f"Running QUICK scan for {target_url}", flush=True)
            headers_scanner = SecurityHeadersScanner(target_url, language=language)
            headers_vulns = headers_scanner.scan()
            if headers_vulns:
                all_vulnerabilities.extend(headers_vulns)

        elif scan.scan_type.value == "custom":
            print(f"Running CUSTOM scan for {target_url}", flush=True)

            if custom_options.get('sql_injection', False):
                print("Running SQL Injection scanner (custom)", flush=True)
                sql_scanner = SQLInjectionScanner(target_url, language=language)
                sql_vulns = sql_scanner.scan()
                if sql_vulns:
                    all_vulnerabilities.extend(sql_vulns)

            if custom_options.get('xss', False):
                print("Running XSS scanner (custom)", flush=True)
                xss_scanner = XSSScanner(target_url, language=language)
                xss_vulns = xss_scanner.scan()
                if xss_vulns:
                    all_vulnerabilities.extend(xss_vulns)

            if custom_options.get('security_headers', False):
                print("Running Security Headers scanner (custom)", flush=True)
                headers_scanner = SecurityHeadersScanner(target_url, language=language)
                headers_vulns = headers_scanner.scan()
                if headers_vulns:
                    all_vulnerabilities.extend(headers_vulns)

            if custom_options.get('crypto', False):
                print("Running Crypto scanner (custom)", flush=True)
                crypto_scanner = CryptoScanner(target_url, language=language)
                crypto_vulns = crypto_scanner.scan()
                if crypto_vulns:
                    all_vulnerabilities.extend(crypto_vulns)

        else:
            print(f"Running FULL scan for {target_url}", flush=True)

            print("Running SQL Injection scanner", flush=True)
            sql_scanner = SQLInjectionScanner(target_url, language=language)
            sql_vulns = sql_scanner.scan()
            print(f"SQL found: {len(sql_vulns)}", flush=True)
            if sql_vulns:
                all_vulnerabilities.extend(sql_vulns)

            print("Running XSS scanner", flush=True)
            xss_scanner = XSSScanner(target_url, language=language)
            xss_vulns = xss_scanner.scan()
            print(f"XSS found: {len(xss_vulns)}", flush=True)
            if xss_vulns:
                all_vulnerabilities.extend(xss_vulns)

            print("Running Security Headers scanner", flush=True)
            headers_scanner = SecurityHeadersScanner(target_url, language=language)
            headers_vulns = headers_scanner.scan()
            print(f"Headers found: {len(headers_vulns)}", flush=True)
            if headers_vulns:
                all_vulnerabilities.extend(headers_vulns)

            print("Running Crypto scanner", flush=True)
            crypto_scanner = CryptoScanner(target_url, language=language)
            crypto_vulns = crypto_scanner.scan()
            print(f"Crypto found: {len(crypto_vulns)}", flush=True)
            if crypto_vulns:
                all_vulnerabilities.extend(crypto_vulns)
        
        for vuln_data in all_vulnerabilities:
            crud_vulnerability.create_vulnerability(db, scan_id=scan_id, vuln_data=vuln_data)
        
        scan.status = ScanStatus.completed
        scan.completed_at = datetime.utcnow()
        scan.scan_duration = (scan.completed_at - scan.started_at).seconds
        scan.total_vulnerabilities = len(all_vulnerabilities)
        scan.critical_count = sum(1 for v in all_vulnerabilities if v.get('severity') == 'critical')
        scan.high_count = sum(1 for v in all_vulnerabilities if v.get('severity') == 'high')
        scan.medium_count = sum(1 for v in all_vulnerabilities if v.get('severity') == 'medium')
        scan.low_count = sum(1 for v in all_vulnerabilities if v.get('severity') == 'low')
        
        db.commit()
        print(f"SCAN {scan_id} FINISHED - Found {len(all_vulnerabilities)} vulnerabilities", flush=True)
        
    except Exception as e:
        print(f"Scan {scan_id} failed: {str(e)}", flush=True)
        if scan is not None:
            scan.status = ScanStatus.failed
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
            db.commit()
    
    finally:
        db.close()