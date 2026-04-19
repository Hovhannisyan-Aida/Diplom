from app.crud import scan as crud_scan
from app.crud import vulnerability as crud_vulnerability
from app.models.scan import ScanStatus
from app.db.session import SessionLocal
from scanners.sql_injection import SQLInjectionScanner
from scanners.xss_scanner import XSSScanner
from scanners.security_headers import SecurityHeadersScanner
from scanners.crypto_scanner import CryptoScanner
from scanners.csrf_scanner import CSRFScanner
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def run_vulnerability_scan(scan_id: int):
    db = SessionLocal()
    scan = None

    try:
        logger.info(f"STARTING SCAN {scan_id}")

        scan = crud_scan.get_scan(db, scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        scan.status = ScanStatus.in_progress
        scan.started_at = datetime.utcnow()
        db.commit()

        target_url = scan.target_url
        all_vulnerabilities = []
        custom_options = dict(scan.custom_options) if scan.custom_options else {}
        language = custom_options.get('language', 'en')

        if scan.scan_type.value == "quick":
            logger.info(f"Running QUICK scan for {target_url}")
            headers_scanner = SecurityHeadersScanner(target_url, language=language)
            headers_vulns = headers_scanner.scan()
            if headers_vulns:
                all_vulnerabilities.extend(headers_vulns)

        elif scan.scan_type.value == "custom":
            logger.info(f"Running CUSTOM scan for {target_url}")

            if custom_options.get('sql_injection', False):
                logger.info("Running SQL Injection scanner (custom)")
                sql_scanner = SQLInjectionScanner(target_url, language=language)
                sql_vulns = sql_scanner.scan()
                if sql_vulns:
                    all_vulnerabilities.extend(sql_vulns)

            if custom_options.get('xss', False):
                logger.info("Running XSS scanner (custom)")
                xss_scanner = XSSScanner(target_url, language=language)
                xss_vulns = xss_scanner.scan()
                if xss_vulns:
                    all_vulnerabilities.extend(xss_vulns)

            if custom_options.get('security_headers', False):
                logger.info("Running Security Headers scanner (custom)")
                headers_scanner = SecurityHeadersScanner(target_url, language=language)
                headers_vulns = headers_scanner.scan()
                if headers_vulns:
                    all_vulnerabilities.extend(headers_vulns)

            if custom_options.get('crypto', False):
                logger.info("Running Crypto scanner (custom)")
                crypto_scanner = CryptoScanner(target_url, language=language)
                crypto_vulns = crypto_scanner.scan()
                if crypto_vulns:
                    all_vulnerabilities.extend(crypto_vulns)

            if custom_options.get('csrf', False):
                logger.info("Running CSRF scanner (custom)")
                csrf_scanner = CSRFScanner(target_url, language=language)
                csrf_vulns = csrf_scanner.scan()
                if csrf_vulns:
                    all_vulnerabilities.extend(csrf_vulns)

        else:
            logger.info(f"Running FULL scan for {target_url}")

            logger.info("Running SQL Injection scanner")
            sql_scanner = SQLInjectionScanner(target_url, language=language)
            sql_vulns = sql_scanner.scan()
            logger.info(f"SQL found: {len(sql_vulns)}")
            if sql_vulns:
                all_vulnerabilities.extend(sql_vulns)

            logger.info("Running XSS scanner")
            xss_scanner = XSSScanner(target_url, language=language)
            xss_vulns = xss_scanner.scan()
            logger.info(f"XSS found: {len(xss_vulns)}")
            if xss_vulns:
                all_vulnerabilities.extend(xss_vulns)

            logger.info("Running Security Headers scanner")
            headers_scanner = SecurityHeadersScanner(target_url, language=language)
            headers_vulns = headers_scanner.scan()
            logger.info(f"Headers found: {len(headers_vulns)}")
            if headers_vulns:
                all_vulnerabilities.extend(headers_vulns)

            logger.info("Running Crypto scanner")
            crypto_scanner = CryptoScanner(target_url, language=language)
            crypto_vulns = crypto_scanner.scan()
            logger.info(f"Crypto found: {len(crypto_vulns)}")
            if crypto_vulns:
                all_vulnerabilities.extend(crypto_vulns)

            logger.info("Running CSRF scanner")
            csrf_scanner = CSRFScanner(target_url, language=language)
            csrf_vulns = csrf_scanner.scan()
            logger.info(f"CSRF found: {len(csrf_vulns)}")
            if csrf_vulns:
                all_vulnerabilities.extend(csrf_vulns)

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
        logger.info(f"SCAN {scan_id} FINISHED - Found {len(all_vulnerabilities)} vulnerabilities")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        if scan is not None:
            scan.status = ScanStatus.failed
            scan.error_message = "Scan failed due to an internal error."
            scan.completed_at = datetime.utcnow()
            db.commit()

    finally:
        db.close()