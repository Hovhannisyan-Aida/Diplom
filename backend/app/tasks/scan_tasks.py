from app.crud import scan as crud_scan
from app.crud import vulnerability as crud_vulnerability
from app.models.scan import ScanStatus
from app.db.session import SessionLocal
from scanners.sql_injection import SQLInjectionScanner
from scanners.xss_scanner import XSSScanner
from scanners.security_headers import SecurityHeadersScanner
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def run_vulnerability_scan(scan_id: int):
    """Run vulnerability scan based on scan type"""
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
        
        # CRITICAL: Check scan type and run appropriate scanners
        if scan.scan_type.value == "quick":
            # QUICK SCAN - Security Headers ONLY
            logger.info(f"Running QUICK scan (Headers only) for scan {scan_id}")
            
            headers_scanner = SecurityHeadersScanner(target_url)
            headers_vulns = headers_scanner.scan()
            if headers_vulns:
                all_vulnerabilities.extend(headers_vulns)
                logger.info(f"Quick scan found {len(headers_vulns)} header vulnerabilities")
        
        elif scan.scan_type.value == "custom":
            # CUSTOM SCAN - Based on user selection
            logger.info(f"Running CUSTOM scan for scan {scan_id}")
            
            custom_options = scan.custom_options or {}
            
            if custom_options.get('sql_injection', False):
                logger.info("Running SQL Injection scanner (custom)")
                sql_scanner = SQLInjectionScanner(target_url)
                sql_vulns = sql_scanner.scan()
                if sql_vulns:
                    all_vulnerabilities.extend(sql_vulns)
            
            if custom_options.get('xss', False):
                logger.info("Running XSS scanner (custom)")
                xss_scanner = XSSScanner(target_url)
                xss_vulns = xss_scanner.scan()
                if xss_vulns:
                    all_vulnerabilities.extend(xss_vulns)
            
            if custom_options.get('security_headers', False):
                logger.info("Running Security Headers scanner (custom)")
                headers_scanner = SecurityHeadersScanner(target_url)
                headers_vulns = headers_scanner.scan()
                if headers_vulns:
                    all_vulnerabilities.extend(headers_vulns)
        
        else:
            # FULL SCAN - All scanners
            logger.info(f"Running FULL scan for scan {scan_id}")
            
            # SQL Injection Scanner
            logger.info("Running SQL Injection scanner (full)")
            sql_scanner = SQLInjectionScanner(target_url)
            sql_vulns = sql_scanner.scan()
            if sql_vulns:
                all_vulnerabilities.extend(sql_vulns)
            
            # XSS Scanner
            logger.info("Running XSS scanner (full)")
            xss_scanner = XSSScanner(target_url)
            xss_vulns = xss_scanner.scan()
            if xss_vulns:
                all_vulnerabilities.extend(xss_vulns)
            
            # Security Headers Scanner
            logger.info("Running Security Headers scanner (full)")
            headers_scanner = SecurityHeadersScanner(target_url)
            headers_vulns = headers_scanner.scan()
            if headers_vulns:
                all_vulnerabilities.extend(headers_vulns)
        
        # Save vulnerabilities to database
        for vuln_data in all_vulnerabilities:
            crud_vulnerability.create_vulnerability(
                db,
                scan_id=scan_id,
                vuln_data=vuln_data
            )
        
        # Update scan status
        scan.status = ScanStatus.completed
        scan.completed_at = datetime.utcnow()
        scan.scan_duration = (scan.completed_at - scan.started_at).seconds
        
        # Update vulnerability counts
        scan.total_vulnerabilities = len(all_vulnerabilities)
        scan.critical_count = sum(1 for v in all_vulnerabilities if v.get('severity') == 'critical')
        scan.high_count = sum(1 for v in all_vulnerabilities if v.get('severity') == 'high')
        scan.medium_count = sum(1 for v in all_vulnerabilities if v.get('severity') == 'medium')
        scan.low_count = sum(1 for v in all_vulnerabilities if v.get('severity') == 'low')
        
        db.commit()
        logger.info(f"SCAN {scan_id} FINISHED - Type: {scan.scan_type.value}, Found {len(all_vulnerabilities)} vulnerabilities")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        scan.status = ScanStatus.failed
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        db.commit()
    
    finally:
        db.close()