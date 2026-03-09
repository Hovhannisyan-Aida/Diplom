from app.db.session import SessionLocal
from app.models.scan import ScanStatus
from app.models.vulnerability import Vulnerability
from app.crud import scan as crud_scan
from app.scanners.sql_injection import SQLInjectionScanner
from app.scanners.security_headers import SecurityHeadersScanner
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def run_vulnerability_scan(scan_id: int):
    """Սկանավորել խոցելիություններ"""
    # Ստեղծել նոր database session այս thread-ի համար
    db = SessionLocal()
    
    try:
        logger.info(f"Starting scan {scan_id}")
        
        # Ստանալ scan-ի տվյալները
        scan = crud_scan.get_scan(db, scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return
        
        # Թարմացնել status-ը IN_PROGRESS
        scan.status = ScanStatus.IN_PROGRESS
        scan.started_at = datetime.utcnow()
        db.commit()
        
        target_url = scan.target_url
        all_vulnerabilities = []
        
        # SQL Injection Scanner
        logger.info(f"Running SQL Injection scan on {target_url}")
        sql_scanner = SQLInjectionScanner(target_url)
        sql_vulns = sql_scanner.scan()
        all_vulnerabilities.extend(sql_vulns)
        
        # Security Headers Scanner
        logger.info(f"Running Security Headers scan on {target_url}")
        headers_scanner = SecurityHeadersScanner(target_url)
        headers_vulns = headers_scanner.scan()
        all_vulnerabilities.extend(headers_vulns)
        
        # Պահպանել խոցելիությունները database-ում
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for vuln_data in all_vulnerabilities:
            vuln = Vulnerability(
                scan_id=scan_id,
                **vuln_data
            )
            db.add(vuln)
            
            # Հաշվել severity-ով
            severity = vuln_data.get("severity")
            if severity == "critical":
                critical_count += 1
            elif severity == "high":
                high_count += 1
            elif severity == "medium":
                medium_count += 1
            elif severity == "low":
                low_count += 1
        
        # Թարմացնել scan-ի արդյունքները
        scan.total_vulnerabilities = len(all_vulnerabilities)
        scan.critical_count = critical_count
        scan.high_count = high_count
        scan.medium_count = medium_count
        scan.low_count = low_count
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        
        # Հաշվել scan-ի տևողությունը
        if scan.started_at and scan.completed_at:
            duration = (scan.completed_at - scan.started_at).total_seconds()
            scan.scan_duration = int(duration)
        
        db.commit()
        
        logger.info(f"Scan {scan_id} completed. Found {len(all_vulnerabilities)} vulnerabilities")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        scan = crud_scan.get_scan(db, scan_id)
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
            
            # Հաշվել տևողությունը failed scan-ի համար էլ
            if scan.started_at and scan.completed_at:
                duration = (scan.completed_at - scan.started_at).total_seconds()
                scan.scan_duration = int(duration)
            
            db.commit()
    
    finally:
        db.close()
