from sqlalchemy.orm import Session
from app.models.scan import Scan, ScanStatus
from app.schemas.scan import ScanCreate
from datetime import datetime

def get_scan(db: Session, scan_id: int):
    return db.query(Scan).filter(Scan.id == scan_id).first()

def get_user_scans(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    return db.query(Scan).filter(Scan.user_id == user_id).offset(skip).limit(limit).all()

def create_scan(db: Session, scan: ScanCreate, user_id: int):
    db_scan = Scan(
        user_id=user_id,
        target_url=scan.target_url,
        scan_type=scan.scan_type,
        status=ScanStatus.pending,
        custom_options=getattr(scan, 'custom_options', None)
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan

def update_scan_status(db: Session, scan_id: int, status: ScanStatus, error_message: str = None):
    scan = get_scan(db, scan_id)
    if scan:
        scan.status = status
        if status == ScanStatus.in_progress:
            scan.started_at = datetime.utcnow()
        elif status in [ScanStatus.completed, ScanStatus.failed]:
            scan.completed_at = datetime.utcnow()
        if error_message:
            scan.error_message = error_message
        db.commit()
        db.refresh(scan)
    return scan
