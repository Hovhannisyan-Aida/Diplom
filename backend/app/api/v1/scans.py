from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List
from app.db.session import get_db
from app.schemas.scan import ScanCreate, ScanInDB
from app.schemas.user import UserInDB
from app.schemas.vulnerability import VulnerabilityInDB
from app.crud import scan as crud_scan
from app.api.v1.auth import get_current_user
from app.models.scan import ScanStatus
from app.tasks.scan_tasks import run_vulnerability_scan
from app.models.vulnerability import Vulnerability

router = APIRouter()

@router.post("/", response_model=ScanInDB, status_code=status.HTTP_201_CREATED)
def create_scan(scan: ScanCreate,
                db: Session = Depends(get_db),
                current_user: UserInDB = Depends(get_current_user)):
    """Նոր սկան ստեղծել և սկսել"""
    db_scan = crud_scan.create_scan(db=db, scan=scan, user_id=current_user.id)
    
    # SYNCHRONOUS - ուղղակի run անենք (testing-ի համար)
    print(f"STARTING SCAN {db_scan.id}")
    run_vulnerability_scan(db_scan.id)
    print(f"SCAN {db_scan.id} FINISHED")
    
    # Վերցնել թարմացված scan-ը
    db.refresh(db_scan)
    
    return db_scan

@router.get("/", response_model=List[ScanInDB])
def get_user_scans(db: Session = Depends(get_db),
                   current_user: UserInDB = Depends(get_current_user)):
    """Օգտատիրոջ բոլոր սկանները"""
    scans = crud_scan.get_user_scans(db, user_id=current_user.id)
    return scans

@router.get("/{scan_id}", response_model=ScanInDB)
def get_scan(scan_id: int,
             db: Session = Depends(get_db),
             current_user: UserInDB = Depends(get_current_user)):
    """Ստանալ scan ID-ով"""
    scan = crud_scan.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    _ = scan.vulnerabilities
    
    return scan

@router.get("/{scan_id}/vulnerabilities", response_model=List[VulnerabilityInDB])
def get_scan_vulnerabilities(scan_id: int,
                              db: Session = Depends(get_db),
                              current_user: UserInDB = Depends(get_current_user)):
    """Scan-ի բոլոր խոցելիությունները"""
    # Ստուգել scan-ը գոյություն ունի և պատկանում է user-ին
    scan = crud_scan.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Վերադարձնել vulnerability-ները
    vulnerabilities = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan_id
    ).all()
    
    return vulnerabilities

@router.get("/{scan_id}/export", response_class=JSONResponse)
def export_scan_vulnerabilities(scan_id: int,
                                 db: Session = Depends(get_db),
                                 current_user: UserInDB = Depends(get_current_user)):
    """Export scan vulnerabilities as JSON"""
    # Ստուգել scan-ը գոյություն ունի և պատկանում է user-ին
    scan = crud_scan.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Ստանալ vulnerability-ները
    vulnerabilities = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan_id
    ).all()
    
    # Ստեղծել export data
    export_data = {
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "scan_type": scan.scan_type.value,
        "status": scan.status.value,
        "created_at": scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "scan_duration": scan.scan_duration,
        "total_vulnerabilities": scan.total_vulnerabilities,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "vulnerabilities": [
            {
                "id": v.id,
                "vuln_type": v.vuln_type,
                "severity": v.severity.value,
                "title": v.title,
                "description": v.description,
                "url": v.url,
                "parameter": v.parameter,
                "method": v.method,
                "payload": v.payload,
                "evidence": v.evidence,
                "recommendation": v.recommendation,
                "references": v.references,
                "created_at": v.created_at.isoformat()
            }
            for v in vulnerabilities
        ]
    }
    
    return JSONResponse(
        content=export_data,
        headers={
            "Content-Disposition": f"attachment; filename=scan_{scan_id}_vulnerabilities.json"
        }
    )

@router.get("/statistics/summary")
def get_user_statistics(db: Session = Depends(get_db),
                        current_user: UserInDB = Depends(get_current_user)):
    """Օգտատիրոջ scan-ների վիճակագրություն"""
    # Ստանալ user-ի բոլոր scans-ները
    scans = crud_scan.get_user_scans(db, user_id=current_user.id)
    
    # Հաշվել վիճակագրություն
    total_scans = len(scans)
    completed_scans = len([s for s in scans if s.status == ScanStatus.completed])
    failed_scans = len([s for s in scans if s.status == ScanStatus.failed])
    in_progress_scans = len([s for s in scans if s.status == ScanStatus.in_progress])
    
    total_vulnerabilities = sum(s.total_vulnerabilities for s in scans)
    total_critical = sum(s.critical_count for s in scans)
    total_high = sum(s.high_count for s in scans)
    total_medium = sum(s.medium_count for s in scans)
    total_low = sum(s.low_count for s in scans)
    
    # Միջին scan duration
    completed_with_duration = [s for s in scans if s.status == ScanStatus.completed and s.scan_duration]
    avg_duration = None
    if completed_with_duration:
        avg_duration = sum(s.scan_duration for s in completed_with_duration) / len(completed_with_duration)
    
    # Վերջին 5 scans
    recent_scans = sorted(scans, key=lambda x: x.created_at, reverse=True)[:5]
    
    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "in_progress_scans": in_progress_scans,
        "total_vulnerabilities": total_vulnerabilities,
        "vulnerabilities_by_severity": {
            "critical": total_critical,
            "high": total_high,
            "medium": total_medium,
            "low": total_low
        },
        "average_scan_duration": round(avg_duration, 2) if avg_duration else None,
        "recent_scans": [
            {
                "id": s.id,
                "target_url": s.target_url,
                "status": s.status.value,
                "created_at": s.created_at.isoformat(),
                "total_vulnerabilities": s.total_vulnerabilities
            }
            for s in recent_scans
        ]
    }