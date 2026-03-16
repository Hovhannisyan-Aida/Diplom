from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List
from app.models.scan import ScanStatus
from app.schemas.vulnerability import VulnerabilityInDB

class ScanBase(BaseModel):
    target_url: str
    scan_type: Optional[str] = "full"
    custom_options: Optional[dict] = None

class ScanCreate(ScanBase):
    pass

class ScanInDB(ScanBase):
    id: int
    user_id: int
    status: ScanStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_duration: Optional[int] = None
    error_message: Optional[str] = None
    custom_options: Optional[dict] = None
    vulnerabilities: List[VulnerabilityInDB] = []
    
    class Config:
        from_attributes = True