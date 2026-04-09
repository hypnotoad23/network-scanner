from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timezone

class Host(BaseModel):
    """Model of one detected device on the network"""
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    ttl: Optional[int] = None
    open_ports: List[int] = Field(default_factory=list)
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ScanResult(BaseModel):
    """The result of a full network scan"""
    network: str
    hosts: List[Host] = Field(default_factory=list)
    scan_time: float = 0.0
    total_hosts: int = 0
