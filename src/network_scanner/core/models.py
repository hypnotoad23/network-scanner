from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import List, Optional, Union

from pydantic import BaseModel, Field, computed_field, field_validator

MAC_PATTERN = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"


class Host(BaseModel):
    # обнаруженное в сети устройство

    ip: Union[IPv4Address, IPv6Address]
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    ttl: Optional[int] = Field(default=None, ge=0, le=255)
    open_ports: List[int] = Field(default_factory=list)
    is_local: bool = False
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("mac")
    @classmethod
    def normalize_mac(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip().lower()
        import re

        if not re.match(MAC_PATTERN, v):
            raise ValueError(f"Invalid MAC address format: {v}")
        return v

    @field_validator("open_ports")
    @classmethod
    def validate_ports(cls, ports: List[int]) -> List[int]:
        for port in ports:
            if not (0 <= port <= 65535):
                raise ValueError(f"Invalid port number: {port}")
        return ports


class ScanResult(BaseModel):
    # Результат сканирования сети

    network: Union[IPv4Network, IPv6Network]
    hosts: List[Host] = Field(default_factory=list)
    scan_time: float = 0.0

    @computed_field
    @property
    def total_hosts(self) -> int:
        return len(self.hosts)
