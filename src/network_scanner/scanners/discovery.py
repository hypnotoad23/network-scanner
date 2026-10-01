import platform
from typing import List, Optional

from rich.progress import Progress
from scapy.all import ARP, Ether, conf, get_if_hwaddr, srp

from ..core.models import Host
from ..utils.mac_vendor import get_vendor

if platform.system() == "Windows":
    conf.use_pcap = True
conf.sniff_promisc = True


def _get_local_host(target_ip: str, iface: Optional[str] = None) -> Optional[Host]:
    """Определяет IP/MAC собственного ПК на интерфейсе, через который достижима target_ip."""
    try:
        network_addr = target_ip.split("/")[0]
        used_iface, src_ip, _ = conf.route.route(network_addr)
        resolved_iface = iface or used_iface
        mac = get_if_hwaddr(resolved_iface)
        vendor_name = get_vendor(mac)
    except Exception:
        return None

    return Host(ip=src_ip, mac=mac, vendor=vendor_name, is_local=True)


def arp_scan(target_ip: str, timeout: int = 3, iface: Optional[str] = None) -> List[Host]:
    # Выполняет ARP-сканирование подсети.
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    hosts: List[Host] = []

    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=None)
        answered, _ = srp(packet, timeout=timeout, iface=iface, verbose=False)
        progress.update(task, completed=100)

    for _, received in answered:
        ip_addr = received.psrc
        mac_addr = received.hwsrc

        try:
            vendor_name = get_vendor(mac_addr)
        except Exception:
            vendor_name = None

        hosts.append(Host(ip=ip_addr, mac=mac_addr, vendor=vendor_name))

    # ПК  пользователя 
    local_host = _get_local_host(target_ip, iface=iface)
    if local_host:
        existing = next((h for h in hosts if str(h.ip) == str(local_host.ip)), None)
        if existing:
            existing.is_local = True
        else:
            hosts.append(local_host)

    return hosts
