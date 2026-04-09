from scapy.all import ARP, Ether, srp
from rich.progress import Progress
from typing import List

from ..core.models import Host
from ..utils.mac_vendor import get_vendor

def arp_scan(target_ip: str, timeout: int = 3) -> List[Host]:
    """
       Performs an ARP scan of the subnet.
              The fastest and most reliable way to detect devices 
        on a local network.       
    """
    
    #Create an ARP request
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    
    hosts: List[Host] = []

    #Send packets and wait for responses
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=100)
        answered, _ = srp(packet, timeout=timeout, verbose=False)
        progress.update(task, advance=100)

    for _, received in answered:
        ip_addr = received.psrc
        mac_addr = received.hwsrc.upper()
        
        vendor_name = get_vendor(mac_addr)

        hosts.append(Host(
            ip=ip_addr,
            mac=mac_addr,
            vendor=vendor_name
        ))

    print(f"[+] Devices found: {len(hosts)}")
    return hosts
