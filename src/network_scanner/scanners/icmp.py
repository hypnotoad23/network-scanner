import platform
from typing import List, Optional

from rich.progress import Progress
from scapy.all import ICMP, IP, conf, sr

from ..core.exception import ScanPermissionError
from ..core.models import Host
from .fingerprint import get_os_guess

if platform.system() == "Windows":
    conf.use_pcap = True


def icmp_scan(target_ips: List[str], timeout: int = 2) -> List[Host]:
    """
    Выполняет ICMP-сканирование (ping) конкретного списка IP-адресов.

    В отличие от arp_scan, не сканирует всю подсеть "вслепую" — ожидается,
    что список target_ips уже получен от arp_scan. Это избавляет от повторного
    ARP-резолвинга для каждого хоста и от долгого ожидания ответа от сотен
    несуществующих адресов в подсети.

    Используется для получения TTL и грубого определения ОС хоста
    (см. fingerprint.get_os_guess). MAC-адрес здесь не определяется —
    за это отвечает arp_scan.
    """
    if not target_ips:
        return []

    packets = IP(dst=target_ips) / ICMP()

    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]ICMP scanning...", total=None)
            answered, _ = sr(packets, timeout=timeout, verbose=False)
            progress.update(task, completed=100)
    except PermissionError as e:
        raise ScanPermissionError(
            "Недостаточно прав для отправки ICMP-пакетов. "
            "Запустите с sudo (Linux) или от администратора (Windows)."
        ) from e

    hosts: List[Host] = []
    for _, received in answered:
        ttl = received.ttl
        hosts.append(
            Host(
                ip=received.src,
                ttl=ttl,
                os_guess=get_os_guess(ttl),
            )
        )

    return hosts
