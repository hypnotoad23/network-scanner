import platform
from typing import List, Optional, Tuple

from rich.progress import Progress
from scapy.all import IP, TCP, conf, send, sr

from ..core.exception import ScanPermissionError
from ..core.models import Host

if platform.system() == "Windows":
    conf.use_pcap = True


def _syn_scan_host(target_ip: str, ports: List[int], timeout: int) -> Tuple[List[int], Optional[int]]:
    """
    Выполняет SYN-сканирование одного хоста по списку портов.

    Возвращает список открытых портов и TCP window size первого открытого порта —
    используется как дополнительный сигнал в fingerprint.get_os_guess.
    """
    packets = IP(dst=target_ip) / TCP(dport=ports, flags="S")
    answered, _ = sr(packets, timeout=timeout, verbose=False)

    open_ports: List[int] = []
    window_size: Optional[int] = None

    for sent, received in answered:
        if not received.haslayer(TCP):
            continue
        tcp_layer = received.getlayer(TCP)
        if tcp_layer.flags == 0x12:  # SYN-ACK — порт открыт
            port = sent[TCP].dport
            open_ports.append(port)
            if window_size is None:
                window_size = tcp_layer.window
            # закрываем half-open соединение, не завершая полный handshake
            rst = IP(dst=target_ip) / TCP(dport=port, flags="R", seq=tcp_layer.ack)
            send(rst, verbose=False)

    return sorted(open_ports), window_size


def port_scan(hosts: List[Host], ports: List[int], timeout: int = 2) -> None:
    """
    Выполняет SYN-сканирование портов для списка хостов (обычно уже найденных arp_scan).

    Результат записывается прямо в переданные объекты Host (open_ports, window_size) —
    функция ничего не возвращает, хосты изменяются "на месте".
    """
    if not hosts or not ports:
        return

    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning ports...", total=len(hosts))
            for host in hosts:
                open_ports, window_size = _syn_scan_host(str(host.ip), ports, timeout)
                host.open_ports = open_ports
                host.window_size = window_size
                progress.advance(task)
    except PermissionError as e:
        raise ScanPermissionError(
            "Недостаточно прав для SYN-сканирования портов. "
            "Запустите с sudo (Linux) или от администратора (Windows)."
        ) from e
