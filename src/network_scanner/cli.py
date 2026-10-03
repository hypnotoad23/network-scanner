import argparse
import time

from rich.console import Console
from rich.table import Table

from network_scanner.core import Host, ScanResult
from network_scanner.core.exception import NetworkScannerError
from network_scanner.scanners import arp_scan, icmp_scan, port_scan
from network_scanner.scanners.fingerprint import get_os_guess
from network_scanner.utils.services import get_service_name

console = Console()


def update_vendor_db() -> None:
    # Скачивает/обновляет локальную базу MAC-вендоров (IEEE OUI)
    from mac_vendor_lookup import MacLookup

    console.print("[cyan]Updating vendor database...[/cyan]")
    try:
        MacLookup().update_vendors()
        console.print("[bold green]Vendor database updated.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to update vendor database: {e}[/bold red]")


def parse_ports(spec: str) -> list[int]:
    # Разбирает строку с портами: "22,80,443", "1-1000" или комбинацию "22,80,1000-2000".

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            if not (0 <= start <= 65535 and 0 <= end <= 65535 and start <= end):
                raise ValueError(f"Некорректный диапазон портов: {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not (0 <= port <= 65535):
                raise ValueError(f"Некорректный порт: {part}")
            ports.add(port)
    return sorted(ports)


def format_open_ports(host: Host) -> str:
    if not host.open_ports:
        return "-"
    return ", ".join(f"{p}/{get_service_name(p)}" for p in host.open_ports)


def run_scan(network: str, detect_os: bool, ports: list[int] | None, timeout: int) -> list[Host]:
    """Выполняет ARP-сканирование и, опционально, ICMP (TTL/ОС) и SYN-скан портов."""
    hosts = arp_scan(network, timeout=timeout)

    if detect_os and hosts:
        ips = [str(h.ip) for h in hosts]
        icmp_hosts = {str(h.ip): h for h in icmp_scan(ips, timeout=timeout)}
        for host in hosts:
            icmp_match = icmp_hosts.get(str(host.ip))
            if icmp_match:
                host.ttl = icmp_match.ttl
                host.os_guess = icmp_match.os_guess

    if ports and hosts:
        port_scan(hosts, ports, timeout=timeout)

    return hosts

def main():
    #Начало сканирования 
    parser = argparse.ArgumentParser(description="Network Scanner CLI")
    parser.add_argument(
        "network",
        nargs="?",
        help="Network range to scan (e.g., 192.168.1.0/24)",
    )
    parser.add_argument("-t", "--timeout", type=int, default=3)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "--os-detect",
        action="store_true",
        help="Дополнительно к ARP выполнить ICMP-сканирование для определения TTL/ОС",
    )
    parser.add_argument(
        "-p",
        "--ports",
        type=str,
        default=None,
        help="Диапазон портов для SYN-сканирования, напр. '22,80,443' или '1-1000'",
    )
    parser.add_argument(
        "--update-vendor-db",
        action="store_true",
        help="Update local MAC vendor database and exit",
    )

    args = parser.parse_args()

    if args.update_vendor_db:
        update_vendor_db()
        return

    if not args.network:
        parser.error("the following arguments are required: network")

    ports: list[int] | None = None
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError as e:
            parser.error(str(e))

    console.print(f"[bold green]Run a network scan {args.network}...[/bold green]")
    start_time = time.perf_counter()

    try:
        hosts = run_scan(args.network, args.os_detect, ports, args.timeout)
        scan_time = round(time.perf_counter() - start_time, 2)

        result = ScanResult(
            network=args.network,
            scan_time=scan_time,
            hosts=hosts,
        )

        table = Table(title="Detected devices on the network", expand=False)
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("MAC", style="magenta", no_wrap=True)
        table.add_column("Vendor", style="spring_green3", overflow="fold")
        table.add_column("OS Guess", style="gold3", overflow="fold")
        if ports:
            table.add_column("Open Ports", style="bright_blue", overflow="fold")

        for host in result.hosts:
            ip_display = f"{host.ip} (this device)" if host.is_local else str(host.ip)
            row = [
                ip_display,
                str(host.mac or "-").strip(),
                str(host.vendor or "-").strip(),
                str(host.os_guess or "-").strip(),
            ]
            if ports:
                row.append(format_open_ports(host))
            table.add_row(*row)

        console.print(table)
        console.print(f"[bold cyan]Devices detected: {result.total_hosts}[/bold cyan]")
        console.print(f"[dim]Scan time: {result.scan_time}s[/dim]")

        if args.verbose and hosts:
            console.print("\n[bold]Detailed information:[/bold]")
            for host in hosts:
                console.print(
                    f"    {str(host.ip):15}   MAC: {host.mac or 'N/A':17}   TTL: {host.ttl or '-'}"
                )

    except NetworkScannerError as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Unexpected error: {e}[/bold red]")
        if args.verbose:
            console.print_exception()


if __name__ == "__main__":
    main()
