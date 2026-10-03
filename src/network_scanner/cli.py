import argparse
import time

from rich.console import Console
from rich.table import Table

from network_scanner.core import Host, ScanResult
from network_scanner.core.exception import NetworkScannerError
from network_scanner.scanners import arp_scan

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


def main():
    # Начало сканирования
    parser = argparse.ArgumentParser(description="Network Scanner CLI")
    parser.add_argument(
        "network",
        nargs="?",
        help="Network range to scan (e.g., 192.168.1.0/24)",
    )
    parser.add_argument("-t", "--timeout", type=int, default=3)
    parser.add_argument("-v", "--verbose", action="store_true")
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

    console.print(f"[bold green]Run a network scan {args.network}...[/bold green]")
    start_time = time.perf_counter()

    try:
        hosts = arp_scan(args.network, timeout=args.timeout)
        scan_time = round(time.perf_counter() - start_time, 2)

        result = ScanResult(
            network=args.network,
            scan_time=scan_time,
            hosts=hosts,
        )

        # Создание таблицы (вывод)
        table = Table(title="Detected devices on the network", expand=False)
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("MAC", style="magenta", no_wrap=True)
        table.add_column("Vendor", style="spring_green3", overflow="fold")
        table.add_column("OS Guess", style="gold3")

        for host in result.hosts:
            ip_display = f"{host.ip} (this device)" if host.is_local else str(host.ip)
            table.add_row(
                ip_display,
                str(host.mac or "-").strip(),
                str(host.vendor or "-").strip(),
                str(host.os_guess or "-").strip(),
            )

        console.print(table)
        console.print(f"[bold cyan]Devices detected: {result.total_hosts}[/bold cyan]")
        console.print(f"[dim]Scan time: {result.scan_time}s[/dim]")

        if args.verbose and hosts:
            console.print("\n[bold]Detailed information:[/bold]")
            for host in hosts:
                console.print(f"    {str(host.ip):15}   MAC: {host.mac or 'N/A'}")

    except NetworkScannerError as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Unexpected error: {e}[/bold red]")
        if args.verbose:
            console.print_exception()


if __name__ == "__main__":
    main()
