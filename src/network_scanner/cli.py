import argparse
import time

from rich.console import Console
from rich.table import Table

from network_scanner.core import Host, ScanResult
from network_scanner.scanners import arp_scan

console = Console()


def main():
    """Run a network scan"""
    parser = argparse.ArgumentParser(description="Network Scanner CLI")
    parser.add_argument("network", help="Network range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-t", "--timeout", type=int, default=3)
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

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

        # Create table
        table = Table(title="Detected devices on the network", expand=False)
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("MAC", style="magenta", no_wrap=True)
        table.add_column("Vendor", style="spring_green3", overflow="fold")
        table.add_column("OS Guess", style="gold3")

        for host in result.hosts:
            table.add_row(
                str(host.ip),
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

    except PermissionError:
        console.print(
            "[bold red]Error: недостаточно прав для ARP-сканирования. "
            "Запустите с sudo/от администратора.[/bold red]"
        )
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        if args.verbose:
            console.print_exception()


if __name__ == "__main__":
    main()
