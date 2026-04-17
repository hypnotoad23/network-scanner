import argparse
from rich.console import Console
from rich.table import Table
import time

from network_scanner.core import Host, ScanResult
from network_scanner.scanners import arp_scan

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Network Scanner CLI")
    parser.add_argument("network", help="Network range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-t", "--timeout", type=int, default=3)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to use (optional)")

    args = parser.parse_args()

    """Run a network scan"""
    console.print(f"[bold green] Run a network scan {args.network}...[/bold green]")
    start_time = time.time()
    
    try:
        hosts = arp_scan(args.network, timeout=args.timeout, interface=args.interface)
        scan_time = round(time.time() - start_time, 2)

        result = ScanResult(
            network=args.network,
            scan_time=scan_time,
            total_hosts=len(hosts),
            hosts=hosts
        )
        
        #Create table
        table = Table(title="Detected devices on the network")
        table.add_column("IP", style="cyan", width=16) 
        table.add_column("MAC", style="magenta", width=19)
        table.add_column("Vendor", style="blue", width=25, overflow="ellipsis")
        table.add_column("OS Guess", style="green", width=15)

        for host in result.hosts:
            table.add_row(
                host.ip,
                host.mac or "-",
                host.vendor or "-",
                host.os_guess or "-"
            )

        console.print(table)

        console.print(f"[bold cyan]Devices detected: {result.total_hosts}[/bold cyan]")
        
        if args.verbose and hosts:
            console.print("\n[bold]Detailed information:[/bold]")
            for host in hosts:
                console.print(f"    {host.ip:15}   MAC: {host.mac or 'N/A'}")


    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")

if __name__ == "__main__":
    main()
