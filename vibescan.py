#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import socket
import re
import sys
import json
import time
from typing import List, Tuple
from rich.live import Live
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskID
from rich.console import Group, Console
from rich.panel import Panel
from rich.text import Text

console = Console()

def parse_targets(target_str: str) -> List[str]:
    """Validate and parse IP, CIDR, or hostname into a list of IP addresses."""
    try:
        if '/' in target_str:
            net = ipaddress.ip_network(target_str, strict=False)
            return [str(ip) for ip in net.hosts()]
        else:
            ip = ipaddress.ip_address(target_str)
            return [str(ip)]
    except ValueError:
        try:
            ip = socket.gethostbyname(target_str)
            return [ip]
        except socket.gaierror:
            console.print(f"[bold red]Error:[/] Invalid IP, CIDR, or hostname: {target_str}")
            sys.exit(1)

def get_targets(args) -> List[str]:
    targets = []
    if args.target:
        targets.extend(parse_targets(args.target))
    if args.network:
        targets.extend(parse_targets(args.network))
    return list(dict.fromkeys(targets))

def parse_ports(args) -> List[int]:
    """Parse ports based on arguments."""
    if args.all:
        return list(range(1, 65536))
    if args.ports:
        ports = []
        for p in args.ports.split(','):
            p = p.strip()
            if p.isdigit():
                port_num = int(p)
                if 1 <= port_num <= 65535:
                    ports.append(port_num)
        if not ports:
            console.print("[bold red]Error:[/] No valid ports specified.")
            sys.exit(1)
        return ports
    # Default to "Top 1000" (using 1-1000 for simplicity)
    return list(range(1, 1001))

def get_service_name(port: int) -> str:
    """Attempt to resolve the well-known service name for a port."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"

async def check_port(ip: str, port: int, timeout: float = 1.0) -> Tuple[str, str, str]:
    """Attempt to connect, grab a banner, and return (state, service, banner)."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        
        banner = b""
        try:
            # Wait briefly for unsolicited banners (e.g., SSH, FTP)
            banner = await asyncio.wait_for(reader.read(1024), timeout=0.5)
        except asyncio.TimeoutError:
            pass
            
        if not banner:
            # Send a generic HTTP-like probe to see if it responds
            try:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            except Exception:
                pass
                
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
            
        banner_str = banner.decode('utf-8', errors='ignore').strip()
        # Clean up the banner string: replace all whitespace/newlines with single space
        banner_str = re.sub(r'\s+', ' ', banner_str)[:100]
        
        return "Open", get_service_name(port), banner_str
    except asyncio.TimeoutError:
        return "Filtered", get_service_name(port), "-"
    except ConnectionRefusedError:
        return "Closed", get_service_name(port), "-"
    except OSError:
        return "Closed", get_service_name(port), "-"
    except Exception:
        return "Closed", get_service_name(port), "-"

VULN_DB = {
    "php/5.": "Outdated PHP 5.x",
    "iis/6.0": "Outdated IIS 6.0",
    "vsftpd 2.3.4": "Backdoored vsftpd (2.3.4)",
    "openssh_5.": "Outdated OpenSSH 5.x",
    "apache/2.2": "Outdated Apache 2.2"
}

def check_vulnerability(banner: str) -> str:
    if not banner:
        return "-"
    banner_lower = banner.lower()
    for sig, risk in VULN_DB.items():
        if sig.lower() in banner_lower:
            return risk
    return "-"

class StatusBar:
    def __init__(self):
        self.open = 0
        self.filtered = 0
        self.closed = 0
        
    def __rich__(self) -> Text:
        return Text(f"[Scanning...] Open: {self.open} | Filtered: {self.filtered} | Closed: {self.closed}", style="bold cyan")

def guess_os(banner: str) -> str:
    """Fast guess OS fingerprinting based on banner keywords."""
    if not banner:
        return "-"
    
    banner_lower = banner.lower()
    if re.search(r'ubuntu', banner_lower):
        return "[bold purple]Linux (Ubuntu)[/]"
    elif re.search(r'debian', banner_lower):
        return "[bold red]Linux (Debian)[/]"
    elif re.search(r'centos', banner_lower):
        return "[bold blue]Linux (CentOS)[/]"
    elif re.search(r'windows|iis|microsoft', banner_lower):
        return "[bold cyan]Windows[/]"
    elif re.search(r'openssh|apache|nginx', banner_lower):
        return "[bold green]Likely Linux/Unix[/]"
    elif re.search(r'freebsd', banner_lower):
        return "[bold red]FreeBSD[/]"
    
    return "-"

async def scan_target(target: str, ports: List[int], sem: asyncio.Semaphore, table, progress, task_id, status_bar: StatusBar, results_list: list, args):
    """Scan ports on a single target asynchronously."""
    async def scan_port(port: int):
        async with sem:
            state, service, banner = await check_port(target, port, timeout=1.0)
            
            alert = check_vulnerability(banner)

            results_list.append({
                "target": target,
                "port": port,
                "state": state,
                "reason": service,
                "banner": banner,
                "alert": alert if alert != "-" else ""
            })

            should_show = False
            if state == "Open":
                status_bar.open += 1
                should_show = True
                state_text = "[bold green]Open[/]"
            elif state == "Filtered":
                status_bar.filtered += 1
                if args.show_filtered or args.show_all:
                    should_show = True
                state_text = "[bold yellow]Filtered[/]"
            elif state == "Closed":
                status_bar.closed += 1
                if args.show_all:
                    should_show = True
                state_text = "[bold red]Closed[/]"

            if should_show and not args.silent and table:
                os_guess = guess_os(banner)
                display_banner = banner if banner else "-"
                alert_display = f"[bold red]{alert}[/]" if alert != "-" else "[gray50]-[/]"
                table.add_row(target, str(port), state_text, service, display_banner, os_guess, alert_display)
            
            if not args.silent and progress:
                progress.advance(task_id)

    tasks = [asyncio.create_task(scan_port(port)) for port in ports]
    await asyncio.gather(*tasks)

async def main(args):
    start_time = time.time()
    targets = get_targets(args)
    ports = parse_ports(args)
    sem = asyncio.Semaphore(1000)

    status_bar = StatusBar()
    results_list = []

    if not args.silent:
        # UI Setup
        table = Table(title="VibeScan Results", expand=True)
        table.add_column("Target", style="cyan", no_wrap=True)
        table.add_column("Port", justify="right", style="magenta", no_wrap=True)
        table.add_column("State", justify="center", no_wrap=True)
        table.add_column("Service", style="green", no_wrap=True)
        table.add_column("Banner", style="yellow")
        table.add_column("OS Guess", justify="center")
        table.add_column("Alerts", justify="center")

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            expand=True
        )

        group = Group(table, "", status_bar, "", progress)

        total_scans = len(targets) * len(ports)
        task_id = progress.add_task("[cyan]Scanning...", total=total_scans)

        # Use Live context manager to render the UI dynamically
        try:
            with Live(group, refresh_per_second=10, console=console, transient=False) as live:
                target_tasks = [scan_target(t, ports, sem, table, progress, task_id, status_bar, results_list, args) for t in targets]
                await asyncio.gather(*target_tasks)
                
            if table.row_count == 0:
                console.print("\n[bold yellow]No open ports were found on the specified targets for the given ports.[/]")
                
            # Final Summary
            time_taken = time.time() - start_time
            summary_text = (
                f"Total Ports Scanned: {total_scans}\n"
                f"Time Taken: {time_taken:.2f} seconds\n\n"
                f"[bold green]Open:[/] {status_bar.open}  |  "
                f"[bold yellow]Filtered:[/] {status_bar.filtered}  |  "
                f"[bold red]Closed:[/] {status_bar.closed}"
            )
            console.print(Panel(summary_text, title="Scan Report", border_style="cyan", expand=False))
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results_list, f, indent=4)
                console.print(f"\n[bold green]Detailed results saved to {args.output}[/]")

        except KeyboardInterrupt:
            # Avoid traceback spam if someone presses Ctrl+C inside the Live block
            raise # We catch it outside
    else:
        # Silent Mode Logic
        target_tasks = [scan_target(t, ports, sem, None, None, None, status_bar, results_list, args) for t in targets]
        await asyncio.gather(*target_tasks)
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results_list, f, indent=4)

def cli_main():
    parser = argparse.ArgumentParser(
        description="VibeScan: An Asyncio-powered specialist port scanner with OS inference and vulnerability matching."
    )
    
    target_group = parser.add_argument_group('Targeting')
    target_group.add_argument("-t", "--target", help="Single IP or hostname to scan")
    target_group.add_argument("-n", "--network", help="CIDR network to scan (e.g., 192.168.1.0/24)")
    
    port_group = parser.add_argument_group('Port Selection')
    port_group.add_argument("-a", "--all", action="store_true", help="Scan all ports (1-65535)")
    port_group.add_argument("-p", "--ports", type=str, help="Comma-separated list of ports (e.g., 22,80,443)")
    
    out_group = parser.add_argument_group('Output')
    out_group.add_argument("-o", "--output", type=str, help="Output file to save detailed JSON log")
    out_group.add_argument("-s", "--silent", action="store_true", help="Run entirely in background without UI")
    
    disp_group = parser.add_argument_group('Display')
    disp_group.add_argument("--show-filtered", action="store_true", help="Include filtered ports in standard output")
    disp_group.add_argument("--show-all", action="store_true", help="Include both filtered and closed ports")
    
    args = parser.parse_args()
    
    if not args.target and not args.network:
        console.print("[bold red]Error:[/] You must specify either a target (-t) or a network (-n).")
        sys.exit(1)
        
    if args.silent and not args.output:
        console.print("[bold red]Error:[/] Silent mode requires an output file (-o) to save results.")
        sys.exit(1)
        
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        if not args.silent:
            console.print("\n[bold yellow]Scan interrupted by user. Showing partial results.[/]")
        sys.exit(0)

if __name__ == "__main__":
    cli_main()
