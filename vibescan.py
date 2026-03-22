#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import socket
import re
import sys
from typing import List, Tuple
from rich.live import Live
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskID
from rich.console import Group, Console

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

def parse_ports(args) -> List[int]:
    """Parse ports based on arguments."""
    if args.a:
        return list(range(1, 65536))
    if args.p:
        ports = []
        for p in args.p.split(','):
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

async def scan_target(target: str, ports: List[int], sem: asyncio.Semaphore, table: Table, progress: Progress, task_id: TaskID, show_filtered: bool, show_all: bool):
    """Scan ports on a single target asynchronously."""
    async def scan_port(port: int):
        async with sem:
            state, service, banner = await check_port(target, port, timeout=1.0)
            
            should_show = False
            if state == "Open":
                should_show = True
                state_text = "[bold green]Open[/]"
            elif state == "Filtered" and (show_filtered or show_all):
                should_show = True
                state_text = "[bold yellow]Filtered[/]"
            elif state == "Closed" and show_all:
                should_show = True
                state_text = "[bold red]Closed[/]"

            if should_show:
                os_guess = guess_os(banner)
                display_banner = banner if banner else "-"
                table.add_row(target, str(port), state_text, service, display_banner, os_guess)
            progress.advance(task_id)

    tasks = [asyncio.create_task(scan_port(port)) for port in ports]
    await asyncio.gather(*tasks)

async def main(args):
    targets = parse_targets(args.target)
    ports = parse_ports(args)
    sem = asyncio.Semaphore(1000)

    # UI Setup
    table = Table(title="VibeScan Results", expand=True)
    table.add_column("Target", style="cyan", no_wrap=True)
    table.add_column("Port", justify="right", style="magenta", no_wrap=True)
    table.add_column("State", justify="center", no_wrap=True)
    table.add_column("Service", style="green", no_wrap=True)
    table.add_column("Banner", style="yellow")
    table.add_column("OS Guess", justify="center")

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        expand=True
    )

    group = Group(table, "", progress)

    total_scans = len(targets) * len(ports)
    task_id = progress.add_task("[cyan]Scanning...", total=total_scans)

    # Use Live context manager to render the UI dynamically
    try:
        with Live(group, refresh_per_second=10, console=console, transient=False) as live:
            target_tasks = [scan_target(t, ports, sem, table, progress, task_id, args.show_filtered, args.show_all) for t in targets]
            await asyncio.gather(*target_tasks)
            
        if table.row_count == 0:
            console.print("\n[bold yellow]No open ports were found on the specified targets for the given ports.[/]")
    except KeyboardInterrupt:
        # Avoid traceback spam if someone presses Ctrl+C inside the Live block
        raise # We catch it outside

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VibeScan - High-performance asynchronous port scanner")
    parser.add_argument("target", help="IP, CIDR, or hostname to scan")
    parser.add_argument("-a", action="store_true", help="Scan all ports (1-65535)")
    parser.add_argument("-p", type=str, help="Comma-separated list of ports to scan (e.g., 22,80,443)")
    parser.add_argument("--show-filtered", action="store_true", help="Include filtered ports in standard output")
    parser.add_argument("--show-all", action="store_true", help="Include both filtered and closed ports")
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user. Showing partial results.[/]")
        sys.exit(0)
