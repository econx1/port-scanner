# VibeScan 🌊

VibeScan is an Asyncio-powered specialist port scanner with OS inference and vulnerability matching. It leverages `asyncio` to achieve incredible concurrent scanning speeds and uses `rich` to provide a stunning, real-time terminal user interface.

## ✨ Features

- **Asynchronous Engine:** Scans thousands of ports concurrently using Python's `asyncio` and semaphores for optimized network performance.
- **Beautiful Live UI:** Built with `rich`, providing a real-time responsive dashboard, progress bars, and beautifully styled tables.
- **Smart Summary:** The console UI logically groups ports and exclusively displays `Open` and `Filtered` ports. A real-time status bar tracks your overall progress (including `Closed` port counts).
- **Vulnerability Quick-Match:** Automatically flags banners against an internal signature database of known-vulnerable and outdated services to instantly highlight risk. 
- **Background Logging & Silent Mode:** Export comprehensive scan details (including closed ports, service mappings, and full raw banner alerts) directly to a standard `JSON` file. Run entirely in the background using `--silent` to bypass the UI completely.
- **OS Fingerprinting & Banner Grabbing:** Performs rapid OS inference and service identification based off active banner responses.
- **Flexible Targeting:** Complete support for scanning single IPv4/IPv6 addresses, standard hostnames, and broad CIDR ranges.

## 📦 Installation

Ensure you have Python 3.7+ installed on your system. 

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/vibescan.git
   cd vibescan
   ```

2. Install globally using `pipx` (Recommended):
   ```bash
   pipx install .
   ```
   *Alternatively, you can install via `pip install .` inside a virtual environment.*
   
Once installed globally, you can execute VibeScan from any directory simply using the `vibescan` command.

## 🚀 Usage

Run VibeScan by providing a target or a CIDR network:

```bash
vibescan -t <target> [options]
```

### Examples

**Scan the Top 1000 ports on a single host:**
```bash
vibescan -t 192.168.1.1
```

**Scan an entire CIDR subnetwork:**
```bash
vibescan -n 10.0.0.0/24
```

**Scan all 65,535 ports:**
```bash
vibescan -t 127.0.0.1 -a
```

**Scan specific comma-separated ports and save the detailed JSON output:**
```bash
vibescan -t scanme.nmap.org -p 22,80,443 -o detailed_results.json
```

**Run in pure silent mode (no UI, perfect for scripts & background processes):**
```bash
vibescan -t 10.10.10.10 -a -o background_scan.json -s
```

## 🛠️ Command-Line Options

| Argument | Category | Description |
| :--- | :--- | :--- |
| `-t`, `--target` | **Targeting** | Single IP or hostname to scan. |
| `-n`, `--network` | **Targeting** | CIDR network block to scan (e.g., `192.168.1.0/24`). |
| `-p`, `--ports` | **Port Selection** | Comma-separated list of specific ports to scan (e.g., `22,80`). Defaults to the Top 1000. |
| `-a`, `--all` | **Port Selection** | Aggressively scan all ports from 1 through 65535. |
| `-o`, `--output` | **Output** | Output file path to save a detailed JSON log of all scanned ports and vulnerability alerts. |
| `-s`, `--silent` | **Output** | Run entirely in the background without launching the UI (Requires `-o`). |
| `--show-filtered`| **Display** | Include filtered ports in standard output. |
| `--show-all` | **Display** | Include both filtered and closed ports in standard output. |

## 📊 Reporting and Analysis

VibeScan provides a final **Scan Report** upon completion, cleanly outlining the total time taken alongside a concise breakdown of the overall scan results. Features like **Vulnerability Quick-Match** will bold any discovered critical alerts directly inside the table output.

When the `-o` or `--output` flag is passed, the full detailed dictionary (Target, Port, State, Reason/Service, Banner, Alerts) is cleanly dumped to a `.json` file for automated processing.

## 📜 License

This project is open-source and available under the [MIT License](LICENSE).
