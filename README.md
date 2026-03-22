# VibeScan 🌊

VibeScan is a high-performance, asynchronous port scanner written in Python. It leverages `asyncio` to achieve incredible concurrent scanning speeds and uses `rich` to provide a stunning, real-time terminal user interface.

## ✨ Features

- **Asynchronous Engine:** Scans thousands of ports concurrently using Python's `asyncio` and semaphores for optimized network performance.
- **Beautiful Live UI:** Built with `rich`, providing a real-time responsive dashboard, progress bars, and styled tables.
- **Smart Summary:** The console UI stays clean by exclusively displaying `Open` and `Filtered` ports. A real-time status bar tracks your overall progress (including `Closed` port counts).
- **Background Logging:** Export comprehensive scan details (including closed ports, service mappings, and full raw banners) directly to a standard `JSON` file for later reporting and analysis.
- **OS Fingerprinting & Banner Grabbing:** Performs rapid OS inference and service identification based off active banner responses.
- **Flexible Targeting:** Complete support for scanning single IPv4/IPv6 addresses, standard hostnames, and broad CIDR ranges.

## 📦 Installation

Ensure you have Python 3.7+ installed on your system. 

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/vibescan.git
   cd vibescan
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: The primary external dependency is the `rich` library for terminal formatting.)*

## 🚀 Usage

Run VibeScan by providing a target (IP, hostname, or CIDR network):

```bash
python3 vibescan.py <target> [options]
```

### Examples

**Scan the Top 1000 ports (default option):**
```bash
python3 vibescan.py 192.168.1.1
```

**Scan an entire CIDR subnetwork:**
```bash
python3 vibescan.py 10.0.0.0/24
```

**Scan all 65,535 ports:**
```bash
python3 vibescan.py 127.0.0.1 -a
```

**Scan specific comma-separated ports and save the detailed JSON output:**
```bash
python3 vibescan.py scanme.nmap.org -p 22,80,443,8080 -o detailed_results.json
```

## 🛠️ Command-Line Options

| Argument | Description |
| :--- | :--- |
| `target` | **(Required)** The IP address, CIDR block, or hostname to actively scan. |
| `-p` | Comma-separated list of specific ports to scan (e.g., `22,80,443`). |
| `-a` | Aggressively scan all ports from 1 through 65535. |
| `-o`, `--output` | Output file path to save a detailed JSON log of all scanned ports (including closed ones). |

## 📊 Reporting and Analysis

VibeScan provides a final **Scan Report** upon completion, cleanly outlining the total time taken alongside a concise breakdown of the overall scan results. The live UI focuses purely on the "signal" (open and filtered ports) while elegantly discarding the "noise." 

When the `-o` or `--output` flag is passed, the full detailed dictionary (Target, Port, State, Reason/Service, Banner) is cleanly dumped to a standard `.json` file for automated processing or manual review.

## 📜 License

This project is open-source and available under the [MIT License](LICENSE).
