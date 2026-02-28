# Masqued 🎭

**Masqued** is a professional-grade reconnaissance and URL discovery tool designed to identify hidden assets and subdomains. It utilizes a multi-layered approach to infrastructure mapping, combining passive DNS lookups, certificate transparency log monitoring, active fuzzing, and local caching.

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚀 Key Features

* **Advanced Reconnaissance**: Queries multiple online intelligence sources (Crtsh, Otx, ThreatMiner, etc.) to discover subdomains.
* **Intelligent Caching**: Automatically stores discovery results in a local SQLite database (`~/.masqued_cache.db`) for instant historical comparison.
* **URL Discovery**: Extracts potential endpoints from various sources to build a comprehensive attack surface map.
* **Active Fuzzing**:
    * **Directory Fuzzing**: Efficiently identifies hidden directories using customizable wordlists and thread counts.
    * **Subdomain Bruteforcing**: Multi-threaded DNS resolution for identifying unlinked subdomains.
* **Batch Processing**: Supports high-throughput operations on lists of targets with export options including JSON, CSV, and TXT.
* **Filter & Validation**: Provides built-in status code filtering and validation of live hosts to eliminate false positives.

---

## ⚙️ Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/shawnnuhq/Masqued.git
    cd masqued
    ```
2.  **Install dependencies**:
    ```bash
    pip install requests
    ```

---

## 🛠️ Usage Examples

### Single Target Discovery
The default command performs passive reconnaissance and queries enabled online APIs for subdomains.
```bash
python masqued.py scan example.com
```
Directory Fuzzing
Perform active directory discovery using a specific wordlist (e.g., common.txt) to find hidden panels or files.
python masqued.py scan -w common.txt example.com

Targeted Subdomain Bruteforce
Attempt to find subdomains via DNS bruteforcing with a custom list of prefixes.
python masqued.py scan -b -w subdomains-top1mil.txt example.com

Batch Processing from File
Analyze multiple domains simultaneously from a file and export the discovery results to a structured CSV.
python masqued.py batch targets.txt -o report.csv --threads 20

Cache Management
View statistics or clear the local discovery history stored in the SQLite database.
python masqued.py cache stats

📊 Modules & Sources
| Category | Sources / Methods |
|---|---|
| Passive DNS | OTX, ThreatMiner, VirusTotal (API) |
| Certificates | Crt.sh (Transparency Logs) |
| Active Fuzzing | HTTP HEAD/GET request validation |
| Automation | Multi-threaded engine for concurrent scanning |
⚖️ Disclaimer
This tool is intended for legal, authorized security testing and educational purposes only. The author is not responsible for any misuse or damage caused by this program. Always obtain explicit permission before scanning targets.
Author: Shawnn | Version: 1

