# 🕵️‍♂️ VPN Extension Forensic Suite

A specialized forensic toolkit for identifying potentially **malicious or insecure VPN browser extensions**.

This repository contains two distinct Python automation tools designed to analyze different aspects of a VPN extension's behavior:

1.  **`vpn_rpki_validation_test.py`**: Analyzes the *external* network infrastructure integrity using RPKI validation.
2.  **`vpn_sysmon_test.py`**: Analyzes the *internal* local behavior, including process filtering and traffic leaks.

---

## 🚀 Tool 1: Infrastructure Integrity (RPKI) Check
**File:** `vpn_rpki_validation_test.py`

This tool analyzes the network infrastructure of a VPN extension. It determines if a VPN is operating on legitimate infrastructure or if it is using hijacked BGP routes—a common trait of malicious "fly-by-night" VPNs.

### Features
* **Infrastructure Integrity Check (Origin Validation):**
    * Extracts the VPN Exit IP.
    * Identifies the ASN (Autonomous System Number) and BGP Prefix.
    * Queries the RIPEstat API to verify if the route is **RPKI Valid**, **Invalid** (Hijacked), or **Unknown**.
* **Security Enforcement Check:** Tests if the VPN protects the user by attempting to connect to a known RPKI-Invalid domain (`invalid.rpki.cloudflare.com`).

---

## 🚀 Tool 2: System Monitor & Leak Check
**File:** `vpn_sysmon_test.py`

This tool acts as a "watchdog" for your local machine while the VPN is running. It specifically looks for traffic that escapes the browser's VPN tunnel (leaks) and verifies that the browser process is isolated.

### Features
* **Process ID (PID) Isolation:** Automatically detects the specific Chrome "Network Service" process to distinguish browser traffic from background system noise.
* **Hybrid Traffic Analysis:**
    * **Global DNS Scan:** Detects if *any* process on your computer sends a DNS request for the visited sites (catching OS-level leaks when VPNs disconnect).
    * **Strict SNI/HTTPS Check:** Verifies that encrypted traffic is actually originating from the browser's tunnel.
* **Evidence Collection:** Automatically saves `.pcap` (Packet Capture) files if a leak is detected for forensic proof.

---

## 📋 Prerequisites

* **Python 3.7+**
* **Google Chrome Browser** installed.
* **Administrator / Root Privileges** (Required for `vpn_sysmon_test.py` to capture packets).
* The **Source Code** (Unzipped folder) of the target VPN extension.
    * *Note: If you have a `.crx` file, unzip it first.*

---

## 🛠️ Installation

1.  **Clone this repository** (or download the scripts):
    

2.  **Install required Python libraries:**
    ```bash
    pip install selenium webdriver-manager requests scapy psutil
    ```
    *(Note: `scapy` and `psutil` are required for the Sysmon test)*

---

## ▶️ Usage Guide

You can run these tests independently depending on what you want to analyze.

### 🧪 Test A: Check for Hijacked Routes (RPKI)
Use this to see if the VPN provider is legitimate.

1.  Open `vpn_rpki_validation_test.py` and set the `EXTENSION_PATH` variable to your unzipped extension folder.
2.  Run the script:
    ```bash
    python vpn_rpki_validation_test.py
    ```
3.  **Action:** A Chrome window will open. Manually turn the VPN **ON**.
4.  Return to the terminal and press `y` + `Enter`.
5.  **Result:** The script will output if the VPN IP is RPKI Valid or Invalid.

### 🧪 Test B: Check for Traffic Leaks (Sysmon)
Use this to see if the VPN is actually encrypting your traffic or leaking it.

**⚠️ Important:** This script must be run as **Administrator** (Windows) or **Root** (Linux/Mac) because it interacts with the network card.

1.  Open command prompt/terminal as **Administrator**.
2.  Run the script:
    ```bash
    python vpn_sysmon_test.py
    ```
3.  **Action:**
    * The script will launch Chrome and automatically find the correct Network Process ID (PID).
    * It will pause for **120 seconds** (default). **Connect your VPN extension now.**
4.  **Wait:** The script will automatically visit 50+ websites and analyze the traffic in the background.
5.  **Result:**
    * Check the generated text report (e.g., `hybrid_leak_report_timestamp.txt`).
    * **[OK] SECURE:** No leaks found.
    * **[!!!] FAIL:** Traffic leaked. Check the generated `.pcap` files for evidence.

---

## 📊 Understanding the Results

### RPKI Test (`vpn_rpki_validation_test.py`)

| Result | Meaning | Risk Level |
| :--- | :--- | :--- |
| **VALID** | IP matches the owner's ROA. Legitimate infrastructure. | 🟢 **Low Risk** |
| **UNKNOWN** | No ROA found. Common for budget hosting. | 🟡 **Medium Risk** |
| **INVALID** | IP prefix **conflicts** with the real owner. Likely hijacked. | 🔴 **Critical / Malicious** |

### Sysmon Test (`vpn_sysmon_test.py`)

| Result | Meaning | Risk Level |
| :--- | :--- | :--- |
| **SECURE** | All traffic stayed inside the VPN tunnel. | 🟢 **Safe** |
| **LEAK DETECTED** | DNS requests or Data packets escaped the VPN. | 🔴 **Critical Failure** |

---

## ⚠️ Disclaimer

This tool is intended for **educational and research purposes only**. It is designed to help security researchers and developers identify potential vulnerabilities in browser extensions.

* Do not use this tool to test extensions you do not have permission to analyze.
* The authors are not responsible for any misuse of this software.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
