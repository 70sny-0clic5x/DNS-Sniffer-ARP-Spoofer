# 🛡️ 70SNY_0xHUNTER: Multi-Platform DNS Sniffer & ARP Spoofer

A high-performance network security tool designed for real-time traffic interception and DNS query analysis. This tool automates the process of **ARP Cache Poisoning** to redirect traffic, allowing for the monitoring of host activities across a local area network (LAN).

---

## 📖 Technical Overview

This tool acts as a **"Man-in-the-Middle" (MitM)** framework. It leverages the **Scapy** library to craft and inject malicious ARP packets, tricking the target and the gateway into routing traffic through the attacker's machine. 

Unlike basic scripts, this tool includes an **Intelligent Interface Discovery Engine** that filters out virtual, docker, and tunnel adapters, ensuring the user selects the correct physical hardware for packet injection.

---

## 🚀 Key Features

* **Cross-Platform Compatibility:** Native support for both **Windows** (PowerShell integration) and **Linux** (Sysctl integration).
* **Smart Interface Selection:** Automatically scans and identifies physical network interfaces while ignoring clutter from VMs or VPNs.
* **Automated Network Mapping:** Calculates the target IP range and Gateway IP dynamically based on the selected interface's configuration.
* **Automatic IP Forwarding:** Programmatically toggles the OS kernel’s forwarding settings to ensure the target maintains internet connectivity during the audit.
* **Multi-Threaded Execution:** Runs the ARP spoofing engine and the DNS sniffer on separate threads for maximum stability and zero packet loss.

---

## 🛠️ Technical Specifications

* **Language:** Python 3.x
* **Network Engine:** Scapy (Advanced Packet Manipulation)
* **Dependencies:** `psutil`, `logging`, `threading`
* **Logic:** * **Layer 2:** ARP Opcode 2 (Is-at) for unsolicited replies.
    * **Layer 7:** UDP Port 53 filtering for DNS Query (DNSQR) extraction.

---

## 📸 Demonstration

> [!TIP]
> **[Screenshot 1.png]**
> **[Screenshot2.png]**

---

## 👤 Developer Profile

**Author:** **Hadeer** (`70SNY_0xHUNTER`)  
**Focus:** Cybersecurity Researcher | OSINT Framework Developer | Penetration Tester  

* **Linkedin Profile:** [**Linkedin**](www.linkedin.com/in/mohamed-hosny-1a2478352)
* **Specialization:** Digital Identity Correlation, Dark Web Reconnaissance, and Network Auditing.
* **Environment:** Optimized for Linux, Unix, and Windows environments.

---

## ⚙️ Installation & Usage

1.  **Clone the repository and install dependencies:**
    ```bash
    pip install scapy psutil
    ```

2.  **Run with Administrative/Root Privileges:**
    * **Windows:** Run Terminal as Administrator.
    * **Linux:** `sudo python3 70SNY_sniffer.py`

3.  **Operation:** Select your physical interface index/name from the generated list, and the tool will handle the rest.

---

## ⚠️ Ethical Disclosure
This framework is provided for **educational purposes and authorized security auditing only**. Unauthorized use of these tools against networks without explicit permission is illegal. The developer assumes no liability for misuse or damage caused by this program.
