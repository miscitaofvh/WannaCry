# WannaCry Malware Analysis & Defense Research

A comprehensive research project analyzing the WannaCry ransomware attack chain, from exploitation and propagation to detection evasion and defensive countermeasures.

## 🚀 Key Features

### 1. Attack Simulation (PoC)
The source code in `PoC-Simulation/` simulates the core behaviors of the WannaCry ransomware:
* **File Encryption**: Scans for specific file extensions (.txt, .doc, .pdf, .jpg, etc.) in target folders, encrypts them using an XOR operation (key: 0xAA), appends the `.wannacry` extension, and generates a ransom note.
* **Network Reconnaissance**: Automatically identifies the local network configuration and scans for hosts with port 445 (SMB) open to find vulnerable targets.
* **EternalBlue Exploitation (MS17-010)**: Implements the exploit for the SMBv1 vulnerability using `NT_TRANSACT` packets and memory grooming techniques to achieve remote code execution.
* **Reverse Shell & Payload Delivery**: Features a built-in reverse shell handler and a mini HTTP server to deliver the malicious executable to the victim's machine post-exploitation.

### 2. Detection & Defense (IDPS)
The `AV-Detection/` component focuses on monitoring and mitigating attacks at the network layer:
* **SMB Traffic Monitoring**: Utilizes raw sockets to sniff and analyze SMB protocol traffic in real-time.
* **EternalBlue Signature Detection**: Identifies malicious `NT_TRANSACT` (0xA0) packets by detecting discrepancies between the declared `Total Data Count` and the actual `NetBIOS Length`.
* **Automated Response**: Automatically blocks the attacker's IP address by dynamically adding a block rule to the Windows Firewall via `netsh` upon detection of an intrusion attempt.

### 3. Technical Research
The project includes deep-dive technical documentation regarding SMB and CIFS protocols to support architectural analysis.

## 📁 Project Structure

* `/PoC-Simulation`: Source code for the ransomware simulation and EternalBlue exploit module.
* `/AV-Detection`: An Intrusion Detection and Prevention System (IDPS) specialized for SMB-based attacks.
* `/Reseach-Papers`: Technical specifications for [MS-SMB] and [MS-CIFS] protocols.

## 🛠 Technical Requirements

* **Language**: C++
* **Libraries**: `WinSock2`, `Iphlpapi`, `Crypt32`.


## ⚠️ Security Disclaimer

This project is for **educational and security research purposes only**. The use of this code for illegal activities is strictly prohibited. The author is not responsible for any misuse of these tools. Always perform simulations in a strictly isolated laboratory environment.