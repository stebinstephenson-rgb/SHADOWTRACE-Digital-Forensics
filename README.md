# 🛡️ SHADOWTRACE
**Offline Digital Forensics & Cyber Investigation Suite**

SHADOWTRACE is an integrated digital forensic investigation toolkit designed to help cybersecurity students, forensic investigators, and security researchers analyze digital evidence from multiple platforms completely offline. 

The application provides a centralized, premium dark-mode dashboard where investigators can upload authorized forensic evidence, conduct investigations, analyze artifacts, and generate professional PDF reports. This is an authorized forensic analysis platform, not a tool for unauthorized access or exploitation.

## ✨ Features
*   **Premium UI:** Dark-mode glassmorphism dashboard built with Streamlit and custom CSS.
*   **Image Forensics:** Extracts EXIF metadata (GPS, camera info, timestamps) and verifies SHA-256 file integrity using ExifTool.
*   **Network Forensics:** Parses PCAP/PCAPNG files to analyze protocol distributions (TCP/UDP/DNS) and IP statistics using Scapy.
*   **Windows Forensics:** Parses Windows Event Logs (.evtx) to find system activity, logins, and potential attack traces (e.g., Event ID 1102).
*   **Evidence Vault:** Cryptographically hashes and stores evidence metadata in a local SQLite database to maintain a strict chain of custody.
*   **Interactive Timeline:** Visualizes the chronological ingestion of evidence using interactive Plotly charts.
*   **Case Management:** Create and track active forensic cases.
*   **PDF Reporting:** Generates professional, automated forensic reports using ReportLab.

## 🛠️ Technology Stack
*   **Frontend:** Streamlit, Custom CSS, Plotly
*   **Backend:** Python 3.11+
*   **Database:** SQLite3
*   **Forensic Tools:** ExifTool, TShark, Scapy, python-evtx, ReportLab

## 🏗️ Architecture Diagram

```mermaid
graph TD
    UI[Streamlit Dashboard app.py] -->|Upload Evidence| Modules[Forensic Modules]
    UI -->|View Data| DB[(SQLite Database)]
    
    subgraph Forensic Modules
        IMG[Image Analyzer]
        NET[Network Analyzer]
        WIN[Windows Analyzer]
    end
    
    IMG -->|ExifTool| Metadata
    NET -->|Scapy| Packets
    WIN -->|python-evtx| Logs
    
    Modules -->|Log Hash & Metadata| DB
    UI -->|Generate Report| PDF[ReportLab PDF]