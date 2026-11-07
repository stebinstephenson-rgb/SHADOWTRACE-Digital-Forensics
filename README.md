# 🛡️ SHADOWTRACE
**Offline Digital Forensics & Cyber Investigation Suite**

SHADOWTRACE is an integrated digital forensic investigation toolkit designed to help cybersecurity students, forensic investigators, and security researchers analyze digital evidence from multiple platforms completely offline.

## ✨ Features
*   **Premium UI:** Dark-mode glassmorphism dashboard built with Streamlit.
*   **Image Forensics:** Extracts EXIF metadata (GPS, camera info) and verifies SHA-256 integrity.
*   **Network Forensics:** Parses PCAP files to analyze protocol distributions (TCP/UDP/DNS) using Scapy.
*   **Windows Forensics:** Parses Windows Event Logs (.evtx) to find system activity and attack traces.
*   **Evidence Vault:** Cryptographically hashes and stores evidence metadata in an SQLite database.
*   **Interactive Timeline:** Visualizes the chronological ingestion of evidence using Plotly.
*   **Case Management:** Create and track active forensic cases.
*   **PDF Reporting:** Generates professional forensic reports using ReportLab.

## 🛠️ Technology Stack
*   **Frontend:** Streamlit, Custom CSS, Plotly
*   **Backend:** Python 3.11+
*   **Database:** SQLite3
*   **Forensic Tools:** ExifTool, TShark, Scapy, python-evtx, ReportLab

## 🚀 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/SHADOWTRACE-Digital-Forensics.git
   cd SHADOWTRACE-Digital-Forensics