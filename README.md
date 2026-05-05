# Automated Threat Intelligence & Correlation Platform

A professional-grade cybersecurity reconnaissance tool designed for ethical hacking projects. This platform automates the transition from passive Open Source Intelligence (OSINT) to active reconnaissance, correlating all findings into an interactive visual graph.

## 🚀 Features

- **Passive OSINT Module**: 
    - Domain search via Hunter.io (extracts emails and data).
    - DNS Reconnaissance (A, MX, NS, TXT records).
- **Active Reconnaissance**:
    - Automatic Nmap scanning of discovered infrastructure.
    - Service and version detection for identified ports.
- **Visual Correlation Graph**:
    - Real-time interactive node-link diagram (Domain -> Email -> IP -> Port -> Service).
- **Streamlit Dashboard**:
    - Clean, modern UI for entering targets and viewing threat reports.

## 🛠️ Installation

1. **Install Nmap**:
   Ensure Nmap is installed on your system.
   - Windows: [Download Nmap](https://nmap.org/download.html) and add it to your System PATH.
   
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   Copy `.env.example` to `.env` and add your API keys:
   - `HUNTER_API_KEY`: Get from [Hunter.io](https://hunter.io/api) (Free tier available).
   - `BREACH_DIRECTORY_API_KEY`: (Alternative) [BreachDirectory](https://breachdirectory.org/) offers a free API for leak checks.
   - `NMAP_PATH`: Path to your nmap executable (usually `C:\Program Files (x86)\Nmap\nmap.exe`).

## 🖥️ Usage

Run the dashboard using Streamlit:
```bash
streamlit run app.py
```

## 📂 Project Structure

- `app.py`: Main Streamlit frontend.
- `src/osint/`: Modules for passive data collection (Hunter, DNS).
- `src/scanner/`: Active scanning engine using `python-nmap`.
- `src/core/`: Orchestration and Graph Management logic.

## ⚖️ Legal Disclaimer

This tool is for **educational and ethical hacking purposes only**. Unauthorized scanning of systems you do not own or have explicit permission to test is illegal. Use responsibly.

---
**Developed by [Your College Team Name]**
*Project for Final Year Ethical Hacking*
