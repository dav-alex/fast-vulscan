# fast-vulscan

**fast-vulscan** is an automated network scanning and vulnerability detection tool that combines **Nmap** with the **Vulscan** database to quickly identify open ports, running services, and known vulnerabilities.  
It also generates a **professional PDF report** with neatly formatted results.

---


## 📌 Features
- Automatic open port discovery (no need to manually specify ports).
- Service and version detection.
- Vulnerability matching using **Vulscan**.
- Color-coded real-time terminal output.
- PDF report generation with a clean, professional table layout.

---


## 🚀 Installation
1. **Clone the repository**
git clone git@github.com:dav-alex/fast-vulscan.git
cd fast-vulscan


2. **Install ReportLab**
pip install reportlab


3. **Vulscan will be automatically downloaded if it is not present.**

---


## 🛠  Usage
python3 fast-vulscan.py -t <TARGET_IP> -o <OUTPUT_PDF>


**Example:**
python3 fast-vulscan.py -t 10.10.10.10 -o scan_report.pdf



This will:

Scan the target for open ports.

Identify running services.

Search for known vulnerabilities via Vulscan.

Generate a PDF report with results.

---


## 📂 Output

Terminal output.
PDF report.

---


## 📜 License

MIT License – You are free to use, modify, and distribute this software with attribution.

