import argparse
import subprocess
import re
import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

# ANSI Colors for terminal
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

def check_nmap():
    """Check if Nmap is installed."""
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"{RED}[-] Nmap is not installed! Please install it with: sudo apt install nmap{RESET}")
        exit(1)

def check_vulscan():
    """Check if Vulscan is installed, if not download it."""
    vulscan_path = os.path.expanduser("~/vulscan")
    if not os.path.exists(vulscan_path):
        print(f"{CYAN}[+] Vulscan not found. Downloading...{RESET}")
        subprocess.run(["git", "clone", "https://github.com/scipag/vulscan.git", vulscan_path])
        print(f"{GREEN}[✓] Vulscan installed successfully at {vulscan_path}{RESET}")
    else:
        print(f"{CYAN}[+] Updating Vulscan database...{RESET}")
        subprocess.run(["git", "-C", vulscan_path, "pull"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_nmap_ports(target):
    """Run a fast Nmap scan to find open ports."""
    print(f"{CYAN}[+] Discovering open ports on {target}...{RESET}")
    result = subprocess.run(
        ["nmap", "-sS", "--min-rate", "5000", "--top-ports", "1000", target],
        capture_output=True, text=True
    )
    return result.stdout

def parse_open_ports(output):
    """Extract open ports from Nmap output."""
    ports = []
    for line in output.split("\n"):
        port_match = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if port_match:
            ports.append(port_match.group(1))
    return ports

def run_vulscan_realtime(target, ports):
    """Run Vulscan and show vulnerabilities in real time."""
    vulscan_path = os.path.expanduser("~/vulscan")
    script_path = os.path.join(vulscan_path, "vulscan.nse")
    print(f"{CYAN}[+] Running Vulscan on ports: {', '.join(ports)}{RESET}")

    process = subprocess.Popen(
        ["nmap", "-sV", "-p", ",".join(ports), "--script", script_path, target],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    data = []
    current_host = target
    current_port = None
    current_service = None

    for line in process.stdout:
        line = line.strip()

        port_match = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if port_match:
            current_port, current_service = port_match.groups()
            print(f"{GREEN}[+] Found open port: {current_port} ({current_service}){RESET}")
            data.append([current_host, current_port, current_service, ""])
            print(f"{CYAN}[*] Searching for vulnerabilities on port {current_port}...{RESET}")

        vuln_match = re.search(r"(CVE-\d{4}-\d+|EDB-ID:\d+|MS\d{2}-\d{3})", line)
        if vuln_match and data:
            vuln = vuln_match.group(0)
            print(f"{RED}[!] Vulnerability found: {vuln} on port {current_port}{RESET}")
            data[-1][3] += vuln + "\n"

    process.wait()
    return data

def save_pdf(filename, table_data):
    """Save results into a PDF table."""
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    title = Paragraph("<b>Vulscan Vulnerability Scan Results</b>", styles['Title'])

    table_data.insert(0, ["Host", "Port", "Service", "Vulnerabilities"])
    table = Table(table_data, colWidths=[100, 60, 100, 280])

    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 12),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),

        # Center Host, Port, and Service columns
        ("ALIGN", (0, 1), (2, -1), "CENTER"),
        ("VALIGN", (0, 1), (2, -1), "MIDDLE"),

        # Keep vulnerabilities left-aligned
        ("ALIGN", (3, 1), (3, -1), "LEFT"),
        ("VALIGN", (3, 1), (3, -1), "TOP"),
        ("TEXTCOLOR", (3, 1), (3, -1), colors.red),

        ("GRID", (0, 0), (-1, -1), 1, colors.black),
    ])
    table.setStyle(style)
    doc.build([title, table])

def main():
    parser = argparse.ArgumentParser(description="Fast vulnerability scanner using Nmap + Vulscan")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-o", "--output", required=True, help="Output PDF filename")
    args = parser.parse_args()

    check_nmap()
    check_vulscan()

    ports_output = run_nmap_ports(args.target)
    open_ports = parse_open_ports(ports_output)

    if not open_ports:
        print(f"{RED}[-] No open ports found.{RESET}")
        return

    parsed_data = run_vulscan_realtime(args.target, open_ports)

    if parsed_data:
        save_pdf(args.output, parsed_data)
        print(f"{GREEN}[+] PDF report saved as: {args.output}{RESET}")
    else:
        print(f"{CYAN}[-] No vulnerabilities found.{RESET}")

if __name__ == "__main__":
    main()
