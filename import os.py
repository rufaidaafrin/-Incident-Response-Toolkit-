import os
import json
import subprocess
import hashlib
import psutil
import requests
from datetime import datetime
from pathlib import Path

# Directory for storing incident response logs
LOG_DIR = "incident_logs"
os.makedirs(LOG_DIR, exist_ok=True)

def log_event(event, data):
    """Logs events to a JSON file for later forensic analysis."""
    log_file = os.path.join(LOG_DIR, "incident_log.json")
    entry = {"timestamp": datetime.now().isoformat(), "event": event, "data": data}
    
    with open(log_file, "a") as f:
        json.dump(entry, f)
        f.write("\n")
    print(f"[LOGGED] {event}")


def scan_network():
    """Runs an Nmap scan on the local network."""
    target = "192.168.1.1/24"  # Adjust as needed
    print("[INFO] Running network scan...")
    result = subprocess.run(["nmap", "-sV", target], capture_output=True, text=True)
    log_event("network_scan", result.stdout)
    print(result.stdout)


def collect_system_logs():
    """Collects system logs from Windows Event Viewer or Linux syslog."""
    print("[INFO] Collecting system logs...")
    if os.name == "nt":  # Windows
        logs = subprocess.run(["wevtutil", "qe", "System", "/c:10"], capture_output=True, text=True).stdout
    else:  # Linux
        logs = subprocess.run(["journalctl", "-n", "10"], capture_output=True, text=True).stdout
    
    log_event("system_logs", logs)
    print(logs)


def check_running_processes():
    """Checks running processes for suspicious activity."""
    print("[INFO] Checking running processes...")
    processes = []
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        processes.append(proc.info)
    
    log_event("running_processes", processes)
    print(json.dumps(processes, indent=2))


def hash_file(filepath):
    """Generates SHA256 hash of a file for integrity checks."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        return f"Error hashing file: {e}"


def scan_files_for_integrity():
    """Scans important files and logs their hash values."""
    print("[INFO] Scanning files for integrity...")
    files_to_check = ["/etc/passwd", "/etc/shadow"] if os.name != "nt" else ["C:\\Windows\\System32\\drivers\\etc\\hosts"]
    file_hashes = {}
    
    for file in files_to_check:
        if Path(file).exists():
            file_hashes[file] = hash_file(file)
    
    log_event("file_integrity", file_hashes)
    print(json.dumps(file_hashes, indent=2))


def check_malware_signatures():
    """Uses VirusTotal API to check file hashes against known malware."""
    API_KEY = "your_virustotal_api_key"  # Replace with an actual API key
    sample_file = "suspicious.exe"  # Replace with actual file path
    if not Path(sample_file).exists():
        print("[INFO] No suspicious files found.")
        return

    file_hash = hash_file(sample_file)
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    log_event("malware_check", response.json())
    print(response.json())


def generate_incident_report():
    """Compiles all logs into a report file."""
    print("[INFO] Generating incident report...")
    report_file = os.path.join(LOG_DIR, "incident_report.txt")
    with open(report_file, "w") as f:
        for log_file in Path(LOG_DIR).glob("*.json"):
            with open(log_file) as lf:
                f.write(lf.read() + "\n")
    print(f"[INFO] Report saved to {report_file}")


if __name__ == "__main__":
    scan_network()
    collect_system_logs()
    check_running_processes()
    scan_files_for_integrity()
    check_malware_signatures()
    generate_incident_report()
    print("[COMPLETED] Incident Response Toolkit execution finished.")
