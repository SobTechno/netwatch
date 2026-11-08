"""
netwatch - live outbound connection monitor for Windows.

Lists which program connects to which remote address, colors each line
(green = looks normal, red = needs review) and logs everything to CSV.
"""

import csv
import ipaddress
import os
import socket
import subprocess
import time
from datetime import datetime

import psutil
from colorama import Fore, init

init(autoreset=True)

LOG_FILE = "connections_log.csv"
HEADER = ["Time", "Verdict", "Reason", "Process", "PID", "Exe Path",
          "Remote IP", "Remote Port", "Host", "Status"]

# ---------------- Rules (edit these to fit your system) ----------------

# Ports that normal software uses (web, DNS, NTP, mail, push notifications)
COMMON_PORTS = {80, 443, 53, 123, 853, 993, 995, 465, 587, 143, 5228}

# Folders where legitimate installed software usually lives
TRUSTED_DIRS = [
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    os.path.expandvars("%LOCALAPPDATA%\\Programs\\").lower(),
]

# Folders malware likes to run from
SUSPICIOUS_DIRS = [
    "\\temp\\", "\\downloads\\", "\\programdata\\",
    "\\users\\public\\", "\\$recycle.bin\\", "\\appdata\\roaming\\",
]

# Process names you personally trust (add your own, e.g. "xray.exe")
WHITELIST_NAMES = {"chrome.exe", "firefox.exe", "msedge.exe", "code.exe", "discord.exe"}

# Check the Authenticode signature with PowerShell (cached per exe)
CHECK_SIGNATURE = True

# -----------------------------------------------------------------------

seen = set()
dns_cache = {}
sig_cache = {}


def init_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="", encoding="utf-8-sig") as f:
            csv.writer(f).writerow(HEADER)


def resolve(ip):
    if ip not in dns_cache:
        try:
            dns_cache[ip] = socket.gethostbyaddr(ip)[0]
        except Exception:
            dns_cache[ip] = ""
    return dns_cache[ip]


def is_local_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except ValueError:
        return False


def is_signed(exe):
    """True if the exe has a valid Authenticode signature."""
    if not CHECK_SIGNATURE or not exe:
        return False
    if exe in sig_cache:
        return sig_cache[exe]
    try:
        safe = exe.replace("'", "''")
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-AuthenticodeSignature -LiteralPath '{safe}').Status"],
            capture_output=True, text=True, timeout=8,
        ).stdout.strip()
        sig_cache[exe] = (out == "Valid")
    except Exception:
        sig_cache[exe] = False
    return sig_cache[exe]


def classify(name, exe, ip, port):
    """Return (verdict, reason). Verdict is 'OK' or 'SUSPICIOUS'."""
    exe_l = (exe or "").lower()

    if is_local_ip(ip):
        return "OK", "local/private network"

    if not exe_l:
        return "SUSPICIOUS", "cannot read exe path (run as Administrator)"

    for d in SUSPICIOUS_DIRS:
        if d in exe_l and not any(exe_l.startswith(t) for t in TRUSTED_DIRS):
            return "SUSPICIOUS", f"runs from unusual folder ({d.strip(chr(92))})"

    port_ok = port in COMMON_PORTS

    if name.lower() in WHITELIST_NAMES and port_ok:
        return "OK", "whitelisted program, common port"
    if is_signed(exe) and port_ok:
        return "OK", "validly signed program, common port"
    if any(exe_l.startswith(t) for t in TRUSTED_DIRS) and port_ok:
        return "OK", "installed program, common port"
    if not port_ok:
        return "SUSPICIOUS", f"unusual remote port {port}"

    return "SUSPICIOUS", "unsigned program in unknown location"


def print_row(verdict, reason, name, pid, ip, port, host):
    color = Fore.GREEN if verdict == "OK" else Fore.RED
    tag = "[ OK ]" if verdict == "OK" else "[ !! ]"
    target = f"{host} ({ip}:{port})" if host else f"{ip}:{port}"
    print(color + f"{tag} {name} (PID {pid}) -> {target}  | {reason}")


def main():
    init_log()
    print(Fore.CYAN + "Monitoring connections... press Ctrl+C to stop")
    print(Fore.GREEN + "Green = looks normal   " + Fore.RED + "Red = needs review\n")

    try:
        while True:
            for c in psutil.net_connections(kind="inet"):
                if not c.raddr or not c.pid:
                    continue
                key = (c.pid, c.raddr.ip, c.raddr.port)
                if key in seen:
                    continue
                seen.add(key)

                try:
                    p = psutil.Process(c.pid)
                    name, exe = p.name(), p.exe()
                except Exception:
                    name, exe = "unknown", ""

                ip, port = c.raddr.ip, c.raddr.port
                host = resolve(ip)
                verdict, reason = classify(name, exe, ip, port)
                print_row(verdict, reason, name, c.pid, ip, port, host)

                with open(LOG_FILE, "a", newline="", encoding="utf-8-sig") as f:
                    csv.writer(f).writerow([
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"), verdict, reason,
                        name, c.pid, exe, ip, port, host, c.status,
                    ])
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
