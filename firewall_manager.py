"""
Small interactive helper to block/unblock programs and IPs
with Windows Firewall (netsh). Run from an Administrator terminal.
"""

import subprocess

import psutil


def list_connections():
    rows = []
    for c in psutil.net_connections(kind="inet"):
        if not c.raddr or not c.pid:
            continue
        try:
            p = psutil.Process(c.pid)
            rows.append((p.name(), c.pid, p.exe(), c.raddr.ip, c.raddr.port))
        except Exception:
            continue
    rows = sorted(set(rows))
    print(f"{'#':<4}{'Process':<25}{'PID':<8}{'Remote':<28}")
    for i, r in enumerate(rows):
        print(f"{i:<4}{r[0]:<25}{r[1]:<8}{r[3]}:{r[4]:<22}")
    return rows


def netsh(*args):
    subprocess.run(["netsh", "advfirewall", "firewall", *args])


def block_program(exe_path, name):
    netsh("add", "rule", f"name=Block {name}", "dir=out", "action=block", f"program={exe_path}")
    print(f"Rule 'Block {name}' created.")


def unblock_program(name):
    netsh("delete", "rule", f"name=Block {name}")
    print(f"Rule 'Block {name}' removed.")


def block_ip(ip):
    netsh("add", "rule", f"name=Block IP {ip}", "dir=out", "action=block", f"remoteip={ip}")
    print(f"IP {ip} blocked.")


def unblock_ip(ip):
    netsh("delete", "rule", f"name=Block IP {ip}")
    print(f"IP {ip} unblocked.")


def main():
    while True:
        print("\n1) Show connections  2) Block program  3) Unblock program")
        print("4) Block IP          5) Unblock IP      6) Exit")
        choice = input("Choice: ").strip()

        if choice == "1":
            list_connections()
        elif choice == "2":
            rows = list_connections()
            try:
                idx = int(input("Row number of the program: "))
                block_program(rows[idx][2], rows[idx][0])
            except (ValueError, IndexError):
                print("Invalid row number.")
        elif choice == "3":
            unblock_program(input("Program name (e.g. chrome.exe): ").strip())
        elif choice == "4":
            block_ip(input("IP: ").strip())
        elif choice == "5":
            unblock_ip(input("IP: ").strip())
        elif choice == "6":
            break


if __name__ == "__main__":
    main()
