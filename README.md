# netwatch

A tiny Windows tool that shows **which program is connecting to which remote address**,
colors each connection (green = looks normal, red = needs review), logs everything to CSV,
and lets you block programs or IPs with Windows Firewall.

Built for people who suspect something on their PC is phoning home and want a quick,
readable overview without installing heavy tools.

## Features

- Live list of outbound connections with process name, PID, exe path, remote IP/port and reverse-DNS host
- Heuristic verdict per connection (signature check, install folder, port, local vs. remote)
- CSV log you can open in Excel (UTF-8 with BOM)
- Interactive firewall helper: block/unblock a program or an IP

## Requirements

- Windows 10/11
- Python 3.9+
- An **Administrator** terminal (otherwise many process paths cannot be read)

## Install

```powershell
git clone https://github.com/sobtechno/netwatch.git
cd netwatch
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

If PowerShell blocks `activate`:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Usage

Monitor connections (writes `connections_log.csv` next to the script):

```powershell
python monitor.py
```

Block / unblock programs and IPs:

```powershell
python firewall_manager.py
```

## Reading the output

```
[ OK ] chrome.exe (PID 5120) -> www.google.com (142.250.x.x:443)  | whitelisted program, common port
[ !! ] updater.exe (PID 7788) -> 45.xx.xx.xx:4444  | runs from unusual folder (temp)
```

Customize the rules at the top of `monitor.py`: `COMMON_PORTS`, `TRUSTED_DIRS`,
`SUSPICIOUS_DIRS` and `WHITELIST_NAMES`.

## Limitations

- **Green does not mean safe.** Malware can inject into a trusted process and use port 443.
- **Red does not mean malware.** Games, torrent clients, VPN/proxy cores and small unsigned
  tools are often flagged. Review them manually.
- If you use a local proxy/VPN (v2ray, Clash, etc.), other programs' traffic goes through the
  proxy process, so you only see the connection to the proxy server.
- Very short-lived connections (under ~0.5 s) can be missed because the tool polls.
- It shows domains/IPs only, not URL paths or traffic content.

## Privacy

Log files contain your username, PC name, program paths and IPs. They are excluded by
`.gitignore` - do not commit or share them publicly without cleaning them first.

## Disclaimer

Use only on computers you own or are authorized to administer.
Firewall rules are persistent; remove them with `firewall_manager.py` or `wf.msc`.

## License

MIT
