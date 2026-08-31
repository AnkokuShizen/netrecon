<div align="center">

# 🦅 NetRecon

**Unified internal network reconnaissance — host discovery, full port scanning, deep service enumeration, and a polished HTML report. All in one script.**

[![Platform](https://img.shields.io/badge/platform-Linux-black?logo=linux&logoColor=white)](#-requirements)
[![Shell](https://img.shields.io/badge/bash-4%2B-4EAA25?logo=gnubash&logoColor=white)](#-requirements)
[![Engine](https://img.shields.io/badge/engine-nmap-4682B4)](#%EF%B8%8F-how-it-works)
[![Python](https://img.shields.io/badge/report-python%203-3776AB?logo=python&logoColor=white)](#-output-files)
[![Tested](https://img.shields.io/badge/tested%20on-Kali%20Linux-557C94?logo=kalilinux&logoColor=white)](#-requirements)

</div>

---

## 📌 Overview

**NetRecon** is a single, self-contained Bash script that turns hours of manual recon work into one command. Instead of juggling separate `nmap` sweeps, `enum4linux` runs, `nikto` scans, and half-finished notes, you point NetRecon at a network and it walks through the entire reconnaissance pipeline for you: it finds live hosts, maps every open TCP port, enumerates each service with targeted NSE scripts plus bonus tools, and finally packs everything into a clean, dark-themed HTML report you can open in any browser.

The script was built for **lab work, home-lab inventory, CTF preparation, and authorized internal assessments**. It is deliberately interactive at the dangerous checkpoints: before the long full-port scan begins, it shows you the live host list and asks for confirmation, so you always stay in control of what gets scanned.

Everything is kept transparent and reviewable — there is no magic, just a well-organized pipeline around `nmap`, with clearly labeled stages, live progress output, and raw result files preserved for manual follow-up.

## ⚙️ How It Works

NetRecon runs as a four-stage pipeline:

| Stage | What Happens | Key Output |
|:---:|---|---|
| **1️⃣ Discovery** | Classifies your targets (CIDR, IP range, single IP, or domain), resolves hostnames, and runs a fast ping/TCP discovery sweep (`-sn -PE -PS… -PA… --min-rate 5000`) | `live_ips.txt` |
| **2️⃣ Port Scan** | Full TCP scan of **all 65535 ports** (`-p- -sS -Pn -T4 --open`) on every live host, with progress printed every 30 s | `scan_results.nmap / .gnmap / .xml` |
| **3️⃣ Enumeration** | Per-host deep scan: version detection at intensity 9, OS detection, and a **service-aware NSE script mapping** (80+ scripts) plus bonus tools (`enum4linux`, `nikto`, `dnsrecon`) | `output/details_*.xml` |
| **4️⃣ Report** | An embedded Python 3 generator parses the XML results and builds `Final_Scan_Report.html`, then cleans up the temporary files | `Final_Scan_Report.html` |

### 🧠 Service-Aware Enumeration

Stage 3 is where NetRecon earns its keep. For every open port it picks NSE scripts **based on the detected service**, for example:

- **HTTP/HTTPS** — security headers, default accounts, CMS enumeration (WordPress/Drupal), Shellshock, Heartbleed, favicon-based tech detection, and more
- **SMB (445/139)** — OS discovery, share/user/group enumeration, and the classic vulnerability checks (`ms17-010`, `ms08-067`, `smb-double-pulsar-backdoor`…)
- **RDP, Kerberos, LDAP, VNC, SSH, FTP, SMTP, DNS** — dedicated script sets for each
- **Everything else** — a safe fallback layer (`default`, `safe`, `vuln`, `discovery`, `banner`, `ssl-cert`, `vulners`) so no service goes unexamined

Any service without a dedicated mapping is logged to `output/unmapped_services.log` so you can extend the map later.

## ✨ Features

- 🎯 **Flexible targets** — CIDR (`172.16.0.0/12`), dash ranges (`192.168.1.1-254`), single IPs, domain names, or any comma-separated mix
- 🔍 **Fast discovery sweep** — tuned with `--min-rate` and multiple probe types so quiet hosts still answer
- 🚪 **Full-port scanning** — all 65535 TCP ports, not just the top 1000
- 🧠 **Smart NSE mapping** — the right scripts for the right services, with a category-based fallback
- 🛡️ **CVE awareness** — the `vulners` script surfaces known vulnerabilities per service version
- 🧰 **Bonus tools with timeouts** — `enum4linux`, `nikto`, and `dnsrecon` run automatically when relevant ports are open, each capped by `timeout` so a hung tool can't stall the batch
- ⚡ **Parallel deep scans** — hosts are enumerated concurrently via `xargs -P`, tunable with `CONCURRENCY`
- 📊 **Single HTML report** — dark-themed dashboard, per-host cards, collapsible script outputs, and vulnerabilities highlighted in red
- 🧹 **Auto cleanup** — the temporary `output/` folder and report generator are removed after a successful run

## 📋 Requirements

| Component | Required? | Notes |
|---|:---:|---|
| **Linux** | ✅ Hard | Tested on Kali; works on Debian/Ubuntu and most distros |
| **Bash ≥ 4** | ✅ Hard | Uses associative arrays |
| **nmap** | ✅ Hard | The entire scanning engine |
| **python3** | ✅ Hard | Used only for Stage 4 (HTML report generation) |
| **sudo / root** | ✅ Hard | SYN scan (`-sS`) and OS detection (`-O`) need raw sockets |
| enum4linux | ➖ Optional | Skipped with a warning if missing (SMB hosts) |
| nikto | ➖ Optional | Skipped with a warning if missing (web hosts) |
| dnsrecon | ➖ Optional | Skipped with a warning if missing (DNS hosts) |

## 🚀 Installation

```bash
git clone https://github.com/AnkokuShizen/netrecon.git
cd netrecon
chmod +x netrecon.sh
```

Optional bonus tools (pre-installed on Kali):

```bash
sudo apt install enum4linux nikto dnsrecon
```

## 🕹️ Usage

```bash
# Scan a CIDR range
sudo ./netrecon.sh 172.16.0.0/12

# Scan an IP range
sudo ./netrecon.sh 192.168.1.1-254

# Mix everything: ranges, single IPs, and domains (comma-separated)
sudo ./netrecon.sh 172.16.0.0/12,10.0.0.5,server.local

# No argument? It asks interactively
sudo ./netrecon.sh
```

**What to expect:** NetRecon first prints the classified targets, then the live-host list. Before Stage 2 it asks for confirmation, because scanning all 65535 ports can take a long time on large networks — that's your chance to abort while keeping `live_ips.txt` for manual use.

**Tune the parallelism** (how many hosts are deep-scanned at once):

```bash
CONCURRENCY=8 sudo -E ./netrecon.sh 192.168.1.0/24
```

## 📁 Output Files

| File | Description |
|---|---|
| `Final_Scan_Report.html` | 📊 The main deliverable — open it in any browser |
| `live_ips.txt` | Live hosts that were discovered (and scanned) |
| `live_hosts.grep` | Raw discovery-sweep output (only if ranges were scanned) |
| `scan_results.nmap / .gnmap / .xml` | Full port-scan results in three nmap formats |

> 🧹 **Note:** The `output/` folder and `generate_report.py` are temporary working files. On a successful run they are deleted automatically; if report generation fails they are kept for debugging. All of these are covered by the repository's `.gitignore`, so scan results never end up on GitHub.

## 🎛️ Configuration

| Variable | Default | Description |
|---|---|---|
| `CONCURRENCY` | `4` | Number of hosts deep-scanned in parallel during Stage 3. Raise it on a fast machine/link, lower it on a Raspberry-Pi-style box or a saturated link. |

## 🧯 Troubleshooting

| Symptom | Cause & Fix |
|---|---|
| `This script requires bash >= 4` | You're probably on macOS's ancient bash 3.2. Run on Linux, or install a newer bash via Homebrew. |
| `Required tool 'nmap' not found` | Install it: `sudo apt install nmap` |
| `No live hosts found` | Some hosts block ping probes. The sweep already uses `-PE/-PS/-PA`; as a fallback, scan a known IP directly. |
| Report generation failed | Check that `python3` is on your `PATH`. Raw files are kept in `output/` for manual inspection. |
| `enum4linux` output is empty | Modern systems with SMB signing or SMB2-only configs often return little. Try `enum4linux-ng` manually against the host. |
| The scan takes forever | A `-p-` scan over a large range is inherently heavy. Narrow your target scope, or let it run — progress prints every 30 s. |

## ❓ FAQ

**Why does it need sudo?**
SYN scanning (`-sS`) and OS fingerprinting (`-O`) require raw socket access. The script refreshes its sudo timestamp before the long scan so it won't time out mid-run.

**Does it scan UDP?**
No. NetRecon is TCP-focused; reliable UDP scanning is orders of magnitude slower. Run targeted `nmap -sU` scans manually for specific UDP services.

**Will anyone notice the scan?**
Port scans are noisy. Switches, firewalls, and IDS/IPS solutions can absolutely log or block this. That's exactly why the tool is meant for networks you own or are authorized to test.

**Where does the report get its data?**
Stage 4 parses every `output/details_*.xml` with an embedded Python script and renders per-host cards, including NSE script outputs and bonus-tool results, into one standalone HTML file.

**Can I rename the report or keep the raw XML?**
Yes — the final report path is set in the last line of the script (`python3 generate_report.py …`), and the raw files are simply what Stage 3 left behind before cleanup.

## ⚖️ Legal Disclaimer

> [!WARNING]
> NetRecon is provided for **educational purposes and authorized security testing only**.
> Use it exclusively on networks you own or have **explicit written permission** to assess.
> Unauthorized scanning of systems you do not control is illegal in most jurisdictions and may violate computer-fraud laws.
> You are solely responsible for how you use this tool.

## 🙏 Acknowledgments

Built on the shoulders of giants:

- [nmap](https://nmap.org/) — the scanning engine and NSE scripting framework
- [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) — Windows/SMB enumeration
- [nikto](https://cirt.net/Nikto2) — web server scanner
- [dnsrecon](https://github.com/darkoperator/dnsrecon) — DNS enumeration and zone transfers
