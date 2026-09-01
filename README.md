# NetRecon — Unified Internal Network Scanner

**NetRecon** is a single, self-contained Bash script that turns hours of manual recon work into one command. Instead of juggling separate `nmap` sweeps, `enum4linux` runs, `nikto` scans, and half-finished notes, you point NetRecon at a network and it walks through the entire reconnaissance pipeline for you: it finds live hosts, maps every open TCP port, enumerates each service with targeted NSE scripts plus bonus tools, and finally packs everything into a clean, dark-themed HTML report you can open in any browser.

Everything runs from one file. No framework, no dependencies beyond `nmap` + `python3`, no config files to edit. Authorized engagements only — you are responsible for scanning networks you have permission to test.

## 🔄 The Pipeline

| Stage | What happens | Files produced |
|-------|--------------|----------------|
| **1️⃣ Discovery** | Classifies your targets (CIDR, IP range, single IP, or domain), resolves hostnames, and runs a fast ping/TCP discovery sweep (`-sn -PE -PS… -PA… --min-rate 5000`) — **in the exact order you gave them**. IPs already queued by an earlier target are skipped inside later (bigger, overlapping) ranges | `live_ips.txt`, `scan_origin.txt` |
| **1️⃣b Fresh check** | Hosts whose archived results are still recent (or were imported with `--import`) are offered **in ONE batched question**: skip them and merge the archive into the report, or re-scan them | `skipped_fresh.txt` (if any) |
| **2️⃣ Port scan** | Full TCP port scan of all 65535 ports (`-p- -sS -Pn -T4 --open --stats-every 30s`) on every live host, after your confirmation | `scan_results.nmap/.gnmap/.xml` |
| **3️⃣ Deep enum** | Per host: service/version detection + a curated NSE script set per service (HTTP, SMB, SSH, DNS, LDAP, Kerberos, RDP, DBs, …) + product-specific scripts + bonus tools (`enum4linux` on 445/139, `nikto` on 80/443/8080, `dnsrecon` on 53) — parallel, with per-host timing and a live ETA line | `output/details_<ip>.*` |
| **4️⃣ Report** | A dark-themed HTML report with stat cards, per-host cards, expandable script outputs, and every skipped host merged from the archive with an `ARCHIVED RESULT` badge | `Final_Scan_Report.html` |

## ✨ Features

- 🎯 **Flexible targets** — CIDR (`172.16.0.0/12`), dash ranges (`192.168.1.1-254`), single IPs, domain names, or any mix; separators may be commas, spaces, or even Persian/Arabic commas (`،`) — invisible RTL marks from Word/Notepad pastes are stripped automatically
- 🧭 **Input-order pipeline** — targets are processed one by one, exactly in the order given
- 🔁 **Overlap-aware** — a bigger later range automatically skips hosts already covered by an earlier target
- ♻️ **Fresh-results cache** — hosts scanned within the last week are offered for skipping in **one batched question** (no hanging in unattended runs)
- 📥 **`--import` for old results** — point it at a previous run's output folder and reuse those results: skip the finished hosts, merge them into the new report
- 🗂️ **Per-IP archive** — every scan (and every import) fills `netrecon_results/<ip>/`, so nothing is ever lost between runs
- ⏱️ **Timing & ETA** — per-host start time, NSE script count, elapsed time, plus a running progress line with average and estimated remaining time
- 🧾 **Rich HTML report** — version banners, NSE outputs (vulners CVEs highlighted), bonus tool outputs, OS guesses, and archived-host badges

## 📦 Requirements

- **bash >= 4**, **sudo** (nmap `-sS`/`-O` need root)
- **nmap** and **python3** (hard requirements)
- Optional: `enum4linux`, `nikto`, `dnsrecon` — missing ones are skipped with a warning

## 🕹️ Usage

```bash
# Scan a CIDR range
sudo ./netrecon.sh 172.16.0.0/12

# Scan an IP range
sudo ./netrecon.sh 192.168.1.1-254

# Mix everything: ranges, single IPs, and domains (comma-separated)
sudo ./netrecon.sh 172.16.0.0/12,10.0.0.5,server.local

# Separators are forgiving: plain spaces and Persian/Arabic commas (،) work too —
# handy when you paste a target list from a Persian note or Word document
sudo ./netrecon.sh "172.18.10.0/24 ، 10.140.18.0/24، 10.102.1.0/24"

# No argument? It asks interactively
sudo ./netrecon.sh

# Reuse results from a previous run (skip what's already done, merge it into the report)
./netrecon.sh --import /path/to/old-output-folder
```

**What to expect:** NetRecon first processes your targets **one by one in the exact order you typed them**, printing which host came from which target (and which ones were skipped because a bigger later range overlaps them). Then the fresh-results question appears (if any host was scanned within the last week) — answered once for all of them. Before Stage 2 it asks for confirmation, because scanning all 65535 ports can take a long time on large networks — that's your chance to abort while keeping `live_ips.txt` for manual use.

**Tune the parallelism** (how many hosts are deep-scanned at once):

```bash
CONCURRENCY=8 sudo -E ./netrecon.sh 192.168.1.0/24
```

**Unattended / scheduled runs** — the fresh question never blocks a headless run:

```bash
# non-interactive shells auto-skip fresh hosts (a notice is printed)
FRESH_POLICY=skip sudo -E ./netrecon.sh 172.16.0.0/12   # explicit, same behavior
FRESH_POLICY=keep sudo -E ./netrecon.sh 172.16.0.0/12   # never skip — always re-scan
```

## 📥 Importing results from previous runs

Already scanned parts of the network with an older tool run (or an older NetRecon)? Put the old files in any folder (the name does not matter) and import them **before** scanning:

```bash
./netrecon.sh --import Output        # your old "Output" folder
./netrecon.sh --import ./output      # default folder if you pass nothing
./netrecon.sh --import old1 old2     # several folders at once
```

No sudo needed for import. NetRecon recognizes these file types:

| File | What it becomes in the archive |
|------|--------------------------------|
| `details_<ip>.xml` | Full host record (ports, services, NSE output, OS, hostname). The **original scan date** is recovered from the XML and preserved |
| `enum4linux_<ip>.txt` / `nikto_<ip>.txt` / `dnsrecon_<ip>.txt` | Bonus tool output, merged into that host's report card |
| `*.gnmap` (any name, up to 3 subfolders deep) | Port-scan-only records: every `Host:` line with a `Ports:` field becomes an archive entry (no deep data — the report says so) |

Import is **idempotent** — re-running it never destroys newer data: an archive entry is only replaced when the imported result is strictly newer. After importing, the imported hosts always appear in the ONE batched re-scan question, no matter how old they are, and answering "no" (or just pressing Enter) skips them and merges their archived results into the final report.

## ♻️ Smart re-scanning

Every host NetRecon scans (or imports) is archived under `netrecon_results/<ip>/`:

```
netrecon_results/
└── 10.0.0.5/
    ├── last_scan.txt        # epoch, human date, target line (+ "imported: yes" for imports)
    ├── ports.txt            # open-ports summary from the full port scan
    ├── details_10.0.0.5.xml # full deep-scan XML
    ├── enum4linux_10.0.0.5.txt   # bonus outputs, when they ran
    └── nikto_10.0.0.5.txt
```

On the next run, hosts with archived results newer than `FRESH_DAYS` (default 7) — or imported ones, regardless of age — are listed together in **one question**:

- **Enter / n** → skip them; their archived results are merged into the final HTML report with an `ARCHIVED RESULT — from scan of <date>` badge
- **y** → re-scan them and refresh the archive
- `FRESH_POLICY=skip` / `keep` → decide without asking (non-interactive shells default to skip)
- `FRESH_DAYS=0` → disable the check entirely

If **every** discovered host is skipped, NetRecon switches to merge-only mode and builds the report straight from the archive — no scan needed.

## ⚙️ Configuration (environment variables)

| Variable | Default | Meaning |
|----------|---------|---------|
| `CONCURRENCY` | `4` | Hosts deep-scanned in parallel |
| `RESULTS_DIR` | `netrecon_results` | Per-IP archive location (powers fresh-check + report merge) |
| `FRESH_DAYS` | `7` | Results newer than this are "fresh" (`0` = check disabled) |
| `FRESH_POLICY` | `ask` | `ask` / `skip` / `keep` — what to do with fresh hosts |
| `PROGRESS_INTERVAL` | `15` | Seconds between deep-scan progress/ETA lines |

## 📄 Files kept at the end

| File | Content |
|------|---------|
| `Final_Scan_Report.html` | The full report (fresh + archived hosts merged) |
| `live_ips.txt` | Live hosts in scan order |
| `scan_origin.txt` | Which target contributed each host (`IP<TAB>source`) |
| `scan_results.nmap/.gnmap/.xml` | Full port scan output |
| `live_hosts.grep` | Discovery sweep output (when ranges were scanned) |
| `skipped_fresh.txt` | Hosts merged from the archive instead of being re-scanned |
| `netrecon_results/` | The per-IP archive |

## 🚑 Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Required tool 'nmap' not found` | Install it: `sudo apt install nmap` |
| `No live hosts found` | Some hosts block ping probes. The sweep already uses `-PE/-PS/-PA`; as a fallback, scan a known IP directly. |
| Report generation failed | Check that `python3` is on your `PATH`. Raw files are kept in `output/` for manual inspection. |
| `enum4linux` output is empty | Modern systems with SMB signing or SMB2-only configs often return little. Try `enum4linux-ng` manually against the host. |
| The scan takes forever | A `-p-` scan over a large range is inherently heavy. Narrow your target scope, or let it run — progress prints every 30 s. |
| I pasted targets and it says `Could not resolve '<one long line>'` | Your list used a separator the old version didn't know (pre-v2.2: e.g. Persian commas `،`). Update to the current kit, or re-run with plain commas/spaces. |

## ❓ FAQ

**Why does it need sudo?**
The full port scan uses SYN scanning (`-sS`) and OS detection (`-O`), which require raw sockets. Import mode needs no privileges at all.

**Will it scan the same host twice if two targets overlap?**
No. The first target that discovers a host owns it. Overlapping hosts found again inside a later, larger range are skipped with a notice naming the earlier target that already covered them.

**Does it do UDP scanning?**
No. NetRecon is TCP-focused; reliable UDP scanning is orders of magnitude slower. Run targeted `nmap -sU` scans manually for specific UDP services.

**Which folder do I put my old files in for `--import`?**
Any folder, any name — pass it as the argument (`./netrecon.sh --import Output`). Without an argument it looks in `./output`. It searches up to 3 subfolders deep for `.gnmap` files and reads `details_<ip>.xml` / `enum4linux_<ip>.txt` / `nikto_<ip>.txt` / `dnsrecon_<ip>.txt` from the top level of each folder you pass.

**Can I paste target lists from a Persian/Arabic document?**
Yes. ASCII commas, spaces, Persian/Arabic commas (`،`), and fullwidth commas are all accepted separators, and invisible RTL/bidi characters that ride along from Word or Notepad are stripped automatically.

**Where is the bonus-tool data of merged (skipped) hosts?**
In the archive. Since v2.1 every scan also archives `enum4linux` / `nikto` / `dnsrecon` outputs, and `--import` brings in old ones — the merged report shows them under "Bonus Tools Output" for each archived host.

---

Authorized use only — run this only against networks you own or have written permission to test.
