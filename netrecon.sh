#!/bin/bash
# ==========================================
# NetRecon — Unified Internal Network Scanner
# (host discovery + full port scan + deep enumeration + HTML report, all in one)
# ==========================================
# What it does, in order:
#   STAGE 1: Get target(s) — from the command line argument, or by asking
#            interactively when no argument is given. Accepted per target:
#              - CIDR range    e.g. 172.16.0.0/12     -> host discovery sweep on the range
#              - IP range      e.g. 192.168.1.1-254   -> host discovery sweep on the range
#              - single IP     e.g. 10.0.0.5          -> scanned directly (no sweep)
#              - domain name   e.g. server.local      -> resolved to an IP (shown), scanned directly
#            Multiple targets can be given comma-separated:
#              172.16.0.0/12,10.0.0.5,server.local
#            Separators: ASCII commas, plain spaces, and the Persian/Arabic
#            comma "،" (and fullwidth "，") are ALL accepted, so a list pasted
#            from a non-English note still parses. Invisible RTL/bidi marks
#            that ride along from Word/Notepad copies are stripped too.
#            Targets are processed EXACTLY in the order you give them. An IP
#            already queued by an earlier target is skipped inside later
#            (bigger, overlapping) ranges — first target wins.
#   STAGE 1b: Fresh-results check — ONE question for ALL hosts: IPs whose
#            archived results (RESULTS_DIR/<ip>/last_scan.txt) are younger
#            than FRESH_DAYS are listed together; answering "no" (or running
#            non-interactively) skips them, and their archived results are
#            merged into the final HTML report instead of being lost.
#   STAGE 2: Full TCP port scan (-p- -sS -Pn -T4 --open) on all live hosts
#            (asks for confirmation first, showing the live host list)
#   STAGE 3: Deep per-host enumeration (service/version/NSE scripts +
#            enum4linux / nikto / dnsrecon bonus tools) with per-host start
#            time, elapsed time and a running ETA progress line
#   STAGE 4: HTML report generation -> Final_Scan_Report.html
#            (hosts skipped by the fresh-results check appear in the report
#            from the archive, marked with an ARCHIVED RESULT badge)
#
# Usage:
#   ./netrecon.sh [target(s)]
#     ./netrecon.sh 172.16.0.0/12
#     ./netrecon.sh 172.16.0.0/12,10.0.0.5,server.local
#     ./netrecon.sh            (asks interactively)
#
#   ./netrecon.sh --import [FOLDER ...]
#     Reuse results from a PREVIOUS run: point it at the old output folder
#     (details_*.xml, enum4linux_/nikto_/dnsrecon_*.txt, scan_results.gnmap).
#     Everything is copied into RESULTS_DIR/<ip>/ so the fresh-results check
#     and the report merge can use it. NO sudo / nmap needed. Imported hosts
#     ALWAYS show up in the ONE batched re-scan question, no matter how old
#     they are (FRESH_POLICY=keep forces a full re-scan of them).
#
# Environment:
#   CONCURRENCY=4          number of hosts deep-scanned in parallel
#   RESULTS_DIR=netrecon_results   per-IP archive powering the fresh-results check
#   FRESH_DAYS=7           archived results newer than this are "fresh"
#   FRESH_POLICY=ask       ask | skip | keep   (what to do with fresh hosts)
#                          imported archives are always offered regardless of age
#   PROGRESS_INTERVAL=15   seconds between deep-scan progress/ETA lines
#
# Requires: nmap, python3  (hard requirements)
# Optional: enum4linux, nikto, dnsrecon (missing ones are skipped with a warning)
#
# Files kept at the end (for manual review):
#   live_ips.txt (scan order), scan_origin.txt (IP -> source target),
#   live_hosts.grep (if ranges were scanned),
#   scan_results.nmap / .gnmap / .xml, Final_Scan_Report.html,
#   skipped_fresh.txt (if any), RESULTS_DIR/ per-IP archive
# ==========================================

set -o pipefail

# Associative arrays need bash >= 4
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "[-] This script requires bash >= 4 (associative arrays)."
    exit 1
fi

# How many hosts to deep-scan concurrently. Tune to your link/CPU.
CONCURRENCY="${CONCURRENCY:-4}"

# --- re-scan intelligence ------------------------------------------------
# Where the per-IP results archive lives. Each scanned (or imported) host
# gets RESULTS_DIR/<ip>/ with last_scan.txt, ports.txt, details_<ip>.xml
# and any bonus tool outputs. The fresh-results check and the report merge
# are both powered by this archive.
RESULTS_DIR="${RESULTS_DIR:-netrecon_results}"
FRESH_DAYS="${FRESH_DAYS:-7}"          # 0 = disable the fresh check entirely
FRESH_POLICY="${FRESH_POLICY:-ask}"    # ask | skip | keep
PROGRESS_INTERVAL="${PROGRESS_INTERVAL:-15}"   # seconds between ETA lines

SCAN_EPOCH=$(date +%s)

TARGET_DISPLAY=""
JOBLIST=""
PROGRESS_FILE=""
trap 'rm -f "$JOBLIST" "$PROGRESS_FILE" discovery_tmp_*.grep 2>/dev/null' EXIT

# --- IPv4 shape check (used by target parsing AND --import) ---------------
is_single_ip() {
    local ip="$1" x
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local o
    IFS='.' read -r -a o <<< "$ip"
    for x in "${o[@]}"; do
        (( 10#$x <= 255 )) || return 1
    done
    return 0
}

# ==========================================
# 0b. --import MODE — ingest results from a PREVIOUS run
#     ./netrecon.sh --import [FOLDER ...]     (default folder: ./output)
#     Understands: details_<ip>.xml, enum4linux_/nikto_/dnsrecon_<ip>.txt,
#     and port-scan-only *.gnmap files (Host: lines carrying a Ports: field).
#     Needs NO sudo and NO nmap. Idempotent: an archive entry is only
#     replaced when the imported result is strictly NEWER.
# ==========================================
if [ "${1:-}" = "--import" ]; then
    shift
    if [ $# -eq 0 ]; then
        echo "[i] No folder given — defaulting to ./output"
        set -- ./output
    fi

    IMPORT_FULL=0
    IMPORT_PORTONLY=0
    IMPORT_BONUS=0
    IMPORT_KEPT=0

    for dir in "$@"; do
        if [ ! -d "$dir" ]; then
            echo "[!] Folder not found, skipping: $dir"
            continue
        fi
        echo ""
        echo "[*] Importing previous results from: $dir"

        # ---- pass 1: detailed per-host XML results ----
        for xf in "$dir"/details_*.xml; do
            [ -e "$xf" ] || continue
            base=$(basename "$xf")
            ip="${base#details_}"; ip="${ip%.xml}"
            if ! is_single_ip "$ip"; then
                echo "[!]   Skipping '$base' — expected details_<ip>.xml naming"
                continue
            fi
            xepoch=$(python3 - "$xf" <<'PY'
import sys, os
import xml.etree.ElementTree as ET
try:
    v = ET.parse(sys.argv[1]).getroot().get('start')
    print(int(v))
except Exception:
    try:
        print(int(os.path.getmtime(sys.argv[1])))
    except Exception:
        print(0)
PY
)
            ts_file="$RESULTS_DIR/$ip/last_scan.txt"
            if [ -f "$ts_file" ]; then
                cur=$(head -n1 "$ts_file" 2>/dev/null)
                case "$cur" in ''|*[!0-9]*) cur=0 ;; esac
                if [ "$xepoch" -le "$cur" ]; then
                    cur_h=$(date -d @"$cur" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "$cur")
                    echo "[=]   $ip — archive already has same/newer results ($cur_h), keeping them."
                    IMPORT_KEPT=$((IMPORT_KEPT + 1))
                    continue
                fi
            fi
            mkdir -p "$RESULTS_DIR/$ip"
            cp -f "$xf" "$RESULTS_DIR/$ip/details_$ip.xml"
            {
                echo "$xepoch"
                date -d @"$xepoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S'
                echo "targets: imported from $dir"
                echo "imported: yes"
            } > "$ts_file"
            python3 - "$RESULTS_DIR/$ip/details_$ip.xml" > "$RESULTS_DIR/$ip/ports.txt" <<'PYPORTS'
import sys
import xml.etree.ElementTree as ET
parts = []
try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception:
    print("")
    raise SystemExit
for h in root.findall('host'):
    pe = h.find('ports')
    if pe is None:
        continue
    for p in pe.findall('port'):
        se = p.find('state')
        if se is None or se.get('state') != 'open':
            continue
        sv = p.find('service')
        name = sv.get('name', '') if sv is not None else ''
        prod = (sv.get('product', '') if sv is not None else '').strip()
        ver  = (sv.get('version', '') if sv is not None else '').strip()
        tail = (prod + ' ' + ver).strip()
        s = p.get('portid', '') + "/open/" + p.get('protocol', '') + "//" + name + "//"
        s = s + tail + "/" if tail else s + "/"
        parts.append(s)
print(", ".join(parts))
PYPORTS
            echo "[+]   $ip — details XML imported"
            IMPORT_FULL=$((IMPORT_FULL + 1))
        done

        # ---- pass 2: bonus tool text outputs ----
        for tool in enum4linux nikto dnsrecon; do
            for bf in "$dir"/${tool}_*.txt; do
                [ -e "$bf" ] || continue
                base=$(basename "$bf")
                ip="${base#${tool}_}"; ip="${ip%.txt}"
                is_single_ip "$ip" || continue
                dst="$RESULTS_DIR/$ip/$base"
                if [ -f "$dst" ] && ! [ "$bf" -nt "$dst" ]; then
                    continue   # archive copy is same/newer
                fi
                mkdir -p "$RESULTS_DIR/$ip"
                cp -f "$bf" "$dst"
                echo "[+]   $ip — bonus file archived: $base"
                IMPORT_BONUS=$((IMPORT_BONUS + 1))
            done
        done

        # ---- pass 3: port-scan-only records from *.gnmap ----
        while IFS= read -r gf; do
            [ -e "$gf" ] || continue
            gepoch=$(stat -c %Y "$gf" 2>/dev/null || echo 0)
            while IFS= read -r line; do
                case "$line" in *"Ports:"*) ;; *) continue ;; esac
                ip=$(printf '%s' "$line" | awk '{print $2}')
                is_single_ip "$ip" || continue
                # a host with full details XML is handled by pass 1
                [ -f "$RESULTS_DIR/$ip/details_$ip.xml" ] && continue
                ts_file="$RESULTS_DIR/$ip/last_scan.txt"
                if [ -f "$ts_file" ]; then
                    cur=$(head -n1 "$ts_file" 2>/dev/null)
                    case "$cur" in ''|*[!0-9]*) cur=0 ;; esac
                    if [ "$gepoch" -le "$cur" ]; then
                        IMPORT_KEPT=$((IMPORT_KEPT + 1))
                        continue
                    fi
                fi
                mkdir -p "$RESULTS_DIR/$ip"
                printf '%s\n' "$line" | awk -F'\t' '{for(i=1;i<=NF;i++) if($i ~ /^Ports:/) {print substr($i,8); exit}}' > "$RESULTS_DIR/$ip/ports.txt"
                {
                    echo "$gepoch"
                    date -d @"$gepoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S'
                    echo "targets: imported from $dir (port scan only)"
                    echo "imported: yes"
                } > "$ts_file"
                echo "[+]   $ip — port-scan-only record imported from $(basename "$gf")"
                IMPORT_PORTONLY=$((IMPORT_PORTONLY + 1))
            done < <(grep "Ports:" "$gf")
        done < <(find "$dir" -maxdepth 3 -name "*.gnmap" 2>/dev/null)
    done

    echo ""
    echo "[+] Import finished: $IMPORT_FULL full result(s), $IMPORT_PORTONLY port-only record(s), $IMPORT_BONUS bonus file(s)"
    [ "$IMPORT_KEPT" -gt 0 ] && echo "    ($IMPORT_KEPT import(s) skipped — the archive already had same/newer results)"
    exit 0
fi

# ==========================================
# 0. PREFLIGHT: privileges + dependency checks
# ==========================================
echo "[*] Checking privileges and dependencies..."

sudo -v || { echo "[-] sudo is required (nmap -sS / -O need root)."; exit 1; }

for req in nmap python3; do
    command -v "$req" >/dev/null 2>&1 || { echo "[-] Required tool '$req' not found in PATH."; exit 1; }
done

for opt in enum4linux nikto dnsrecon; do
    command -v "$opt" >/dev/null 2>&1 || echo "[!] Warning: '$opt' not found — that bonus scan will be skipped."
done

# a skipped_fresh.txt left over from a PREVIOUS run must not leak into this
# run's report merge — it is rewritten only when this run actually skips
rm -f skipped_fresh.txt

# ==========================================
# 1. TARGET INPUT (command-line argument, or interactive prompt)
# ==========================================
if [ $# -ge 1 ]; then
    # "$*" joins ALL positional args with spaces — so an unquoted paste like
    #   ./netrecon.sh 10.0.0.0/24, 10.0.0.5, ...
    # can never silently lose everything after the first space (old bug: only
    # $1 was read and the rest of the targets vanished). The sanitizer below
    # then normalizes the joined string anyway.
    TARGETS_RAW="$*"
    echo "[+] Target(s) taken from command line: $TARGETS_RAW"
else
    echo "[*] No target given on the command line."
    echo "    Examples: 172.16.0.0/12 | 192.168.1.1-254 | 10.0.0.5 | server.local"
    echo "              (comma-separated mix is allowed)"
    while [ -z "${TARGETS_RAW// /}" ]; do
        if ! read -rp "[?] Enter target(s) (CIDR / IP range / single IP / domain): " TARGETS_RAW; then
            echo "[-] No interactive input available. Pass the target as an argument:"
            echo "    $0 <cidr|ip-range|ip|domain>[,...]"
            exit 1
        fi
    done
fi

# --- input sanitizer: make non-English pastes safe -------------------------
# 1) strip invisible characters that ride along when text is copied from
#    RTL documents (Word / Notepad in Persian): bidi marks, zero-width
#    chars, BOM — they glue themselves to the last IP and break parsing
for _zw in $'\u200B' $'\u200C' $'\u200D' $'\u200E' $'\u200F' \
           $'\u202A' $'\u202B' $'\u202C' $'\u202D' $'\u202E' \
           $'\u2066' $'\u2067' $'\u2068' $'\u2069' $'\uFEFF'; do
    TARGETS_RAW="${TARGETS_RAW//"$_zw"/}"
done
# 2) normalize non-ASCII separators to ASCII commas:
#    U+060C "،" Arabic/Persian comma | U+066C "٬" Arabic thousands sep
#    | U+FF0C "，" fullwidth comma (CJK keyboards)
TARGETS_RAW="${TARGETS_RAW//$'\u060C'/,}"
TARGETS_RAW="${TARGETS_RAW//$'\u066C'/,}"
TARGETS_RAW="${TARGETS_RAW//$'\uFF0C'/,}"

TARGET_DISPLAY="$TARGETS_RAW"

# ==========================================
# 2. TARGET CLASSIFICATION
#    range  -> ping discovery sweep first
#    single -> scanned directly, no sweep
#    domain -> resolved to an IP first (and shown), then scanned as single IP
# ==========================================
echo ""
echo "=========================================="
echo "[*] STAGE 1/4: TARGET CLASSIFICATION + HOST DISCOVERY"
echo "=========================================="
echo "[*] Processing targets in the exact order given..."

is_ip_range() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] && return 0   # CIDR
    [[ "$1" =~ ^[0-9][0-9.]*-[0-9][0-9.]*$ ]] && return 0                # dash range
    return 1
}

resolve_host() {
    # Print the first IPv4 address of a hostname (empty string if unresolvable)
    local host="$1" ip=""
    if command -v getent >/dev/null 2>&1; then
        ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}')
    fi
    if [ -z "$ip" ] && command -v dig >/dev/null 2>&1; then
        ip=$(dig +short A "$host" 2>/dev/null | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n1)
    fi
    if [ -z "$ip" ] && command -v host >/dev/null 2>&1; then
        ip=$(host -t A "$host" 2>/dev/null | awk '/has address/ {print $NF; exit}')
    fi
    if [ -z "$ip" ] && command -v nslookup >/dev/null 2>&1; then
        ip=$(nslookup "$host" 2>/dev/null | awk '/^Address/ {print $NF}' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | tail -n1)
    fi
    echo "$ip"
}

IFS=',' read -r -a RAW_TOKENS <<< "$TARGETS_RAW"

# also split every comma-token on whitespace, so a list pasted with plain
# spaces ("10.0.0.1 10.0.0.0/24 server.local") acts like a comma list too
RAW_TOKENS2=()
for _ctok in "${RAW_TOKENS[@]}"; do
    read -r -a _wparts <<< "$_ctok"
    for _wp in "${_wparts[@]}"; do
        RAW_TOKENS2+=("$_wp")
    done
done
RAW_TOKENS=("${RAW_TOKENS2[@]}")
unset RAW_TOKENS2 _ctok _wparts _wp

# ==========================================
# IN-ORDER TARGET PROCESSING
#   Targets are handled one by one, EXACTLY in the order given. The first
#   target that queues an IP owns it: any later target (e.g. a bigger range
#   that contains an earlier one) skips the IPs already covered.
# ==========================================
declare -A SEEN_IP
declare -A ORIGIN_OF
QUEUE=live_ips.txt
ORIGIN_MAP=scan_origin.txt
TOKEN_N=0
SWEEP_N=0

: > "$QUEUE"
: > "$ORIGIN_MAP"
rm -f live_hosts.grep

queue_ip() {
    # queue_ip <ip> <source-target> — queue once, skip with notice afterwards
    local ip="$1" src="$2"
    if [[ -n "${SEEN_IP[$ip]+x}" ]]; then
        echo "[!]   $ip skipped — already covered by earlier target: ${ORIGIN_OF[$ip]}"
        return 0
    fi
    SEEN_IP[$ip]=1
    ORIGIN_OF[$ip]="$src"
    echo "$ip" >> "$QUEUE"
    printf '%s\t%s\n' "$ip" "$src" >> "$ORIGIN_MAP"
    echo "[+]   $ip queued (source: $src)"
}

for token in "${RAW_TOKENS[@]}"; do
    # trim surrounding whitespace
    t="${token#"${token%%[![:space:]]*}"}"
    t="${t%"${t##*[![:space:]]}"}"
    [ -z "$t" ] && continue
    TOKEN_N=$((TOKEN_N + 1))

    if is_single_ip "$t"; then
        echo "[*] Target #$TOKEN_N: single IP -> $t"
        queue_ip "$t" "$t"
    elif is_ip_range "$t"; then
        SWEEP_N=$((SWEEP_N + 1))
        SWEEP_OUT="discovery_tmp_${SWEEP_N}.grep"
        echo ""
        echo "[*] Target #$TOKEN_N: range -> $t (running host discovery sweep)"
        if nmap -sn -PE -PS80,443,22,3389 -PA80,443 -n -T4 --min-rate 5000 --max-retries 1 "$t" -oG "$SWEEP_OUT"; then
            mapfile -t FOUND_IPS < <(grep "Up$" "$SWEEP_OUT" | awk '{print $2}')
            if [ "${#FOUND_IPS[@]}" -eq 0 ]; then
                echo "[!]   No live hosts answered in $t"
            else
                for fip in "${FOUND_IPS[@]}"; do
                    queue_ip "$fip" "$t"
                done
            fi
        else
            echo "[-]   Host discovery sweep failed for '$t' — skipping this target, continuing with the rest."
        fi
    else
        # defensive: a leftover token that still contains an IP/CIDR but is
        # not a clean target means an exotic separator glued targets together
        if [[ "$t" =~ [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})? ]]; then
            echo "[!] Target #$TOKEN_N: '$t' contains an IP/CIDR but is not a clean single target."
            echo "    It looks like several targets glued together by an unusual separator."
            echo "    Separate targets with commas, spaces, or Persian commas (،) — skipping this blob."
            echo "[!]   Could not use '$t' — skipping it."
            continue
        fi
        echo "[*] Target #$TOKEN_N: domain -> $t (resolving... )"
        ip=$(resolve_host "$t")
        if [ -n "$ip" ]; then
            echo "[+]   Resolved: $t -> $ip"
            queue_ip "$ip" "$t"
        else
            echo "[!] Could not resolve '$t' — skipping it."
        fi
    fi
done

# merge the per-range sweep outputs into the classic live_hosts.grep
cat discovery_tmp_*.grep > live_hosts.grep 2>/dev/null || :
rm -f discovery_tmp_*.grep

if [ ! -s "$QUEUE" ]; then
    echo ""
    echo "[-] No live hosts found for any target. Exiting."
    exit 1
fi

# ==========================================
# 2b. FRESH-RESULTS CHECK — ONE question for ALL hosts
#     IPs whose archived results (RESULTS_DIR/<ip>/last_scan.txt) are newer
#     than FRESH_DAYS are offered for skipping in a single batched question.
#     Skipped hosts are NOT re-scanned; their archived results are merged
#     into the final HTML report instead.
# ==========================================
SKIP_SCAN=0
SKIP_FRESH=0
FRESH_LIST=$(mktemp)

if [ "$FRESH_DAYS" -gt 0 ]; then
    while IFS= read -r ip; do
        ts_file="$RESULTS_DIR/$ip/last_scan.txt"
        [ -f "$ts_file" ] || continue
        # results brought in via --import are ALWAYS offered for skipping,
        # no matter how old they are — the user imported them on purpose
        if grep -q '^imported:' "$ts_file" 2>/dev/null; then
            echo "$ip" >> "$FRESH_LIST"
            continue
        fi
        ts=$(head -n1 "$ts_file" 2>/dev/null)
        case "$ts" in
            ''|*[!0-9]*) continue ;;
        esac
        if [ $(( SCAN_EPOCH - ts )) -le $(( FRESH_DAYS * 86400 )) ]; then
            echo "$ip" >> "$FRESH_LIST"
        fi
    done < live_ips.txt
fi

if [ -s "$FRESH_LIST" ]; then
    FRESH_COUNT=$(wc -l < "$FRESH_LIST" | tr -d ' ')
    echo ""
    echo "[i] $FRESH_COUNT host(s) already have usable results in $RESULTS_DIR/ (newer than $FRESH_DAYS day(s), or imported):"
    head -n 20 "$FRESH_LIST" | sed 's/^/        /'
    [ "$FRESH_COUNT" -gt 20 ] && echo "        ... and $((FRESH_COUNT - 20)) more"
    DO_SKIP="y"
    if [ "$FRESH_POLICY" = "keep" ]; then
        DO_SKIP="n"
        echo "[i] FRESH_POLICY=keep — re-scanning them."
    elif [ "$FRESH_POLICY" = "skip" ]; then
        DO_SKIP="y"
        echo "[i] FRESH_POLICY=skip — skipping them without asking."
    elif [ ! -t 0 ]; then
        DO_SKIP="y"
        echo "[i] Not running in an interactive terminal — skipping them automatically."
        echo "    (run with FRESH_POLICY=keep to force a re-scan of these hosts)"
    else
        echo "[?] Answer ONCE for all of them. (Their archived results stay on disk either way.)"
        read -rp "[?] Re-scan these $FRESH_COUNT host(s)? [y/N] " ANS
        case "$ANS" in
            [yY]*) DO_SKIP="n" ;;
            *)     DO_SKIP="y" ;;
        esac
    fi
    if [ "$DO_SKIP" = "y" ]; then
        cp -f "$FRESH_LIST" skipped_fresh.txt
        grep -vxF -f "$FRESH_LIST" live_ips.txt > live_ips.txt.tmp
        mv live_ips.txt.tmp live_ips.txt
        SKIP_FRESH=1
        echo "[i] $FRESH_COUNT host(s) will NOT be re-scanned — their archived results will be merged into the final HTML report."
    fi
fi
rm -f "$FRESH_LIST"

LIVE_COUNT=$(wc -l < live_ips.txt | tr -d ' ')
if [ "$LIVE_COUNT" -eq 0 ]; then
    if [ "$SKIP_FRESH" -eq 1 ]; then
        echo ""
        echo "[i] Nothing new to scan — every discovered host already has fresh results."
        echo "[i] Generating the merged report from the archive only..."
        SKIP_SCAN=1
    else
        echo "[-] No live hosts found. Exiting."
        exit 1
    fi
fi

echo ""
echo "[+] Discovery finished (input order preserved) — $LIVE_COUNT live host(s) queued for scanning:"
n=0
while IFS= read -r ip; do
    n=$((n + 1))
    [ "$n" -gt 20 ] && break
    echo "      $n. $ip   (source: ${ORIGIN_OF[$ip]})"
done < live_ips.txt
[ "$LIVE_COUNT" -gt 20 ] && echo "      ... and $((LIVE_COUNT - 20)) more"

# Confirmation before the long full-port scan (skipped entirely in merge-only mode)
if [ "$SKIP_SCAN" -eq 0 ]; then
    read -rp "[?] Next: full TCP port scan (-p-, all 65535 ports) on these hosts. This can take a LONG time. Continue? [Y/n] " CONFIRM
    if [[ "$CONFIRM" == [nN]* ]]; then
        echo "[-] Aborted by user. Live host list kept in live_ips.txt for manual use."
        exit 0
    fi
fi

# ==========================================
# STAGES 2-3 — skipped entirely in merge-only mode (everything was fresh)
# ==========================================
if [ "$SKIP_SCAN" -eq 0 ]; then

# ==========================================
# 3. FULL PORT SCAN (exact original command)
# ==========================================
echo ""
echo "=========================================="
echo "[*] STAGE 2/4: FULL TCP PORT SCAN (-p-)"
echo "=========================================="
sudo -v   # refresh sudo timestamp before the long scan
sudo nmap -iL live_ips.txt \
  -p- \
  -sS \
  -Pn \
  -T4 \
  --open \
  --stats-every 30s \
  -oA scan_results

if [ ! -f scan_results.gnmap ]; then
    echo "[-] Port scan failed — scan_results.gnmap not found. Exiting."
    exit 1
fi
echo "[+] Port scan finished. Results: scan_results.{nmap,gnmap,xml}"

# ==========================================
# GLOBAL SCRIPTS + FALLBACK CATEGORIES
# ==========================================
# These always run. "vuln" and "default" are NSE *categories*, not single
# scripts -- nmap resolves them against whatever service/version it detects,
# so this is the safety net for any service NOT in SERVICE_SCRIPTS below.
GLOBAL_SCRIPTS=(
    "banner"
    "ssl-cert"
    "ssl-enum-ciphers"
    "vulners"
    "default"
    "safe"
    "vuln"
    "discovery"
)

# ==========================================
# 4. SERVICE MAPPING (extra depth on top of the category fallback above)
# ==========================================
declare -A SERVICE_SCRIPTS
SERVICE_SCRIPTS=(
    ["http"]="http-title,http-headers,http-server-header,http-methods,http-security-headers,http-enum,http-favicon,http-generator,http-date,http-robots.txt,http-useragent-tester,http-cors,http-cookie-flags,http-trace,http-auth,http-auth-finder,http-default-accounts,http-wordpress-enum,http-wordpress-users,http-drupal-enum-users,http-php-version,http-iis-short-name-brute,http-vuln-cve2017-5638,http-shellshock"
    ["https"]="http-title,http-headers,http-server-header,http-methods,http-security-headers,http-enum,http-favicon,http-generator,http-date,http-robots.txt,http-useragent-tester,http-cors,http-cookie-flags,http-trace,http-auth,http-auth-finder,http-default-accounts,ssl-known-key,ssl-heartbleed,http-wordpress-enum,http-wordpress-users,http-drupal-enum-users,http-php-version,http-iis-short-name-brute,http-vuln-cve2017-5638,http-shellshock"
    ["http-proxy"]="http-title,http-headers,http-server-header,http-methods,http-security-headers,http-enum,http-generator,http-open-proxy"
    ["https-alt"]="http-title,http-headers,http-server-header,http-methods,http-security-headers,http-enum"
    ["http-alt"]="http-title,http-headers,http-server-header,http-methods,http-security-headers,http-enum"
    ["ssh"]="ssh2-enum-algos,ssh-auth-methods,ssh-hostkey,ssh-publickey-acceptance,sshv1"
    ["ftp"]="ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-syst,ftp-vsftpd-backdoor"
    ["microsoft-ds"]="smb-os-discovery,smb-protocols,smb-security-mode,smb-enum-shares,smb-enum-users,smb-enum-groups,smb-enum-domains,smb-system-info,smb2-security-mode,smb2-time,smb2-capabilities,smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,smb-double-pulsar-backdoor"
    ["netbios-ssn"]="smb-os-discovery,smb-protocols,smb-security-mode,smb-enum-shares,smb-enum-users,smb-enum-groups,smb-enum-domains,smb-system-info,smb2-security-mode,smb2-time,smb2-capabilities,smb-vuln-ms17-010,smb-vuln-ms08-067,nbstat"
    ["ldap"]="ldap-rootdse,ldap-search,ldap-novell-getpass"
    ["ldapssl"]="ssl-cert,ldap-rootdse,ldap-search,ldap-novell-getpass"
    ["kerberos-sec"]="krb5-enum-users"
    ["ms-wbt-server"]="rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020"
    ["vnc"]="vnc-info,vnc-title,realvnc-auth-bypass"
    ["telnet"]="telnet-encryption,telnet-ntlm-info"
    ["smtp"]="smtp-commands,smtp-enum-users,smtp-open-relay,smtp-ntlm-info,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764"
    ["pop3"]="pop3-capabilities,pop3-ntlm-info"
    ["imap"]="imap-capabilities,imap-ntlm-info"
    ["domain"]="dns-recursion,dns-nsid,dns-service-discovery,dns-cache-snoop,dns-zone-transfer,dns-brute,dns-random-srcport,dns-random-txid"
    ["domain-s"]="dns-recursion,dns-nsid,dns-service-discovery,dns-cache-snoop,dns-zone-transfer,dns-brute,dns-random-srcport,dns-random-txid"
    ["ntp"]="ntp-info,ntp-monlist"
    ["snmp"]="snmp-info,snmp-interfaces,snmp-processes,snmp-netstat,snmp-win32-services,snmp-win32-users,snmp-win32-shares,snmp-sysdescr,snmp-brute"
    ["mysql"]="mysql-info,mysql-users,mysql-databases,mysql-empty-password,mysql-enum,mysql-variables"
    ["postgresql"]="pgsql-databases,pgsql-brute"
    ["ms-sql-s"]="ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-ntlm-info,ms-sql-tables,ms-sql-xp-cmdshell"
    ["ms-sql-m"]="ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-ntlm-info"
    ["oracle-tns"]="oracle-sid-brute,oracle-tns-version"
    ["redis"]="redis-info,redis-brute"
    ["mongodb"]="mongodb-info,mongodb-databases,mongodb-brute"
    ["memcache"]="memcached-info"
    ["couchdb"]="couchdb-databases"
    ["cassandra"]="cassandra-info"
    ["elastic"]="http-enum,http-title,http-headers,elasticsearch-http"
    ["elasticsearch"]="http-enum,http-title,http-headers,elasticsearch-http"
    ["rabbitmq"]="http-title,http-enum,http-headers,amqp-info"
    ["activemq"]="http-title,http-enum"
    ["jenkins"]="http-title"
    ["jboss"]="http-title,http-enum"
    ["tomcat"]="http-title,http-auth,http-enum"
    ["kube"]="http-title,http-enum,ssl-cert"
    ["kubernetes"]="http-title,http-enum,ssl-cert"
    ["docker"]="docker-version"
    ["sip"]="sip-methods,sip-enum-users,sip-call-spoof"
    ["asterisk"]="asterisk-info"
    ["irc"]="irc-info,irc-botnet-channels,irc-unrealircd-backdoor"
    ["rtsp"]="rtsp-methods,rtsp-url-brute"
    ["nfs"]="nfs-showmount,nfs-ls,nfs-statfs,rpcinfo"
    ["rpcbind"]="rpcinfo,nfs-showmount,nfs-ls,nfs-statfs"
    ["portmapper"]="rpcinfo,nfs-showmount,nfs-ls,nfs-statfs"
    ["rsync"]="rsync-list-modules"
    ["afp"]="afp-showmount,afp-serverinfo,afp-ls,afp-path-vuln"
    ["ipmi"]="ipmi-version,ipmi-cipher-zero"
    ["bacnet"]="bacnet-info"
    ["modbus"]="modbus-discover"
    ["mqtt"]="mqtt-subscribe"
    ["x11"]="x11-access"
    ["xdmcp"]="xdmcp-discover"
    ["netbios-ns"]="nbstat"
    ["upnp"]="upnp-info"
    ["nntp"]="nntp-ntlm-info"
    ["finger"]="finger"
    ["ike"]="ike-version"
    ["socks"]="socks-auth-info,socks-open-proxy"

    # --- added from the port/service reference sheet ---
    ["daytime"]="daytime"
    ["time"]="rfc868-time"
    ["whois"]="whois-ip,whois-domain"
    ["tftp"]="tftp-enum,tftp-version"
    ["iso-tsap"]="s7-info"
    ["auth"]="auth-owners"
    ["ident"]="auth-owners"
    ["msrpc"]="msrpc-enum"
    ["exec"]="rexec-brute"
    ["login"]="rlogin-brute"
    ["who"]="rusers"
    ["ipp"]="cups-info,cups-queue-info"
    ["rmiregistry"]="rmi-dumpregistry,rmi-vuln-classloader"
    ["java-rmi"]="rmi-dumpregistry,rmi-vuln-classloader"
    ["nessus"]="nessus-xmlrpc-brute"
    ["ica"]="citrix-enum-apps,citrix-enum-servers"
    ["citrix-ica"]="citrix-enum-apps,citrix-enum-servers"
    ["pptp"]="pptp-version"
    ["cvspserver"]="cvs-brute-repository"
    ["iscsi"]="iscsi-info"
    ["distccd"]="distcc-cve2004-2687"
    ["svn"]="svn-brute,http-svn-enum,http-svn-info"
    ["subversion"]="svn-brute,http-svn-enum,http-svn-info"
    ["epmd"]="epmd-info"
    ["nrpe"]="nrpe-enum"
    ["amqp"]="amqp-info"
    ["mikrotik"]="mikrotik-routeros-version"
    ["bitcoin"]="bitcoin-getaddr,bitcoin-info,bitcoinrpc-info"
    ["netbus"]="netbus-info,netbus-version"
    ["freeciv"]="backorifice-info"
)

# ==========================================
# 5. PRODUCT MAPPING (from version-banner text)
# ==========================================
declare -A PRODUCT_SCRIPTS
PRODUCT_SCRIPTS=(
    ["apache"]="http-server-header,http-headers,http-title"
    ["nginx"]="http-server-header,http-headers,http-title"
    ["iis"]="http-server-header,http-headers,http-title,http-iis-short-name-brute"
    ["jetty"]="http-server-header,http-headers"
    ["vsftpd"]="ftp-anon,ftp-syst"
    ["proftpd"]="ftp-anon,ftp-syst"
    ["pure-ftpd"]="ftp-anon"
    ["samba"]="smb-enum-shares,smb-os-discovery,smb-vuln-cve-2017-7494"
    ["postfix"]="smtp-commands,smtp-enum-users"
    ["exchange"]="smtp-commands,smtp-enum-users,smtp-ntlm-info"
    ["exim"]="smtp-commands,smtp-enum-users"
    ["bind"]="dns-recursion,dns-nsid,dns-zone-transfer"
    ["microsoft dns"]="dns-recursion,dns-nsid"
    ["vmware"]="ssl-cert,ssl-enum-ciphers,http-title,http-headers,http-methods"
    ["vcenter"]="ssl-cert,ssl-enum-ciphers,http-title,http-headers,http-methods"
)

OUTDIR="output"
mkdir -p "$OUTDIR"
: > "$OUTDIR/unmapped_services.log"

# ==========================================
# 6. Build one deep-scan "job" per host, write jobs to a file, run with xargs -P
# ==========================================
echo ""
echo "=========================================="
echo "[*] STAGE 3/4: DEEP SERVICE ENUMERATION"
echo "=========================================="

JOBLIST=$(mktemp)

grep "Ports:" scan_results.gnmap | while read -r line; do
    ip=$(echo "$line" | awk '{print $2}')
    ports_line=$(echo "$line" | awk -F'\t' '{for(i=1;i<=NF;i++) if($i ~ /^Ports:/) {print substr($i, 8); exit}}')
    [ -z "$ports_line" ] && continue

    open_ports=()
    scripts_to_run=("${GLOBAL_SCRIPTS[@]}")

    while read -r entry; do
        entry=$(echo "$entry" | sed 's/^[[:space:],]*//; s/[[:space:],]*$//')
        [ -z "$entry" ] && continue

        port=$(echo "$entry" | awk -F'/' '{print $1}')
        state=$(echo "$entry" | awk -F'/' '{print $2}')
        service=$(echo "$entry" | awk -F'/' '{print $5}' | tr '[:upper:]' '[:lower:]' | sed 's/[^a-zA-Z0-9_-]//g')
        [ -z "$service" ] && service="unknown"
        version=$(echo "$entry" | awk -F'/' '{v=""; for(i=7; i<NF; i++) {v = v (i==7?"":"/") $i} print v}')

        [ "$state" != "open" ] && continue
        open_ports+=("$port")

        if [[ -n "${SERVICE_SCRIPTS[$service]+x}" ]]; then
            IFS=',' read -r -a svc_scr <<< "${SERVICE_SCRIPTS[$service]}"
            scripts_to_run+=("${svc_scr[@]}")
        elif [[ "$service" != "unknown" && "$service" != "tcpwrapped" ]]; then
            echo "$ip:$port service='$service' has no dedicated entry, relying on default/safe/vuln fallback" >> "$OUTDIR/unmapped_services.log"
        fi

        if [ -n "$version" ]; then
            version_lower=$(echo "$version" | tr '[:upper:]' '[:lower:]')
            for product in "${!PRODUCT_SCRIPTS[@]}"; do
                if [[ "$version_lower" == *"$product"* ]]; then
                    IFS=',' read -r -a prod_scr <<< "${PRODUCT_SCRIPTS[$product]}"
                    scripts_to_run+=("${prod_scr[@]}")
                fi
            done
        fi
    done < <(echo "$ports_line" | awk -v RS=', ' '{print}')

    [ ${#open_ports[@]} -eq 0 ] && continue

    unique_scripts=($(printf "%s\n" "${scripts_to_run[@]}" | sort -u))
    scripts_str=$(IFS=, ; echo "${unique_scripts[*]}")
    ports_str=$(IFS=, ; echo "${open_ports[*]}")

    # one line per host job: ip|ports|scripts
    echo "${ip}|${ports_str}|${scripts_str}" >> "$JOBLIST"
done

if [ ! -s "$JOBLIST" ]; then
    echo "[!] No open-port hosts found in scan_results.gnmap — nothing to deep-scan."
else
    echo "[+] $(wc -l < "$JOBLIST") host(s) queued, running with concurrency=$CONCURRENCY"

    run_host_job() {
        local job="$1"
        local ip ports scripts_str
        IFS='|' read -r ip ports scripts_str <<< "$job"

        local nscripts start_ts end_ts elapsed
        nscripts=$(awk -F',' '{print NF}' <<< "$scripts_str")
        start_ts=$(date +%s)
        echo "[+] Scanning $ip (ports: $ports) — started $(date '+%H:%M:%S') — NSE scripts: $nscripts"

        sudo nmap \
            -Pn -sS -sV --version-intensity 9 \
            -p "$ports" \
            --script="$scripts_str" \
            -O --osscan-guess \
            --max-rate 300 \
            "$ip" \
            -oA "output/details_$ip" >/dev/null

        # Bonus tools, each capped with timeout so a hung tool can't stall the batch
        if [[ ",$ports," == *",445,"* ]] || [[ ",$ports," == *",139,"* ]]; then
            echo "    [+] [$ip] enum4linux"
            timeout 300 enum4linux -a "$ip" > "output/enum4linux_$ip.txt" 2>/dev/null
        fi
        if [[ ",$ports," == *",80,"* ]] || [[ ",$ports," == *",443,"* ]] || [[ ",$ports," == *",8080,"* ]]; then
            echo "    [+] [$ip] nikto"
            timeout 300 nikto -h "$ip" -p "$ports" -output "output/nikto_$ip.txt" 2>/dev/null
        fi
        if [[ ",$ports," == *",53,"* ]]; then
            echo "    [+] [$ip] dnsrecon"
            timeout 120 dnsrecon -t axfr -d "$ip" > "output/dnsrecon_$ip.txt" 2>/dev/null
        fi

        end_ts=$(date +%s)
        elapsed=$((end_ts - start_ts))
        echo "    [$ip] finished in ${elapsed}s"
        [ -n "${PROGRESS_FILE:-}" ] && echo "$ip $elapsed" >> "$PROGRESS_FILE"
    }
    export -f run_host_job

    PROGRESS_FILE=$(mktemp)
    export PROGRESS_FILE
    JOBS_TOTAL=$(wc -l < "$JOBLIST" | tr -d ' ')
    BATCH_START=$(date +%s)

    # run the batch in the background so a progress watcher can print live ETA
    cat "$JOBLIST" | xargs -P "$CONCURRENCY" -I{} bash -c 'run_host_job "$@"' _ {} &
    XARGS_PID=$!

    if [ "$PROGRESS_INTERVAL" -gt 0 ]; then
        while kill -0 "$XARGS_PID" 2>/dev/null; do
            sleep "$PROGRESS_INTERVAL"
            JOBS_DONE=$(wc -l < "$PROGRESS_FILE" 2>/dev/null | tr -d ' ')
            [ -z "$JOBS_DONE" ] && JOBS_DONE=0
            [ "$JOBS_DONE" -eq 0 ] && continue
            NOW_TS=$(date +%s)
            ELAPSED=$((NOW_TS - BATCH_START))
            AVG=$(awk -v e="$ELAPSED" -v d="$JOBS_DONE" 'BEGIN{printf "%.1f", e/d}')
            REMAIN=$(awk -v e="$ELAPSED" -v d="$JOBS_DONE" -v t="$JOBS_TOTAL" 'BEGIN{printf "%.0f", (t-d)*(e/d)}')
            echo "[i] Progress: $JOBS_DONE/$JOBS_TOTAL host(s) done | elapsed: ${ELAPSED}s | avg: ${AVG}s/host | est. remaining: ${REMAIN}s"
        done
    fi
    wait "$XARGS_PID"

    BATCH_ELAPSED=$(( $(date +%s) - BATCH_START ))
    SLOWEST=$(sort -k2 -rn "$PROGRESS_FILE" 2>/dev/null | head -n1 | awk '{print $1" ("$2"s)"}')
    echo "[+] All scans completed in ${BATCH_ELAPSED}s"
    [ -n "$SLOWEST" ] && echo "[+] Slowest host: $SLOWEST"
    rm -f "$PROGRESS_FILE"; PROGRESS_FILE=""
fi
rm -f "$JOBLIST"; JOBLIST=""

# ==========================================
# 7. PER-IP ARCHIVE — power the next run's fresh-results check + report merge
#    last_scan.txt : line1 epoch | line2 human date | line3 targets
#    ports.txt     : the gnmap "Ports:" summary (raw)
#    details_<ip>.xml + bonus tool outputs are copied in too
# ==========================================
echo ""
echo "[*] Archiving per-host results into $RESULTS_DIR/ ..."
ARCHIVE_N=0
while IFS= read -r ip; do
    mkdir -p "$RESULTS_DIR/$ip"
    {
        echo "$SCAN_EPOCH"
        date '+%Y-%m-%d %H:%M:%S'
        echo "targets: $TARGET_DISPLAY"
    } > "$RESULTS_DIR/$ip/last_scan.txt"
    awk -F'\t' -v want="$ip" '
        /Ports:/ {
            split($1, a, " ")
            if (a[2] == want) { for (i=1; i<=NF; i++) if ($i ~ /^Ports:/) { print substr($i, 8); exit } }
        }' scan_results.gnmap > "$RESULTS_DIR/$ip/ports.txt" 2>/dev/null || :
    [ -f "output/details_$ip.xml" ] && cp -f "output/details_$ip.xml" "$RESULTS_DIR/$ip/details_$ip.xml"
    for tool in enum4linux nikto dnsrecon; do
        [ -f "output/${tool}_$ip.txt" ] && cp -f "output/${tool}_$ip.txt" "$RESULTS_DIR/$ip/"
    done
    ARCHIVE_N=$((ARCHIVE_N + 1))
done < live_ips.txt
echo "[+] Archive updated for $ARCHIVE_N host(s) — next runs will offer to skip these if still fresh."

fi   # end of "something new to scan" (SKIP_SCAN == 0)

# ==========================================
# 8. REPORT GENERATION & CLEANUP
#    Skipped (fresh/imported) hosts are merged from RESULTS_DIR into the
#    report with an ARCHIVED RESULT badge, so nothing is ever lost.
# ==========================================
echo ""
echo "=========================================="
echo "[*] STAGE 4/4: HTML REPORT GENERATION"
echo "=========================================="
echo "[+] Generating comprehensive HTML report..."

cat << 'PYTHON_SCRIPT' > generate_report.py
import xml.etree.ElementTree as ET
import os, glob, html, re, sys

def parse_details_xml(xml_file, ip, totals):
    """Parse one nmap details XML -> host_data dict (same shape for fresh + archived)."""
    host_data = {'ip': ip, 'hostnames': [], 'os': [], 'ports': [], 'host_scripts': {}, 'bonus': []}
    try:
        root = ET.parse(xml_file).getroot()
    except Exception:
        return None
    for host in root.findall('host'):
        if host.find('status') is not None and host.find('status').get('state') != 'up':
            continue
        for hn in host.findall('hostnames/hostname'):
            host_data['hostnames'].append(hn.get('name'))
        os_elem = host.find('os')
        if os_elem is not None:
            for osmatch in os_elem.findall('osmatch'):
                host_data['os'].append(f"{osmatch.get('name')} ({osmatch.get('accuracy')}%)")
        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                state_elem = port.find('state')
                if state_elem is not None and state_elem.get('state') == 'open':
                    totals['ports'] += 1
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    service_elem = port.find('service')
                    port_info = {
                        'port': port_id, 'proto': protocol,
                        'service': service_elem.get('name', '') if service_elem is not None else '',
                        'product': service_elem.get('product', '') if service_elem is not None else '',
                        'version': service_elem.get('version', '') if service_elem is not None else '',
                        'extrainfo': service_elem.get('extrainfo', '') if service_elem is not None else '',
                        'scripts': {}
                    }
                    for script in port.findall('script'):
                        sid = script.get('id')
                        sout = script.get('output', '')
                        port_info['scripts'][sid] = sout
                        if sid == 'vulners' and sout.strip():
                            cves = re.findall(r'CVE-\d{4}-\d{4,}', sout)
                            totals['vulns'] += len(cves) if cves else 1
                    host_data['ports'].append(port_info)
        hostscript_elem = host.find('hostscript')
        if hostscript_elem is not None:
            for script in hostscript_elem.findall('script'):
                host_data['host_scripts'][script.get('id')] = script.get('output', '')
    return host_data

def collect_bonus(folder, ip):
    """Grab enum4linux_/nikto_/dnsrecon_<ip>.txt outputs from a folder."""
    bonus = []
    for tool in ("enum4linux", "nikto", "dnsrecon"):
        p = os.path.join(folder, f"{tool}_{ip}.txt")
        if os.path.exists(p):
            try:
                with open(p, 'r', errors='ignore') as f:
                    bonus.append({'tool': tool, 'content': f.read()})
            except Exception:
                pass
    return bonus

def read_archive_meta(archive_ip_dir):
    """last_scan.txt: line1 epoch, line2 human date, line3 targets, line4 imported marker."""
    meta = {'epoch': None, 'date': None, 'targets': None, 'imported': False}
    ts = os.path.join(archive_ip_dir, 'last_scan.txt')
    if os.path.exists(ts):
        try:
            with open(ts, 'r', errors='ignore') as f:
                lines = [l.rstrip('\n') for l in f.readlines()]
            if len(lines) >= 1 and lines[0].strip().isdigit():
                meta['epoch'] = int(lines[0].strip())
            if len(lines) >= 2:
                meta['date'] = lines[1].strip()
            if len(lines) >= 3:
                meta['targets'] = lines[2].strip()
            if any(l.strip() == 'imported: yes' for l in lines):
                meta['imported'] = True
        except Exception:
            pass
    return meta

def main():
    output_dir = sys.argv[1]
    html_file = sys.argv[2]
    target_info = sys.argv[3] if len(sys.argv) > 3 else "N/A"
    scan_date = sys.argv[4] if len(sys.argv) > 4 else "N/A"
    info5 = sys.argv[5] if len(sys.argv) > 5 else ""
    results_dir, skipped_file = (info5.split('|', 1) + [None])[:2] if info5 else (None, None)

    # hosts actually skipped THIS run — their archive copy wins over any stale
    # output/details_*.xml left behind by an earlier run or import
    skipped_set = set()
    if skipped_file and os.path.exists(skipped_file):
        with open(skipped_file, 'r', errors='ignore') as f:
            skipped_set = {l.strip() for l in f if l.strip()}

    totals = {'ports': 0, 'vulns': 0}
    hosts = []

    for xml_file in glob.glob(os.path.join(output_dir, "details_*.xml")):
        ip_match = re.search(r'details_(.+)\.xml', os.path.basename(xml_file))
        ip = ip_match.group(1) if ip_match else "Unknown"
        if ip in skipped_set:
            continue   # skipped this run -> rendered from the archive instead
        host_data = parse_details_xml(xml_file, ip, totals)
        if host_data is None:
            continue
        host_data['bonus'] = collect_bonus(output_dir, ip)
        hosts.append(host_data)

    fresh_ips = {h['ip'] for h in hosts}

    # ---- merge skipped hosts from the archive -------------------------------
    archived_hosts = []      # full details XML available in the archive
    portonly_hosts = []      # only a gnmap Ports summary available
    noarchive_skipped = []   # nothing archived (nothing we can render)
    if results_dir and skipped_file and os.path.exists(skipped_file):
        with open(skipped_file, 'r', errors='ignore') as f:
            skipped_ips = [l.strip() for l in f if l.strip()]
        for ip in skipped_ips:
            if ip in fresh_ips:
                continue   # re-scanned anyway (FRESH_POLICY=keep) — fresh card wins
            adir = os.path.join(results_dir, ip)
            axml = os.path.join(adir, f"details_{ip}.xml")
            aports = os.path.join(adir, "ports.txt")
            if os.path.exists(axml):
                hd = parse_details_xml(axml, ip, totals)
                if hd is not None:
                    hd['bonus'] = collect_bonus(adir, ip)
                    hd['archived'] = True
                    hd['archive_meta'] = read_archive_meta(adir)
                    archived_hosts.append(hd)
                    continue
            if os.path.exists(aports):
                try:
                    with open(aports, 'r', errors='ignore') as f:
                        ports_line = f.read().strip()
                except Exception:
                    ports_line = ""
                meta = read_archive_meta(adir)
                portonly_hosts.append({'ip': ip, 'ports_line': ports_line, 'meta': meta})
                continue
            noarchive_skipped.append(ip)

    all_hosts_count = len(hosts) + len(archived_hosts) + len(portonly_hosts)
    merged_count = len(archived_hosts) + len(portonly_hosts)

    unmapped = []
    unmapped_path = os.path.join(output_dir, "unmapped_services.log")
    if os.path.exists(unmapped_path):
        with open(unmapped_path, 'r', errors='ignore') as f:
            unmapped = [l.strip() for l in f if l.strip()]

    css = """
    :root { --bg:#0d1117;--card-bg:#161b22;--border:#30363d;--text:#c9d1d9;--text-muted:#8b949e;--accent:#58a6ff;--success:#3fb950;--danger:#f85149;--warning:#d29922; }
    body { background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;margin:0;padding:20px;line-height:1.5; }
    .container { max-width:1200px;margin:0 auto; }
    h1,h2,h3 { color:#fff;margin-top:0; }
    .card { background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:20px;box-shadow:0 4px 6px rgba(0,0,0,.3); }
    table { width:100%;border-collapse:collapse;margin-top:10px;font-size:14px; }
    th,td { padding:10px 12px;border-bottom:1px solid var(--border);text-align:left; }
    th { background:#21262d;color:var(--accent);text-transform:uppercase;font-size:12px;letter-spacing:.5px; }
    tr:hover { background:#1c2128; }
    .badge { padding:4px 8px;border-radius:12px;font-size:12px;font-weight:bold;display:inline-block; }
    .badge-open { background:rgba(63,185,80,.2);color:var(--success); }
    .badge-warn { background:rgba(210,153,34,.2);color:var(--warning); }
    pre { background:#010409;padding:15px;border-radius:6px;overflow-x:auto;font-size:13px;color:var(--text-muted);border:1px solid var(--border);white-space:pre-wrap;word-wrap:break-word;max-height:400px;overflow-y:auto; }
    details { margin-top:15px;border:1px solid var(--border);border-radius:6px;padding:10px; }
    summary { cursor:pointer;font-weight:bold;color:var(--accent);outline:none; }
    summary:hover { text-decoration:underline; }
    .summary-grid { display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-bottom:30px; }
    .stat-card { background:var(--card-bg);border:1px solid var(--border);padding:20px;border-radius:8px;text-align:center; }
    .stat-value { font-size:2.5em;font-weight:bold;color:var(--accent);margin:0; }
    .stat-label { color:var(--text-muted);font-size:14px;text-transform:uppercase;letter-spacing:1px; }
    .ip-header { display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);padding-bottom:10px;margin-bottom:20px; }
    .ip-title { font-size:24px;font-weight:bold;color:#fff;margin:0; }
    .os-info { color:var(--warning);font-size:14px;font-style:italic; }
    """

    def render_host_card(h, archived=False, archive_date=None):
        hostnames = ", ".join(h['hostnames']) if h['hostnames'] else "No reverse DNS"
        os_info = ", ".join(h['os'][:2]) if h['os'] else "Unknown OS"
        badge = ""
        if archived:
            d = html.escape(archive_date) if archive_date else "unknown date"
            badge = f'<span class="badge badge-warn">ARCHIVED RESULT — from scan of {d}</span>'
        card = f"""
        <div class="card">
            <div class="ip-header">
                <div>
                    <div class="ip-title">{html.escape(h['ip'])}</div>
                    <div style="color:var(--text-muted);font-size:14px;">{html.escape(hostnames)}</div>
                </div>
                <div class="os-info">{badge} {html.escape(os_info)}</div>
            </div>
        """
        if h['ports']:
            card += "<h3>Open Ports & Services</h3><table><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th><th>Details</th></tr></thead><tbody>"
            for p in h['ports']:
                version_str = f"{html.escape(p['product'])} {html.escape(p['version'])}".strip()
                card += f"""
                <tr>
                    <td><span class="badge badge-open">{html.escape(p['port'])}</span></td>
                    <td>{html.escape(p['proto'])}</td>
                    <td>{html.escape(p['service'])}</td>
                    <td>{version_str}</td>
                    <td><div style="font-size:12px;color:var(--text-muted);">{html.escape(p['extrainfo'])}</div>
                """
                for sid, sout in p['scripts'].items():
                    if sid == 'vulners':
                        card += f'<details><summary style="color:var(--danger);">Vulnerabilities ({html.escape(sid)})</summary><pre>{html.escape(sout)}</pre></details>'
                    else:
                        card += f'<details><summary>Script: {html.escape(sid)}</summary><pre>{html.escape(sout)}</pre></details>'
                card += "</td></tr>"
            card += "</tbody></table>"
        if h['host_scripts']:
            card += "<h3>Host-Level Scripts</h3>"
            for sid, sout in h['host_scripts'].items():
                card += f'<details><summary>Script: {html.escape(sid)}</summary><pre>{html.escape(sout)}</pre></details>'
        if h['bonus']:
            card += "<h3>Bonus Tools Output</h3>"
            for b in h['bonus']:
                card += f'<details><summary>Tool: {html.escape(b["tool"])}</summary><pre>{html.escape(b["content"])}</pre></details>'
        card += "</div>"
        return card

    html_body = f"""
    <div class="container">
        <h1>Internal Network Scan Report</h1>
        <div style="color:var(--text-muted);font-size:14px;margin-bottom:25px;">
            Target: {html.escape(target_info)} &nbsp;|&nbsp; Live hosts: {all_hosts_count} &nbsp;|&nbsp; Generated: {html.escape(scan_date)}
        </div>
        <div class="summary-grid">
            <div class="stat-card"><div class="stat-value">{len(hosts)}</div><div class="stat-label">Hosts Scanned</div></div>
            <div class="stat-card"><div class="stat-value">{totals['ports']}</div><div class="stat-label">Open Ports</div></div>
            <div class="stat-card"><div class="stat-value">{totals['vulns']}</div><div class="stat-label">Potential Vulns</div></div>
            <div class="stat-card"><div class="stat-value">{len(unmapped)}</div><div class="stat-label">Unmapped Services</div></div>
            <div class="stat-card"><div class="stat-value">{all_hosts_count}</div><div class="stat-label">Hosts in Report</div></div>
            <div class="stat-card"><div class="stat-value">{merged_count}</div><div class="stat-label">Archived Results Merged</div></div>
        </div>
    """

    if unmapped:
        html_body += '<div class="card"><h3>Services without a dedicated script entry</h3><pre>' + html.escape("\n".join(unmapped)) + '</pre></div>'

    if noarchive_skipped:
        html_body += ('<div class="card"><h3>Skipped hosts without any archived data</h3>'
                      '<pre>' + html.escape("\n".join(noarchive_skipped)) + '</pre></div>')

    for h in hosts:
        html_body += render_host_card(h, archived=False)

    for h in archived_hosts:
        html_body += render_host_card(h, archived=True,
                                      archive_date=(h.get('archive_meta') or {}).get('date'))

    for po in portonly_hosts:
        d = (po['meta'] or {}).get('date')
        d = html.escape(d) if d else "unknown date"
        html_body += f"""
        <div class="card">
            <div class="ip-header">
                <div>
                    <div class="ip-title">{html.escape(po['ip'])}</div>
                    <div style="color:var(--text-muted);font-size:14px;">Port-scan-only record — no detailed XML in the archive</div>
                </div>
                <div class="os-info"><span class="badge badge-warn">ARCHIVED RESULT — from scan of {d}</span></div>
            </div>
            <h3>Open Ports (from the full port scan)</h3>
            <pre>{html.escape(po['ports_line'])}</pre>
        </div>
        """

    html_body += "</div>"

    full_html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Internal Network Scan Report</title><style>{css}</style></head>
<body>{html_body}</body></html>"""

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(full_html)
    print(f"[+] HTML Report successfully generated: {html_file}")

if __name__ == "__main__":
    main()
PYTHON_SCRIPT

python3 generate_report.py "output" "Final_Scan_Report.html" "$TARGET_DISPLAY" "$(date '+%Y-%m-%d %H:%M')" "${RESULTS_DIR}|skipped_fresh.txt"

if [ -f "Final_Scan_Report.html" ]; then
    echo "[+] HTML Report generated successfully: Final_Scan_Report.html"
    echo "[+] Cleaning up raw output files to leave only the report..."
    rm -rf output/
    rm -f generate_report.py
    echo ""
    echo "[+] =========================================================="
    echo "[+] All scans and reporting completed!"
    echo "[+]   Report   : Final_Scan_Report.html"
    echo "[+]   Raw data kept for reference:"
    echo "[+]     - live_ips.txt                    (hosts that were scanned, in scan order)"
    echo "[+]     - scan_origin.txt                 (which target contributed each host)"
    [ -f live_hosts.grep ] && echo "[+]     - live_hosts.grep                 (discovery sweep output)"
    echo "[+]     - scan_results.nmap/.gnmap/.xml  (full port scan output)"
    [ -f skipped_fresh.txt ] && echo "[+]     - skipped_fresh.txt               (hosts merged from the archive)"
    echo "[+]     - $RESULTS_DIR/                  (per-IP archive — powers re-scan skipping)"
    echo "[+] =========================================================="
else
    echo "[-] Report generation failed. Raw files kept in output/ for debugging."
    rm -f generate_report.py
fi
