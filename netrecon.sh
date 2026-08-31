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
#   STAGE 2: Full TCP port scan (-p- -sS -Pn -T4 --open) on all live hosts
#            (asks for confirmation first, showing the live host list)
#   STAGE 3: Deep per-host enumeration (service/version/NSE scripts +
#            enum4linux / nikto / dnsrecon bonus tools)
#   STAGE 4: HTML report generation -> Final_Scan_Report.html
#
# Usage:
#   ./netrecon.sh [target(s)]
#     ./netrecon.sh 172.16.0.0/12
#     ./netrecon.sh 172.16.0.0/12,10.0.0.5,server.local
#     ./netrecon.sh            (asks interactively)
#
# Environment:
#   CONCURRENCY=4   number of hosts deep-scanned in parallel (tune to CPU/link)
#
# Requires: nmap, python3  (hard requirements)
# Optional: enum4linux, nikto, dnsrecon (missing ones are skipped with a warning)
#
# Files kept at the end (for manual review):
#   live_ips.txt, live_hosts.grep (if ranges were scanned),
#   scan_results.nmap / .gnmap / .xml, Final_Scan_Report.html
# ==========================================

set -o pipefail

# Associative arrays need bash >= 4
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "[-] This script requires bash >= 4 (associative arrays)."
    exit 1
fi

# How many hosts to deep-scan concurrently. Tune to your link/CPU.
CONCURRENCY="${CONCURRENCY:-4}"

TARGET_DISPLAY=""
JOBLIST=""
trap 'rm -f "$JOBLIST" 2>/dev/null' EXIT

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

# ==========================================
# 1. TARGET INPUT (command-line argument, or interactive prompt)
# ==========================================
if [ $# -ge 1 ]; then
    TARGETS_RAW="$1"
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
echo "[*] Classifying targets..."

RANGES=()
SINGLES=()

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

for token in "${RAW_TOKENS[@]}"; do
    # trim surrounding whitespace
    t="${token#"${token%%[![:space:]]*}"}"
    t="${t%"${t##*[![:space:]]}"}"
    [ -z "$t" ] && continue

    if is_single_ip "$t"; then
        echo "[+] Single IP target     : $t (scanned directly, no sweep)"
        SINGLES+=("$t")
    elif is_ip_range "$t"; then
        echo "[+] Network range target : $t (host discovery sweep will run)"
        RANGES+=("$t")
    else
        ip=$(resolve_host "$t")
        if [ -n "$ip" ]; then
            echo "[+] Domain target        : $t -> $ip (resolved, scanned directly)"
            SINGLES+=("$ip")
        else
            echo "[!] Could not resolve '$t' — skipping it."
        fi
    fi
done

if [ ${#RANGES[@]} -eq 0 ] && [ ${#SINGLES[@]} -eq 0 ]; then
    echo "[-] No valid targets to scan. Exiting."
    exit 1
fi

# ==========================================
# 3. HOST DISCOVERY (ranges only — exact original commands)
#    Single IPs / resolved domains go straight into live_ips.txt
# ==========================================
: > live_ips.txt

if [ ${#RANGES[@]} -gt 0 ]; then
    RANGES_STR=$(IFS=,; echo "${RANGES[*]}")
    echo ""
    echo "[*] Running host discovery sweep on: $RANGES_STR"
    if ! nmap -sn -PE -PS80,443,22,3389 -PA80,443 -n -T4 --min-rate 5000 --max-retries 1 "$RANGES_STR" -oG live_hosts.grep; then
        echo "[-] Host discovery sweep failed — check the target syntax."
        exit 1
    fi
    grep "Up$" live_hosts.grep | awk '{print $2}' >> live_ips.txt
else
    echo "[*] No ranges given — skipping the discovery sweep (direct targets only)."
fi

for ip in "${SINGLES[@]}"; do
    echo "$ip" >> live_ips.txt
done

# dedupe while keeping one IP per line
if [ -s live_ips.txt ]; then
    sort -u live_ips.txt -o live_ips.txt
fi

LIVE_COUNT=$(wc -l < live_ips.txt | tr -d ' ')
if [ "$LIVE_COUNT" -eq 0 ]; then
    echo "[-] No live hosts found. Exiting."
    exit 1
fi

echo ""
echo "[+] Discovery finished — $LIVE_COUNT live host(s) queued for scanning:"
head -n 20 live_ips.txt | sed 's/^/      /'
if [ "$LIVE_COUNT" -gt 20 ]; then
    echo "      ... and $((LIVE_COUNT - 20)) more"
fi

# Confirmation before the long full-port scan
read -rp "[?] Next: full TCP port scan (-p-, all 65535 ports) on these hosts. This can take a LONG time. Continue? [Y/n] " CONFIRM
if [[ "$CONFIRM" == [nN]* ]]; then
    echo "[-] Aborted by user. Live host list kept in live_ips.txt for manual use."
    exit 0
fi

# ==========================================
# 4. FULL PORT SCAN (exact original command)
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
# 1. SERVICE MAPPING (extra depth on top of the category fallback above)
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
# 2. PRODUCT MAPPING (from version-banner text)
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
# 3. Build one deep-scan "job" per host, write jobs to a file, run with xargs -P
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
    echo "[-] No open-port hosts found in scan_results.gnmap"
    rm -f "$JOBLIST"
    exit 1
fi

echo "[+] $(wc -l < "$JOBLIST") host(s) queued, running with concurrency=$CONCURRENCY"

run_host_job() {
    local job="$1"
    local ip ports scripts_str
    IFS='|' read -r ip ports scripts_str <<< "$job"

    echo "[+] Scanning $ip (ports: $ports)"

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
}
export -f run_host_job

cat "$JOBLIST" | xargs -P "$CONCURRENCY" -I{} bash -c 'run_host_job "$@"' _ {}
rm -f "$JOBLIST"

echo "[+] All scans completed!"

# ==========================================
# 4. REPORT GENERATION & CLEANUP
# ==========================================
echo ""
echo "=========================================="
echo "[*] STAGE 4/4: HTML REPORT GENERATION"
echo "=========================================="
echo "[+] Generating comprehensive HTML report..."

cat << 'PYTHON_SCRIPT' > generate_report.py
import xml.etree.ElementTree as ET
import os, glob, html, re, sys

def main():
    output_dir = sys.argv[1]
    html_file = sys.argv[2]
    target_info = sys.argv[3] if len(sys.argv) > 3 else "N/A"
    scan_date = sys.argv[4] if len(sys.argv) > 4 else "N/A"

    hosts = []
    total_ports = 0
    total_vulns = 0

    for xml_file in glob.glob(os.path.join(output_dir, "details_*.xml")):
        ip_match = re.search(r'details_(.+)\.xml', os.path.basename(xml_file))
        ip = ip_match.group(1) if ip_match else "Unknown"
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except Exception:
            continue

        host_data = {'ip': ip, 'hostnames': [], 'os': [], 'ports': [], 'host_scripts': {}, 'bonus': []}

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
                        total_ports += 1
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
                                total_vulns += len(cves) if cves else 1
                        host_data['ports'].append(port_info)
            hostscript_elem = host.find('hostscript')
            if hostscript_elem is not None:
                for script in hostscript_elem.findall('script'):
                    host_data['host_scripts'][script.get('id')] = script.get('output', '')

        hosts.append(host_data)

    for txt_file in glob.glob(os.path.join(output_dir, "*.txt")):
        basename = os.path.basename(txt_file)
        tool, ip = "", ""
        if basename.startswith("enum4linux_"):
            tool, ip = "enum4linux", basename.replace("enum4linux_", "").replace(".txt", "")
        elif basename.startswith("nikto_"):
            tool, ip = "nikto", basename.replace("nikto_", "").replace(".txt", "")
        elif basename.startswith("dnsrecon_"):
            tool, ip = "dnsrecon", basename.replace("dnsrecon_", "").replace(".txt", "")
        if tool and ip:
            for h in hosts:
                if h['ip'] == ip:
                    try:
                        with open(txt_file, 'r', errors='ignore') as f:
                            h['bonus'].append({'tool': tool, 'content': f.read()})
                    except Exception:
                        pass

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

    html_body = f"""
    <div class="container">
        <h1>Internal Network Scan Report</h1>
        <div style="color:var(--text-muted);font-size:14px;margin-bottom:25px;">
            Target: {html.escape(target_info)} &nbsp;|&nbsp; Live hosts: {len(hosts)} &nbsp;|&nbsp; Generated: {html.escape(scan_date)}
        </div>
        <div class="summary-grid">
            <div class="stat-card"><div class="stat-value">{len(hosts)}</div><div class="stat-label">Hosts Scanned</div></div>
            <div class="stat-card"><div class="stat-value">{total_ports}</div><div class="stat-label">Open Ports</div></div>
            <div class="stat-card"><div class="stat-value">{total_vulns}</div><div class="stat-label">Potential Vulns</div></div>
            <div class="stat-card"><div class="stat-value">{len(unmapped)}</div><div class="stat-label">Unmapped Services</div></div>
        </div>
    """

    if unmapped:
        html_body += '<div class="card"><h3>Services without a dedicated script entry</h3><pre>' + html.escape("\n".join(unmapped)) + '</pre></div>'

    for h in hosts:
        hostnames = ", ".join(h['hostnames']) if h['hostnames'] else "No reverse DNS"
        os_info = ", ".join(h['os'][:2]) if h['os'] else "Unknown OS"
        html_body += f"""
        <div class="card">
            <div class="ip-header">
                <div>
                    <div class="ip-title">{html.escape(h['ip'])}</div>
                    <div style="color:var(--text-muted);font-size:14px;">{html.escape(hostnames)}</div>
                </div>
                <div class="os-info">{html.escape(os_info)}</div>
            </div>
        """
        if h['ports']:
            html_body += "<h3>Open Ports & Services</h3><table><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th><th>Details</th></tr></thead><tbody>"
            for p in h['ports']:
                version_str = f"{html.escape(p['product'])} {html.escape(p['version'])}".strip()
                html_body += f"""
                <tr>
                    <td><span class="badge badge-open">{html.escape(p['port'])}</span></td>
                    <td>{html.escape(p['proto'])}</td>
                    <td>{html.escape(p['service'])}</td>
                    <td>{version_str}</td>
                    <td><div style="font-size:12px;color:var(--text-muted);">{html.escape(p['extrainfo'])}</div>
                """
                for sid, sout in p['scripts'].items():
                    if sid == 'vulners':
                        html_body += f'<details><summary style="color:var(--danger);">Vulnerabilities ({html.escape(sid)})</summary><pre>{html.escape(sout)}</pre></details>'
                    else:
                        html_body += f'<details><summary>Script: {html.escape(sid)}</summary><pre>{html.escape(sout)}</pre></details>'
                html_body += "</td></tr>"
            html_body += "</tbody></table>"

        if h['host_scripts']:
            html_body += "<h3>Host-Level Scripts</h3>"
            for sid, sout in h['host_scripts'].items():
                html_body += f'<details><summary>Script: {html.escape(sid)}</summary><pre>{html.escape(sout)}</pre></details>'

        if h['bonus']:
            html_body += "<h3>Bonus Tools Output</h3>"
            for b in h['bonus']:
                html_body += f'<details><summary>Tool: {html.escape(b["tool"])}</summary><pre>{html.escape(b["content"])}</pre></details>'

        html_body += "</div>"

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

python3 generate_report.py "output" "Final_Scan_Report.html" "$TARGET_DISPLAY" "$(date '+%Y-%m-%d %H:%M')"

if [ -f "Final_Scan_Report.html" ]; then
    echo "[+] HTML Report generated successfully: Final_Scan_Report.html"
    echo "[+] Cleaning up raw output files to leave only the report..."
    rm -rf output/
    rm generate_report.py
    echo ""
    echo "[+] =========================================================="
    echo "[+] All scans and reporting completed!"
    echo "[+]   Report   : Final_Scan_Report.html"
    echo "[+]   Raw data kept for reference:"
    echo "[+]     - live_ips.txt                    (hosts that were scanned)"
    [ -f live_hosts.grep ] && echo "[+]     - live_hosts.grep                 (discovery sweep output)"
    echo "[+]     - scan_results.nmap/.gnmap/.xml  (full port scan output)"
    echo "[+] =========================================================="
else
    echo "[-] Report generation failed. Raw files kept in output/ for debugging."
    rm -f generate_report.py
fi
