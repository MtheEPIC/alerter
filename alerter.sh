#!/bin/bash

declare -g SCRIPT_DIR #used for internal files and scripts
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
declare -g USER_DIR #used for files to be easily accessible by the end user
USER_DIR=$(pwd)
readonly SCRIPT_DIR USER_DIR

source "$SCRIPT_DIR/styled_prints.sh"

declare -rg log_ssh="$USER_DIR/ssh.log"
declare -rg log_ftp="$USER_DIR/ftp.log"
declare -rg log_smb="$USER_DIR/smb.log"
declare -rg msf_log="$USER_DIR/tmp.log"
declare -A modes_enum

modes_enum=( [SSH]=1 [FTP]=2 [SMB]=3 [ALL]=4 )
keys=("SSH" "FTP" "SMB" "ALL")

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root."
        return 1
    fi
    return 0
}

install_progs() {
    sudo apt-get install rsyslog
}

welcome_msg() {
    echo -e "${TITLE_PRE_CLR}[*] ${TITLE_MSG}Alerter - Netwrok Honetpot${NC}\n"
    echo -e "${NOTE_PRE_CLR}1. ${NOTE_MSG}SSH${NC}"
    echo -e "${NOTE_PRE_CLR}2. ${NOTE_MSG}FTP${NC}"
    echo -e "${NOTE_PRE_CLR}3. ${NOTE_MSG}SMB${NC}"
    echo -e "${NOTE_PRE_CLR}4. ${NOTE_MSG}Start all services${NC}\n"
}

declare -g choice
get_user_input() {
    # read -rp "[+] Enter your choice: " choice
    echo "[+] Enter your choice: " 
    read -r choice

    [ -z "$choice" ] && return 1
    ! [[ $choice =~ ^[0-9]+$ ]] && return 1
    [ ${#choice} -gt ${#modes_enum[@]} ] && return 1
    choice=$(rev <<< "${choice}")
    #TODO sort the input
    return 0
}

use_ssh=false
use_ftp=false
use_smb=false
add_choice() {
    opt="$1"
    
    use_all=false
    [[ "$opt" == *${modes_enum[ALL]}* ]] && use_all=true
    [[ "$opt" == *${modes_enum[SSH]}* ]] || $use_all && { use_ssh=true; modes_str+=" 22(SSH)"; }
    [[ "$opt" == *${modes_enum[FTP]}* ]] || $use_all && { use_ftp=true; modes_str+=" 21(FTP)"; }
    [[ "$opt" == *${modes_enum[SMB]}* ]] || $use_all && { use_smb=true; modes_str+=" 445(SMB)"; }

    return 0
}

parse_input() {
    while ! get_user_input; do
        echo "Invalid Input"
    done

    modes_str=""
    add_choice "${choice}" || return 1

    [ -z "$modes_str" ] && echo "Invalid Input" && return 1

    return 0
}

live_feed() {
    # When running the Alerter, display in live-mode the Honeypot activity.
    # echo "$(date): $ip accessed SMB [admin:password]"
    # echo "$(date): $ip accessed SMB [admin:password1]"

    $use_ssh && tail -Fn 10 "$log_ssh" | grep --line-buffered --text -w "password for" &
    
    filter="("
    $use_ftp && filter+="FTP"
    $use_ftp && $use_smb && filter+="|"
    $use_smb && filter+="\[SMB\]"
    filter+=")"
    $use_ftp || $use_smb && tail -Fn 10 "$msf_log" | grep --line-buffered --text -w -E "$filter" &

}

log_activity() {
    echo "logging..." #| tee -a ssh.log
    
    # $use_ssh && tail -Fn 0 /var/log/auth.log | grep -w "password for" 2>> ssh.log &
    # ./log.sh &
    # tail -fn 0 /var/log/auth.log | grep --line-buffered "password for" > ssh.log &
    pids=""
    $use_ssh && systemctl is-active ssh >/dev/null || systemctl start ssh || return 1 \
    && tail -fn 0 /var/log/auth.log > "$log_ssh" & pids+="$! " #TODO switch to cowrie

    # $use_ssh && tail -fn 0 /var/log/auth.log > "$log_ssh" & #pids+="$! " #TODO switch to cowrie
    # $use_ftp && tail -fn 0 /var/log/vsftpd.log > "$log_ftp" & #pids+="$! " #TODO switch to rc file
    # $use_smb && tail -fn 0 /var/log/samba/log.smbd > $log_smb & #pids+="$! " #TODO switch to rc file


    live_feed &
    # pid2=$!

    rc_file="tmp.rc"
    echo -n > $rc_file
    $use_ftp && cat honeypot_ftp.rc >> $rc_file  #& pids+="$! "; } #TODO switch to rc file
    $use_smb && cat honeypot_smb.rc >> $rc_file
    [ -s "$rc_file" ] && msfconsole -r $rc_file -q -o "$msf_log" # & pids+="$! "
    # wait $!

    while true; do
        read -r -n 1 -t .1 -s && break
    done
    
    # echo $pids
    # $use_ftp || $use_smb && pkill -f msfconsole
    [ -n "$pids" ] && kill $pids #$pids2
    # The information of the users trying to access, and their input, should be saved into a log.
}

counter_scan() {
#     Using the log details, use the IP addresses to learn about them. Find their origin
# country, organization, contact information, open ports, services and save the
# information.
    echo "All your base are belong to us ~CATS 1991"
    
    attacker_ips=""
    $use_ssh && attacker_ips+="$(awk '/password for/ {print $(NF-3)}' "$log_ssh" | sort -u)\n"
    $use_ftp && attacker_ips+="$(awk '/\[\+\] FTP LOGIN/ {sub(/:.*/, ""); print $NF}' "$msf_log" | sort -u)\n"
    $use_smb && attacker_ips+="$(awk '/\[SMB\] NTLMv2-SSP Client/ {print $NF}' "$msf_log" | sort -u)\n"
    attacker_ips=$(echo -e "$attacker_ips" | sort -u | sed '/^$/d')

    if [ -n "$attacker_ips" ]; then
        port_scan="$SCRIPT_DIR/open_ports.txt"
        while read -r ip; do
            scan_dir="$USER_DIR/scans-$ip"
            
            # [ -e path ] && [ -d path ] && [ -w path ] && echo "Continue" \
            # || ([ -e path ] && [ -d path ] && echo "Error: Directory exists, but it's not writable") \
            # || ([ -e path ] && echo "Error: File or Directory exists, but it's not a writable directory") \
            # || (mkdir path && echo "Directory created")

            if ! [ -e "$scan_dir" ]; then
                mkdir "$scan_dir"
            elif ! [ -d "$scan_dir" ] || ! [ -w "$scan_dir" ]; then
                alert "ERROR: $scan_dir already exist but not as a writable directory"
                continue
            fi

            # geoiplookup "$ip" > "$scan_dir/location"
            curl -s "https://ipinfo.io/$ip/json" > "$scan_dir/location"
            if ! grep -oq "\"bogon\"" "$scan_dir/location"; then
                whois "$ip" > "$scan_dir/whois"
                dig "$ip" > "$scan_dir/dig"
            fi
            
            # masscan -p 0-65535 "$ip" --rate=10000 -oL "$scan_dir"/scan.txt
            nmap -p- -oN "$port_scan" "$ip"
            ports=$(grep "^[0-9]" "$port_scan" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
            nmap -p"$ports" -A -oN "$scan_dir/nmap_$ip.txt" -oX "$scan_dir/nmap_$ip.xml"
            xsltproc "$scan_dir/nmap_$ip.xml" -o "$scan_dir/nmap_$ip.html"
        done <<< "$attacker_ips"
        rm -f "$port_scan"
    fi
}
######################

main() {
    check_root || exit 1

    # install_progs

    welcome_msg

    parse_input || exit 1

    title "Alerter started using${modes_str}"

    # log_activity #&
    # log_pid=$!

    read -rp "should a counter scan be initiated? (y/n) " ans
    [ "${ans,,n}" == "y" ] && counter_scan

    success "done"
}

main