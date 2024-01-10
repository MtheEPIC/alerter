#!/bin/bash

################################################################################
#                                                                              #
# alerter.sh                                                                   #
#                                                                              #
# version: 1.0.0                                                               #
#                                                                              #
# ALERTER - Run Linux as a Honeypot and alert for anomalies.                   #
#                                                                              #
# Student Name - Michael Ivlev                                                 #
# Student Code - S11                                                           #
# Class Code - HMagen773616                                                    #
# Lectures Name - Eliran Berkovich                                             #
#                                                                              #
# GNU GENERAL PUBLIC LICENSE                                                   #
#                                                                              #
# This program is free software: you can redistribute it and/or modify         #
# it under the terms of the GNU General Public License as published by         #
# the Free Software Foundation, either version 3 of the License, or            #
# (at your option) any later version.                                          #
#                                                                              #
# This program is distributed in the hope that it will be useful,              #
# but WITHOUT ANY WARRANTY; without even the implied warranty of               #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                #
# GNU General Public License for more details.                                 #
#                                                                              #
# You should have received a copy of the GNU General Public License            #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.        #
#                                                                              #
################################################################################

declare -g SCRIPT_DIR #used for internal files and scripts
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
declare -g USER_DIR #used for files to be easily accessible by the end user
USER_DIR=$(pwd)
readonly SCRIPT_DIR USER_DIR

source "$SCRIPT_DIR/styled_prints.sh"

declare -rg ssh_log="$USER_DIR/.ssh.log"
declare -rg ftp_log="$USER_DIR/.ftp.log"
declare -rg smb_log="$USER_DIR/.smb.log"
declare -rg msf_log="$USER_DIR/.msf.log"
declare -rg all_log="$USER_DIR/honeypot.log"
declare -rg ftp_msf_template="$SCRIPT_DIR/.honeypot_ftp.rc"
declare -rg smb_msf_template="$SCRIPT_DIR/.honeypot_smb.rc"

# VARS
declare -rg USERNAME="${SUDO_USER:-$USER}"
declare -A modes_enum

modes_enum=( [SSH]=1 [FTP]=2 [SMB]=3 [ALL]=4 )

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root."
        return 1
    fi
    return 0
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
    return 0
}

use_ssh=false
use_ftp=false
use_smb=false
# Sets flags for selected services
# input: $1 - valid user input
# return: 0 - no errors
add_choice() {
    opt="$1"
    
    local use_all=false
    [[ "$opt" == *${modes_enum[ALL]}* ]] && use_all=true
    [[ "$opt" == *${modes_enum[SSH]}* ]] || $use_all && { use_ssh=true; modes_str+=" 22(SSH)"; }
    [[ "$opt" == *${modes_enum[FTP]}* ]] || $use_all && { use_ftp=true; modes_str+=" 21(FTP)"; }
    [[ "$opt" == *${modes_enum[SMB]}* ]] || $use_all && { use_smb=true; modes_str+=" 445(SMB)"; }

    return 0
}

# Parces the users service choice, checks for validity
# return: 1 - problem with parsing
#         0 - no errors
parse_input() {
    while ! get_user_input; do
        alert "Invalid Input"
    done

    modes_str=""
    add_choice "${choice}" || return 1

    [ -z "$modes_str" ] && alert "Invalid Input: failed to parse" && return 1

    return 0
}

# When running the Alerter, display in live-mode the Honeypot activity.
live_feed() {
    create_file "$all_log" || exit 1

    $use_ssh && tail -Fn 0 "$ssh_log" 2>/dev/null | grep --line-buffered --text -w "password for" | tee -a "$all_log" &
    
    filter="("
    $use_ftp && filter+="FTP"
    $use_ftp && $use_smb && filter+="|"
    $use_smb && filter+="\[SMB\]"
    filter+=").*"
    $use_ftp || $use_smb && tail -Fn 0 "$msf_log" 2>/dev/null | grep --line-buffered --text -Eo "$filter" | tee -a "$all_log" &

}

# Log the bad actors access method to the honeypot
log_activity() {
    echo "staring honeypot logging... this may take a few seconds depending on the amount of services"
    echo "enter exit to stop the logging" 

    local pids=""
    $use_ssh && systemctl is-active ssh >/dev/null || systemctl start ssh || return 1 \
    && create_file "$ssh_log" && tail -fn 0 /var/log/auth.log > "$ssh_log" & pids+="$! " #TODO switch to cowrie

    live_feed &
    # pid2=$!
    local rc_file="$SCRIPT_DIR/honeypot_msf.rc"
    echo -n > "$rc_file"
    $use_ftp && cat "$ftp_msf_template" >> "$rc_file"
    $use_smb && cat "$smb_msf_template" >> "$rc_file"
    local msf_flag=false
    [ -s "$rc_file" ] && { msf_flag=true; msfconsole -r "$rc_file" -q -o "$msf_log" ; } # & pids+="$! "
    # wait $!

    while ! $msf_flag; do
        read -rs input
        [ "$input" == "exit" ] && break
    done
    
    # echo $pids
    # $use_ftp || $use_smb && pkill -f msfconsole
    # shellcheck disable=SC2086
    [ -n "$pids" ] && kill $pids #$pids2
}

# create a dir with a given name using the user as the owner
# input: $1 - dir name
# return: 1 - cannot create dir / dir exists but inaccessible
#         0 - created successfuly / dir exists
create_dir() {
    local dir_name="$1"
    if ! [ -e "$dir_name" ]; then
        su "$USERNAME" -c "mkdir $dir_name"
    elif ! [ -d "$dir_name" ] || ! [ -w "$dir_name" ]; then
        alert "ERROR: $dir_name already exist but not as a writable directory"
        return 1
    fi
    return 0
}

# create a file with a given name using the user as the owner
# input: $1 - file name
# return: 1 - cannot create file / file exists but inaccessible
#         0 - created successfuly / file exists
create_file() {
    local file_name="$1"
    if ! [ -e "$file_name" ]; then
        su "$USERNAME" -c "touch $file_name"
    elif ! [ -f "$file_name" ] || ! [ -w "$file_name" ]; then
        alert "ERROR: $file_name already exist but not as a writable file"
        return 1
    fi
    return 0
}


counter_scan() {
# Using the log details scan the captured bad actors. Find their origin
# creates a log with country, organization, open ports etc.    
    local attacker_ips=""
    $use_ssh && attacker_ips+="$(awk '/password for/ {print $(NF-3)}' "$ssh_log" | sort -u)\n"
    $use_ftp && attacker_ips+="$(awk '/\[\+\] FTP LOGIN/ {sub(/:.*/, ""); print $NF}' "$msf_log" | sort -u)\n"
    $use_smb && attacker_ips+="$(awk '/\[SMB\] NTLMv2-SSP Client/ {print $NF}' "$msf_log" | sort -u)\n"
    attacker_ips=$(echo -e "$attacker_ips" | sort -u | sed '/^$/d')

    if [ -n "$attacker_ips" ]; then
        local port_scan="$SCRIPT_DIR/open_ports.txt"
        while read -r ip; do
            local scan_dir="$USER_DIR/scans-$ip"
            local location="$scan_dir/location"
            local whois="$scan_dir/whois"
            local dig="$scan_dir/dig"
            local ports_txt="$scan_dir/nmap_$ip.txt"
            local ports_xml="$scan_dir/nmap_$ip.xml"
            local ports_html="$scan_dir/nmap_$ip.html"

            create_dir "$scan_dir" || continue

            create_file "$location" || continue
            # geoiplookup "$ip" > "$scan_dir/location"
            curl -s "https://ipinfo.io/$ip/json" > "$location"
            if grep -oq "\"country\"" "$location"; then
                create_file "$whois" || continue
                whois "$ip" > "$whois"
                create_file "$dig" || continue
                dig "$ip" > "$dig"
            fi
            
            create_file "$ports_txt" || continue
            create_file "$ports_xml" || continue
            create_file "$ports_html" || continue
            # masscan -p 0-65535 "$ip" --rate=10000 -oL "$scan_dir"/scan.txt
            nmap -p- -oN "$port_scan" "$ip"
            ports=$(grep "^[0-9]" "$port_scan" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
            nmap -p"$ports" -A -oN "$ports_txt" -oX "$ports_xml" "$ip"
            xsltproc "$ports_xml" -o "$ports_html"
        done <<< "$attacker_ips"
        rm -f "$port_scan"
    fi
    
    success "All your base are belong to us ~CATS 1991"
}

main() {
    check_root || exit 1

    welcome_msg

    parse_input || exit 1

    title "Alerter started using${modes_str}"

    log_activity || exit 1

    read -rp "initiate a counter scan? (y/n) " ans
    [ "${ans,,n}" == "y" ] && counter_scan

    success "done"
}

main
