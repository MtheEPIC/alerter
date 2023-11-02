#!/bin/bash

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

welcome_msg() {
    echo -e "[*] Alerter - Netwrok Honetpot\n"
    echo "1. SSH"
    echo "2. FTP"
    echo "3. SMB"
    echo "4. Start all services"
    echo
}

declare -g choice
get_user_input() {
    read -rp "[+] Enter your choice: " choice

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
    add_choice "${choice}"

    [ -z "$modes_str" ] && echo "Invalid Input" && return 1

    return 0
}

live_feed() {
    # When running the Alerter, display in live-mode the Honeypot activity.
    echo "$(date): $ip accessed SMB [admin:password]"
    echo "$(date): $ip accessed SMB [admin:password1]"

    use_ssh && tail -Fn 0 /var/log/auth.log | grep -w "password for"
}

log_activity() {
    echo "logging..."
    # The information of the users trying to access, and their input, should be saved into a log.
}

counter_scan() {
    echo "All your base are belong to us ~CATS 1991"
    # Using the log details, use the IP addresses to learn about them. Find their origin country, organization, contact information, open ports, services and save the information.
}

######################
check_root || exit 1

welcome_msg

parse_input || exit 1

echo "[+] Alerter started using${modes_str}"

live_feed &
pid=$!
log_activity
counter_scan

wait $pid
