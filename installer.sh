#!/bin/bash

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source $SCRIPT_DIR/styled_prints.sh
apps=( "rsyslog" "nmap" "metasploit-framework" "xsltproc") 


check_root() {
    if [[ $EUID -ne 0 ]]; then
        alert "This script must be run as root."
        return 1
    fi
    return 0
}

run_installer() {   
    check_root || return 1
    apt update || return 1
    apt install -y ${apps[*]} || return 1
    return 0
}

check_apps() {
    if ! dpkg-query -W -f='${Status}' ${apps[*]} &>/dev/null; then
        alert "missing some apps"; return 1
    fi
    success "All apps are installed"; return 0
}

while getopts "hqd" opt; do
    case "$opt" in
        h)
            echo "-q => checkes the installation status"
            echo "-d => installes with more details"
            exit 0
            ;;
        q)
            check_apps
            exit $?
            ;;
        d)
            run_installer || exit 1
            ;;
        *)
            alert "invalid option"
            exit 1
            ;;
    esac
done

run_installer &>/dev/null
[ $? -eq 1 ] && alert "an error has ocurred, try to run with -d to get more info" && exit 1

success "All dependencies have been successfully installed"
