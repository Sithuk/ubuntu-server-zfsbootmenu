#!/bin/bash
## Script installs ubuntu on the zfs file system with snapshot rollback at boot.
## Refactored into modular structure by Antigravity.

set -euo pipefail

# Get project root to allow script_copy to find files correctly
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source configuration and modules
source "$PROJECT_ROOT/config.sh"
source "$PROJECT_ROOT/bin/utility.sh"
source "$PROJECT_ROOT/bin/checks.sh"
source "$PROJECT_ROOT/bin/disk.sh"
source "$PROJECT_ROOT/bin/apt.sh"
source "$PROJECT_ROOT/bin/zfs.sh"
source "$PROJECT_ROOT/bin/system.sh"
source "$PROJECT_ROOT/bin/software.sh"

initialinstall() {
    disclaimer
    live_desktop_check
    connectivity_check 
    getdiskID_pool "root"
    ipv6_apt_live_iso_fix

    debootstrap_part1_Func
    debootstrap_createzfspools_Func
    debootstrap_installminsys_Func
    systemsetupFunc_part1 
    systemsetupFunc_part2 
    systemsetupFunc_part3 
    
    keyboard_console_setup
    systemsetupFunc_part4 
    systemsetupFunc_part5 
    
    usersetup 
    logcompress 
    reinstate_apt "chroot" 
    script_copy 
    fixfsmountorder 
    logcopy 
    
    echo "Initial minimal system setup complete."
    echo "Reboot required to complete installation."
    echo "First login is ${user}:${PASSWORD}"
    echo "Following reboot, run script with postreboot option to complete installation."
}

postreboot() {
    disclaimer
    connectivity_check 
    
    distroinstall 
    NetworkManager_config 
    sanoid_install 
    extra_programs 
    reinstate_apt "base" 
    
    echo "Installation complete: ${distro_variant}."
    echo "Reboot."
}

# Main execution logic
logFunc
environment_check
update_date_time

case "${1-default}" in
    initial)
        echo "Running initial system installation. Press Enter to Continue or CTRL+C to abort."
        read -r _
        initialinstall
    ;;
    postreboot)
        echo "Running postreboot setup. Press Enter to Continue or CTRL+C to abort."
        read -r _
        postreboot
    ;;
    datapool)
        echo "Running create data pool on non-root drive. Press Enter to Continue or CTRL+C to abort."
        read -r _
        createdatapool
    ;;
    reinstall-zbm)
        echo "Re-installing zfsbootmenu. Press Enter to Continue or CTRL+C to abort."
        read -r _
        reinstall-zbm
    ;;
    reinstall-pyznap)
        echo "Re-installing pyznap. Press Enter to Continue or CTRL+C to abort."
        read -r _
        reinstall-pyznap
    ;;
    *)
        printf "%s\n%s\n%s\n" "-----" "Usage: $0 initial | postreboot | datapool | reinstall-zbm | reinstall-pyznap" "-----"
    ;;
esac

exit 0
