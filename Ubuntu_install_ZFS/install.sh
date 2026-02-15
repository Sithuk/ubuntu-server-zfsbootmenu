#!/bin/bash
## Script installs ubuntu on the zfs file system with snapshot rollback at boot.
## Refactored into modular structure by Antigravity.

set -euo pipefail

# Get project root to allow script_copy to find files correctly
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Sanitize project files (convert CRLF to LF) to handle Windows line endings
echo "Sanitizing project files..."
find "$PROJECT_ROOT" -type f -not -path "*/.git/*" -exec sed -i 's/\r//g' {} + || true

# Source configuration and modules
source "$PROJECT_ROOT/config.sh"
source "$PROJECT_ROOT/bin/utility"
source "$PROJECT_ROOT/bin/checks"
source "$PROJECT_ROOT/bin/disk"
source "$PROJECT_ROOT/bin/apt"
source "$PROJECT_ROOT/bin/zfs"
source "$PROJECT_ROOT/bin/system"
source "$PROJECT_ROOT/bin/software"

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

os_install() {
    export OS_INSTALL_MODE="yes"
    disclaimer
    connectivity_check 
    
    get_existing_pool_info
    identify_existing_esp
    
    ipv6_apt_live_iso_fix
    
    debootstrap_part1_Func
    # debootstrap_createzfspools_Func is replaced by logic in mountpointsFunc to handle existing pools
    mountpointsFunc 
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
    
    echo "OS installation into existing pool complete."
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
        user_action_banner "Starting initial system installation.\n  Press ENTER to CONTINUE or CTRL+C to ABORT."
        read -r _
        initialinstall
    ;;
    postreboot)
        user_action_banner "Starting postreboot setup.\n  Press ENTER to CONTINUE or CTRL+C to ABORT."
        read -r _
        postreboot
    ;;
    osinstall)
        user_action_banner "Starting installation into EXISTING ZFS pool.\n  Press ENTER to CONTINUE or CTRL+C to ABORT."
        read -r _
        os_install
    ;;
    reinstall-zbm)
        user_action_banner "Re-installing zfsbootmenu.\n  Press ENTER to CONTINUE or CTRL+C to ABORT."
        read -r _
        reinstall-zbm
    ;;
    reinstall-pyznap)
        user_action_banner "Re-installing pyznap.\n  Press ENTER to CONTINUE or CTRL+C to ABORT."
        read -r _
        reinstall-pyznap
    ;;
    *)
        printf "%s\n%s\n%s\n" "-----" "Usage: $0 initial | osinstall | postreboot | reinstall-zbm | reinstall-pyznap" "-----"
    ;;
esac

exit 0
