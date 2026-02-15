#!/bin/bash

environment_check() {
    ## Check for root privileges
    if [ "$(id -u)" -ne 0 ]; then
        echo "Please run as root."
        exit 1
    fi

    ## Check for EFI boot environment
    if [ -d /sys/firmware/efi ]; then
        echo "Boot environment check passed. Found EFI boot environment."
    else
        echo "Boot environment check failed. EFI boot environment not found. Script requires EFI."
        exit 1
    fi

    ## Check encryption defined if password defined
    if [ -n "$zfs_root_password" ]; then
        if [ -z "$zfs_root_encrypt" ]; then
            echo "Password entered but no encryption method defined. Please define the zfs_root_encrypt variable."
            exit 1
        fi
    fi
}

live_desktop_check() {
    ## Check for live desktop environment
    if [ "$(dpkg -l ubuntu-desktop)" ]; then
        echo "Desktop environment test passed."
        if grep casper /proc/cmdline >/dev/null 2>&1; then
            echo "Live environment present."
        else
            echo "Live environment test failed. Run script from a live desktop environment."
            exit 1
        fi
    else
        echo "Desktop environment test failed. Run script from a live desktop environment."
        exit 1
    fi

    ## Check live desktop version
    live_desktop_version="$( . /etc/os-release && echo ${VERSION_CODENAME} )"
    if [ "$(echo "${live_desktop_version}" | tr '[:upper:]' '[:lower:]')" = "$(echo "${ubuntuver}" | tr '[:upper:]' '[:lower:]')" ]; then
        echo "Live environment version test passed."
    else
        echo "Live environment version test failed."
        echo "The live environment version does not match the Ubuntu version to be installed. Re-run script from an environment which matches the version to be installed. This is to avoid zfs version conflicts."
        exit 1
    fi
}

keyboard_console_settings() {
    kb_console_settings=/tmp/kb_console_selections.conf
    apt install -y debconf-utils
    
    export DEBIAN_PRIORITY=high
    export DEBIAN_FRONTEND=dialog
    dpkg-reconfigure keyboard-configuration
    dpkg-reconfigure console-setup
    export DEBIAN_"${install_warning_level}"
    
    debconf-get-selections | grep keyboard-configuration | tee "${kb_console_settings}"
    debconf-get-selections | grep console-setup | tee -a "${kb_console_settings}"
}

topology_min_disk_check() {
    ## Check that number of disks meets minimum number for selected topology.
    pool="$1"
    echo "Checking script variables for $pool pool..."
    
    topology_pool_pointer="topology_$pool"
    eval "topology_val=\$${topology_pool_pointer}"
    echo "User defined topology for ${pool} pool: $topology_val"
    
    disks_pointer="disks_${pool}"
    eval "disks_val=\$${disks_pointer}"
    echo "User defined number of disks in pool: $disks_val"

    num_disks_check() {
        min_num_disks="$1"
        if [ "$disks_val" -lt "$min_num_disks" ]; then
            echo "A $topology_val topology requires at least $min_num_disks disks. Check variable for number of disks or change the selected topology."
            exit 1
        fi
    }
    
    case "$topology_val" in
        single) true ;;
        mirror|raid0|raidz1) num_disks_check "2" ;;
        raidz2) num_disks_check "3" ;;
        raidz3) num_disks_check "4" ;;
        *)
            echo "Pool topology not recognised. Check pool topology variable."
            exit 1
        ;;
    esac
    printf "%s\n\n" "Minimum disk topology check passed for $pool pool."
}

disclaimer() {
    echo "***WARNING*** This script could wipe out all your data, or worse! I am not responsible for your decisions. Press Enter to Continue or CTRL+C to abort."
    read -r _
}
