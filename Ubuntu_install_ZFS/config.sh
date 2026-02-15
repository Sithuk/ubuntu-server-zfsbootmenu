#!/bin/bash

# Ubuntu release and variant
ubuntuver="noble"            # Ubuntu release. "jammy" (22.04), "noble" (24.04), "questing" (25.10)
distro_variant="server"      # Ubuntu variant. "server" (CLI only), "desktop", "kubuntu", etc.

# User and Hostname
user="testuser"              # Username for new install
PASSWORD="testuser"          # Password for user in new install
hostname="ubuntu"            # Hostname for the system

# ZFS Root Pool Configuration
RPOOL="rpool"                # Root pool name
zfs_rpool_ashift="12"        # ashift=9 (512B), 12 (4KiB), 13 (8KiB)
topology_root="single"       # "single", "mirror", "raid0", "raidz1", "raidz2", "raidz3"
disks_root="1"               # Number of disks for root pool (ignored for single)

# Partition Sizes
EFI_boot_size="512"          # EFI partition size in MiB
swap_size="500"              # Swap partition size in MiB

# ZFS Data Pool Configuration
datapool="datapool"          # Data pool name
datapoolmount="/mnt/$datapool" # Data pool mount point
zfs_dpool_ashift="12"        # ashift for data pool
topology_data="single"       # Topology for data pool
disks_data="1"               # Number of disks for data pool

# ZFS General settings
zfs_compression="zstd"       # "lz4" or "zstd"

# Installation Paths
mountpoint="/mnt/ub_server"  # Mountpoint in live ISO
log_loc="/var/log"           # Installation log location
install_log="ubuntu_setup_zfs_root.log" # Log filename

# Network and Remote Access
ethprefix="e"                # First letter of ethernet interface
remoteaccess_first_boot="no" # "yes" to enable remote access during first boot
remoteaccess_hostname="zbm"  # Hostname for ZFSBootMenu
remoteaccess_ip_config="dhcp" # "dhcp", "dhcp,dhcp6", "dhcp6", or "static"
remoteaccess_ip="192.168.0.222" # Static IP for ZFSBootMenu
remoteaccess_netmask="255.255.255.0" # Subnet mask for static IP

# Timeouts and Boot
timeout_rEFInd="3"           # rEFInd timeout
timeout_zbm_no_remote_access="3" # ZFSBootMenu timeout (no remote)
timeout_zbm_remote_access="45"   # ZFSBootMenu timeout (with remote)
quiet_boot="yes"             # Show boot sequence if "no"

# APT settings
mirror_archive=""            # ISO 3166-1 country code for mirror speed test
ubuntu_original="http://archive.ubuntu.com/ubuntu"
ipv6_apt_fix_live_iso="no"   # Enable if apt-get is slow in live ISO

# Misc
install_warning_level="PRIORITY=critical" # "PRIORITY=critical" or "FRONTEND=noninteractive"
extra_programs="no"          # Install cifs-utils, locate, man-db, openssh-server, tldr
locale="en_GB.UTF-8"         # Language setting
timezone="Europe/London"     # Timezone setting
