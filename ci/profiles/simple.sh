# shellcheck shell=bash disable=SC2034 # Sourced by gen-env.sh, which reads these by name.
##CI test profile: one disk, natively encrypted root pool, no data pool, no Tor.
##
##Sourced by gen-env.sh on top of the defaults from the install script's own buildenv()
##(so the pinned zbm_ref / zbm_builder_image shipped in the script are what gets tested),
##after the random PASSWORD / zfs_root_password / admin_ssh_pubkeys are generated.
##May set any variable in the script's ENV_VAR_ORDER, plus CI_* harness settings:
##  CI_RAM_MB   guest memory                (default 4096)
##  CI_DISK_GB  size of each root-pool disk (default 16)
##  CI_ISO_BASE Debian Live download dir    (default current-live, i.e. current stable)
##To add a config, copy this file, change it, and add it to the workflow matrix.

user="ci"
hostname="ci-simple"

##Root pool disk(s): one id per line. The harness creates one virtio disk per line, with
##serial = the id minus its "virtio-" prefix.
disks_root_ids="virtio-ciroot0"
topology_root="single"
disks_root="1"

##Keep the installed system small enough for a CI guest.
swap_size="1024"
zfs_arc_max_mb="512"
zfs_arc_min_mb="128"

##Don't let debconf stop the install to show critical messages.
install_warning_level="FRONTEND=noninteractive"

CI_RAM_MB=4096
CI_DISK_GB=16
