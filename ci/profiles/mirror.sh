# shellcheck shell=bash disable=SC2034 # Sourced by gen-env.sh, which reads these by name.
##CI test profile: two disks in a mirrored, natively encrypted root pool, no data pool, no Tor.
##See simple.sh for how profiles are layered and which CI_* settings exist.

user="ci"
hostname="ci-mirror"

##Root pool disks: one id per line; the harness creates one virtio disk per line.
disks_root_ids="virtio-ciroot0
virtio-ciroot1"
topology_root="mirror"
disks_root="2"

swap_size="1024"
zfs_arc_max_mb="512"
zfs_arc_min_mb="128"

install_warning_level="FRONTEND=noninteractive"

CI_RAM_MB=4096
CI_DISK_GB=16
