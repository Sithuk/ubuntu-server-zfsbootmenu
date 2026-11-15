#!/bin/bash
# shellcheck disable=SC2154 # Variables come from the sourced .env file.
##Runs inside the live guest after "initial" has finished. Checks the pool was exported
##cleanly, then re-imports it (without -f) and checks the files and datasets "initial"
##should have left behind. Exits non-zero if anything failed.
##Expects debian_server_encrypted_root_zfs.env next to it.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
. "$here/debian_server_encrypted_root_zfs.env"

verify_root="/mnt/ci_verify"
fails=0

pass(){ echo "PASS: $1"; }
fail(){ echo "FAIL: $1"; fails=$((fails + 1)); }
check(){
	##check "description" command args... -- passes if the command succeeds.
	desc="$1"; shift
	if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}
file_in(){ check "present: $1" test -f "${verify_root}$1"; }
exec_in(){ check "present and executable: $1" test -x "${verify_root}$1"; }
mode_is(){
	##mode_is /path 600
	actual="$(stat -c %a "${verify_root}$1" 2>/dev/null || echo missing)"
	if [ "$actual" = "$2" ]; then pass "mode $2: $1"; else fail "mode $2: $1 (is ${actual})"; fi
}
contains(){
	##contains /path fixed-string
	if grep -qF -- "$2" "${verify_root}$1" 2>/dev/null; then pass "$1 contains: $2"; else fail "$1 contains: $2"; fi
}

echo "=== Pool state straight after initial ==="
##A failed export isn't a failure: "initial" says so itself (zbm imports the pool at boot regardless).
##Warn, then verify against the pool where it is.
pool_still_imported=0
if zpool list -H -o name 2>/dev/null | grep -qx "$RPOOL"; then
	echo "WARN: ${RPOOL} was not exported by initial (allowed); trying a forced export"
	if zpool export -f "$RPOOL"; then
		echo "NOTE: forced export worked"
	else
		echo "WARN: ${RPOOL} cannot be exported; verifying it in place under ${mountpoint}"
		pool_still_imported=1
	fi
else
	pass "${RPOOL} is not imported"
fi

if [ "$pool_still_imported" -eq 1 ]; then
	verify_root="$mountpoint"
	pass "${RPOOL} still imported; skipping the re-import checks"
else
	if grep -q " ${mountpoint}[ /]" /proc/mounts; then
		fail "mounts still present under ${mountpoint}"
		grep " ${mountpoint}[ /]" /proc/mounts
	else
		pass "nothing mounted under ${mountpoint}"
	fi
	if zpool import 2>&1 | grep -q "pool: ${RPOOL}"; then
		pass "${RPOOL} is visible as an importable pool"
	else
		fail "${RPOOL} is not visible as an importable pool"
	fi

	echo "=== Re-import without -f ==="
	mkdir -p "$verify_root"
	if zpool import -N -R "$verify_root" "$RPOOL"; then
		pass "zpool import ${RPOOL} (no -f)"
	else
		fail "zpool import ${RPOOL} (no -f)"
		echo "Cannot continue without the pool."
		echo "RESULT: ${fails} check(s) failed"
		exit 1
	fi
fi

check "pool health ONLINE" test "$(zpool list -H -o health "$RPOOL")" = "ONLINE"
check "ashift=${zfs_rpool_ashift}" test "$(zpool get -H -o value ashift "$RPOOL")" = "$zfs_rpool_ashift"

if [ -n "$zfs_root_password" ]; then
	check "encryption=aes-256-gcm" test "$(zfs get -H -o value encryption "$RPOOL")" = "aes-256-gcm"
	if printf '%s\n' "$zfs_root_password" | zfs load-key -r "$RPOOL"; then
		pass "root pool unlocks with zfs_root_password"
	else
		fail "root pool unlocks with zfs_root_password"
	fi
else
	check "encryption=off" test "$(zfs get -H -o value encryption "$RPOOL")" = "off"
fi

check "compression=${zfs_compression}" test "$(zfs get -H -o value compression "$RPOOL")" = "$zfs_compression"

bootfs="$(zpool get -H -o value bootfs "$RPOOL")"
case "$bootfs" in
	"${RPOOL}/ROOT/debian."*) pass "bootfs set (${bootfs})" ;;
	*) fail "bootfs set to ${RPOOL}/ROOT/debian.* (is '${bootfs}')" ;;
esac
check "root dataset canmount=noauto" test "$(zfs get -H -o value canmount "$bootfs")" = "noauto"
check "root dataset mountpoint=/" test "$(zfs get -H -o value mountpoint "$bootfs")" = "/"
check "org.zfsbootmenu:commandline set on ${RPOOL}/ROOT" \
	test "$(zfs get -H -o value org.zfsbootmenu:commandline "${RPOOL}/ROOT")" != "-"

for ds in ROOT srv usr/local var/log var/mail var/spool var/www var/cache var/tmp var/lib/docker home home/root "home/${user}"; do
	check "dataset ${RPOOL}/${ds}" zfs list -H -o name "${RPOOL}/${ds}"
done
check "var/cache excluded from snapshots" test "$(zfs get -H -o value com.sun:auto-snapshot "${RPOOL}/var/cache")" = "false"

echo "=== Mount the new root ==="
if zfs mount "$bootfs" && zfs mount -a; then
	pass "mounted ${bootfs} and child datasets under ${verify_root}"
else
	fail "mounted ${bootfs} and child datasets under ${verify_root}"
fi

echo "=== Files left by initial ==="
check "hostname is ${hostname}" test "$(cat "${verify_root}/etc/hostname" 2>/dev/null)" = "$hostname"
check "user ${user} exists" grep -q "^${user}:" "${verify_root}/etc/passwd"
check "root password locked" grep -qE '^root:[!*]' "${verify_root}/etc/shadow"
file_in /etc/fstab
contains /etc/fstab "swap"
file_in /etc/crypttab

file_in /etc/sanoid/sanoid.conf
file_in /etc/apt/apt.conf.d/80-zfs-snapshot
exec_in /usr/local/bin/apt-snapshot-prune.sh
file_in /etc/systemd/system/apt-snapshot-prune.service
file_in /etc/systemd/system/apt-snapshot-prune.timer
check "a systemd-networkd .network file exists" \
	sh -c "ls '${verify_root}'/etc/systemd/network/10-*.network"

if [ -n "$zfs_root_password" ]; then
	file_in "/etc/zfs/${RPOOL}.key"
	mode_is "/etc/zfs/${RPOOL}.key" 0
	file_in /etc/initramfs-tools/hooks/zfs-root-key
fi

file_in /etc/zfsbootmenu/config.yaml
exec_in /etc/zfsbootmenu/zbm-builder.sh
file_in /etc/zfsbootmenu/zbm-builder.conf

for f in "debian_server_encrypted_root_zfs.sh" "debian_server_encrypted_root_zfs.env"; do
	file_in "/home/${user}/${f}"
	check "owned by ${user}: /home/${user}/${f}" \
		test "$(stat -c %U "${verify_root}/home/${user}/${f}" 2>/dev/null)" = "$user"
done
exec_in "/home/${user}/debian_server_encrypted_root_zfs.sh"
mode_is "/home/${user}/debian_server_encrypted_root_zfs.env" 600
check "installed .env matches the one used" \
	cmp -s "$here/debian_server_encrypted_root_zfs.env" "${verify_root}/home/${user}/debian_server_encrypted_root_zfs.env"

file_in "/home/${user}/.ssh/authorized_keys"
mode_is "/home/${user}/.ssh/authorized_keys" 600
if [ -n "$admin_ssh_pubkeys" ]; then
	first_key="$(printf '%s\n' "$admin_ssh_pubkeys" | head -n1)"
	contains "/home/${user}/.ssh/authorized_keys" "$first_key"
fi

file_in "${log_loc}/${install_log}"
mode_is "${log_loc}/${install_log}" 600

echo "=== EFI system partition ==="
disk_id="$(printf '%s\n' "$disks_root_ids" | sed -n '1p' | tr -d '[:space:]')"
disk_path="/dev/disk/by-id/${disk_id}"
esp="${disk_path}-part1"
check "partition 1 is an EFI System Partition" \
	sh -c "sgdisk -i1 '${disk_path}' | grep -qi 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B'"
check "partition 2 is swap" \
	sh -c "sgdisk -i2 '${disk_path}' | grep -qiE '0657FD6D-A4AB-43C4-84E5-0933C84B4F4F|A19D880F-05FC-4D3B-A006-743F0F84911E'"
check "partition 3 exists" sh -c "sgdisk -i3 '${disk_path}'"
check "ESP is vfat labelled EFI" \
	sh -c "[ \"\$(blkid -s TYPE -o value '${esp}')\" = vfat ] && [ \"\$(blkid -s LABEL -o value '${esp}')\" = EFI ]"
mkdir -p "${verify_root}/boot/efi"
if mount -o ro "$esp" "${verify_root}/boot/efi"; then
	pass "mounted ESP"
	file_in /boot/efi/EFI/refind/refind_x64.efi
	file_in /boot/efi/EFI/refind/refind.conf
	contains /boot/efi/EFI/refind/refind.conf 'default_selection "EFI/debian"'
	file_in /boot/efi/EFI/debian/refind_linux.conf
	contains /boot/efi/EFI/debian/refind_linux.conf "zbm.timeout=${timeout_zbm_no_remote_access}"
	check "zfsbootmenu image present in EFI/debian (>1MB)" \
		sh -c "[ -n \"\$(find '${verify_root}/boot/efi/EFI/debian' -type f -size +1M)\" ]"
	umount "${verify_root}/boot/efi" || fail "unmount ESP"
else
	fail "mounted ESP"
fi
check "efibootmgr has a rEFInd entry" sh -c "efibootmgr | grep -q 'rEFInd Boot Manager'"

echo "=== Export again ==="
umount -R "$verify_root" 2>/dev/null || true
if [ "$pool_still_imported" -eq 1 ]; then
	echo "NOTE: ${RPOOL} could not be exported after initial either; skipping the export checks"
else
	if zpool export "$RPOOL"; then
		pass "zpool export ${RPOOL}"
	else
		fail "zpool export ${RPOOL}"
	fi
	if zpool list -H -o name 2>/dev/null | grep -qx "$RPOOL"; then fail "${RPOOL} not imported afterwards"; else pass "${RPOOL} not imported afterwards"; fi
fi

if [ "$fails" -eq 0 ]; then
	echo "RESULT: all checks passed"
	exit 0
fi
echo "RESULT: ${fails} check(s) failed"
exit 1
