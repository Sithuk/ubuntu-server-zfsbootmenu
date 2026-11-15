#!/bin/bash
##Boots a Debian Live ISO under QEMU/KVM (UEFI), runs the install script's "initial" phase
##against virtual disks, then checks the result. See ci/README.md.
##Usage: ci/run-initial-test.sh <profile>      (profile = a file in ci/profiles/, minus .sh)
##Environment: CI_WORKDIR, CI_CACHE_DIR (ISO cache), CI_ALLOW_TCG=1 (permit running without KVM),
##  CI_RAM_MB_OVERRIDE, CI_BOOT_TIMEOUT
set -euo pipefail

profile_name="${1:?usage: run-initial-test.sh <profile>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"
profile="$here/profiles/${profile_name}.sh"
[ -f "$profile" ] || { echo "No such profile: ${profile}" >&2; exit 1; }

work="${CI_WORKDIR:-$repo/ci-work/${profile_name}}"
cache="${CI_CACHE_DIR:-$repo/ci-work/cache}"
script_name="debian_server_encrypted_root_zfs.sh"
rm -rf "$work"
mkdir -p "$work" "$cache"

for tool in qemu-system-x86_64 qemu-img mke2fs python3 curl sha256sum ssh-keygen; do
	command -v "$tool" >/dev/null || { echo "Missing required tool: ${tool}" >&2; exit 1; }
done
python3 -c 'import pexpect' 2>/dev/null || { echo "Missing python3 pexpect (apt install python3-pexpect)." >&2; exit 1; }

##Harness settings from the profile (CI_*), with defaults.
CI_RAM_MB=4096
CI_DISK_GB=16
CI_ISO_BASE="https://cdimage.debian.org/cdimage/release/current-live/amd64/iso-hybrid"
# shellcheck source=/dev/null
. "$profile"
CI_RAM_MB="${CI_RAM_MB_OVERRIDE:-$CI_RAM_MB}"   # e.g. for a small dev machine

echo "=== Generating env file ==="
ssh-keygen -q -t ed25519 -N "" -C "ci-admin" -f "$work/admin_key"
CI_ADMIN_PUBKEY_FILE="$work/admin_key.pub" "$here/gen-env.sh" "$profile" "$work/${script_name%.sh}.env"

##One virtio disk per root-pool id; the id is "virtio-<serial>".
mapfile -t root_ids < <(
	# shellcheck source=/dev/null
	# shellcheck disable=SC2154
	( . "$work/${script_name%.sh}.env"; printf '%s\n' "$disks_root_ids" | tr -d '[:blank:]' | sed '/^$/d' )
)
[ "${#root_ids[@]}" -gt 0 ] || { echo "Profile defines no disks_root_ids." >&2; exit 1; }

echo "=== Fetching Debian Live ISO ==="
curl -fsSL "$CI_ISO_BASE/SHA256SUMS" -o "$work/SHA256SUMS"
iso_line="$(grep -E ' \*?debian-live-[0-9.]+-amd64-standard\.iso$' "$work/SHA256SUMS" | head -n1)"
[ -n "$iso_line" ] || { echo "No standard live ISO listed in ${CI_ISO_BASE}/SHA256SUMS." >&2; exit 1; }
iso_sha="${iso_line%% *}"
iso_name="$(printf '%s' "$iso_line" | sed -E 's/^[0-9a-f]+ +\*?//')"
iso="$cache/$iso_name"
if [ -f "$iso" ] && echo "$iso_sha  $iso" | sha256sum -c --status; then
	echo "Using cached ${iso_name}"
else
	rm -f "$cache"/debian-live-*-standard.iso
	curl -fsSL --retry 3 -o "$iso" "$CI_ISO_BASE/$iso_name"
	echo "$iso_sha  $iso" | sha256sum -c -
fi

echo "=== Extracting live kernel and initrd ==="
##Direct kernel boot lets us add console=ttyS0 without editing the ISO's bootloader config.
##OVMF still provides a UEFI environment, which the script requires (/sys/firmware/efi).
mkdir -p "$work/boot"
if command -v 7z >/dev/null; then extract=7z; elif command -v 7zz >/dev/null; then extract=7zz; else extract=""; fi
if [ -n "$extract" ]; then
	"$extract" e -y -o"$work/boot" "$iso" 'live/vmlinuz-*' 'live/initrd.img-*' >/dev/null
elif command -v bsdtar >/dev/null; then
	( cd "$work/boot" && bsdtar -xf "$iso" --strip-components=1 'live/vmlinuz-*' 'live/initrd.img-*' )
else
	echo "Need 7z (p7zip-full) or bsdtar to read the ISO." >&2; exit 1
fi
kernel="$(find "$work/boot" -name 'vmlinuz-*' | head -n1)"
initrd="$(find "$work/boot" -name 'initrd.img-*' | head -n1)"
[ -n "$kernel" ] && [ -n "$initrd" ] || { echo "Kernel/initrd not found in ISO." >&2; exit 1; }

echo "=== Building seed disk and virtual disks ==="
seed="$work/seed"
mkdir -p "$seed"
cp "$repo/$script_name" "$work/${script_name%.sh}.env" "$here/guest-verify.sh" "$seed/"
mke2fs -q -t ext4 -L CISEED -d "$seed" "$work/seed.img" 32M
disk_args=()
for i in "${!root_ids[@]}"; do
	id="${root_ids[$i]}"
	[[ "$id" == virtio-* ]] || { echo "disks_root_ids entry '${id}' must start with virtio- for the CI guest." >&2; exit 1; }
	qemu-img create -q -f qcow2 "$work/root${i}.qcow2" "${CI_DISK_GB}G"
	disk_args+=( -drive "if=none,id=root${i},file=$work/root${i}.qcow2,format=qcow2" \
		-device "virtio-blk-pci,drive=root${i},serial=${id#virtio-}" )
done

echo "=== Locating OVMF ==="
ovmf_code=""; ovmf_vars=""
for dir in /usr/share/OVMF /usr/share/edk2/ovmf /usr/share/edk2/x64; do
	if [ -f "$dir/OVMF_CODE_4M.fd" ] && [ -f "$dir/OVMF_VARS_4M.fd" ]; then ovmf_code="$dir/OVMF_CODE_4M.fd"; ovmf_vars="$dir/OVMF_VARS_4M.fd"; break; fi
	if [ -f "$dir/OVMF_CODE.fd" ] && [ -f "$dir/OVMF_VARS.fd" ]; then ovmf_code="$dir/OVMF_CODE.fd"; ovmf_vars="$dir/OVMF_VARS.fd"; break; fi
done
[ -n "$ovmf_code" ] || { echo "OVMF firmware not found (apt install ovmf)." >&2; exit 1; }
cp "$ovmf_vars" "$work/OVMF_VARS.fd"

if [ -w /dev/kvm ]; then
	accel=( -accel kvm -cpu host )
elif [ "${CI_ALLOW_TCG:-0}" = "1" ]; then
	echo "::warning::/dev/kvm unavailable; using software emulation (very slow)."
	accel=( -accel tcg -cpu max )
else
	echo "/dev/kvm is not usable. Set CI_ALLOW_TCG=1 to run without it (very slow)." >&2
	exit 1
fi

qemu_cmd=(
	qemu-system-x86_64 -machine q35 "${accel[@]}" -smp "$(nproc)" -m "$CI_RAM_MB"
	-nographic -monitor none -no-reboot
	-drive "if=pflash,format=raw,readonly=on,file=$ovmf_code"
	-drive "if=pflash,format=raw,file=$work/OVMF_VARS.fd"
	-kernel "$kernel" -initrd "$initrd"
	-append "boot=live components console=ttyS0,115200 loglevel=3 noeject"
	-drive "file=$iso,format=raw,media=cdrom,readonly=on"
	-drive "if=none,id=seed,file=$work/seed.img,format=raw,readonly=on"
	-device "virtio-blk-pci,drive=seed,serial=ciseed"
	"${disk_args[@]}"
	-nic "user,model=virtio-net-pci"
)

echo "=== Booting guest ==="
echo "ISO: ${iso_name}  profile: ${profile_name}  RAM: ${CI_RAM_MB}MB  disks: ${#root_ids[@]}x${CI_DISK_GB}G"
python3 "$here/drive-guest.py" --log "$work/serial.log" \
	${CI_BOOT_TIMEOUT:+--boot-timeout "$CI_BOOT_TIMEOUT"} -- "${qemu_cmd[@]}"
