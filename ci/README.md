# CI for the `initial` phase

`ci/run-initial-test.sh <profile>` boots the Debian Live standard ISO under QEMU with UEFI
firmware (OVMF), runs `debian_server_encrypted_root_zfs.sh initial` against virtual disks, and
then checks the result. It exercises the real script end to end, including debootstrap, the
ZFS DKMS build and the zfsbootmenu build. It does **not** boot the installed system.

What is checked (`guest-verify.sh`, run in the guest straight after `initial`):

- `rpool` is exported, nothing is mounted under `$mountpoint`, and `zpool import` lists it (if `initial` could not export it, that is only a warning and the pool is verified in place)
- it re-imports **without `-f`** and (if encrypted) unlocks with the generated passphrase
- dataset layout and properties, `bootfs`, compression, ashift
- files in the new root (sanoid, apt snapshot hook, networkd, zbm config, initramfs key hook,
  user/ssh files, the copied script and `.env`, install log) and their modes
- the EFI partition: type, label, rEFInd, `refind_linux.conf`, the zfsbootmenu image, NVRAM entry
- the pool exports cleanly again afterwards

## Profiles

A profile (`ci/profiles/<name>.sh`) is a few variable overrides. `gen-env.sh` builds the
`.env` as: defaults parsed from `buildenv()` in the script, then random passwords and a
generated admin SSH key, then the profile. It fails if any name in `ENV_VAR_ORDER` ends up
undefined. `CI_RAM_MB`, `CI_DISK_GB`, `CI_ISO_BASE` are harness settings. A profile with several
`disks_root_ids` lines (all `virtio-<serial>`) gets that many virtual disks. To add a config,
copy `simple.sh` and add its name to the workflow matrix.

## Running locally

Needs `qemu-system-x86`, `qemu-utils`, `ovmf`, `p7zip-full` (or `bsdtar`), `e2fsprogs`,
`python3-pexpect` and a usable `/dev/kvm` (`CI_ALLOW_TCG=1` permits software emulation, which is
far too slow for the full install). Output goes to `ci-work/<profile>/serial.log`.

## Driver notes

The guest is driven over the serial console. It answers the "Press Enter to Continue" prompts
and, if a pinned zfsbootmenu version/image is stale, the `[C/u/e]` prompt with `C` (emitting a
warning annotation). Any other prompt hangs the script and fails the job after 15 minutes of
silence.
