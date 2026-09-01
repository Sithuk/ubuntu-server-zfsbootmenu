# Debian zfsbootmenu install script

`debian_server_encrypted_root_zfs.sh` installs Debian on the ZFS filesystem with integrated snapshot
management using [sanoid](https://github.com/jimsalterjrs/sanoid). Snapshots can be rolled back remotely at
boot over SSH using [zfsbootmenu](https://zfsbootmenu.org/). This is useful where there is no physical access
to the machine — handy for a headless KVM/libvirt host.

It is a Debian port of [Sithuk/ubuntu-server-zfsbootmenu](https://github.com/Sithuk/ubuntu-server-zfsbootmenu).
See "Differences from the upstream Ubuntu script" below for what changed and why.

Snapshots allow you to roll back your system to a previous state if there is a problem. The system
automatically creates snapshots on a timer (sanoid). Snapshots are pruned over time to keep fewer older
snapshots.

Supports:
- Debian trixie (13), bookworm (12).
- Root filesystem on ZFS.
- Single, mirror, raid0, raidz1, raidz2, and raidz3 topologies.
- Native ZFS encryption.
- Remote unlocking of encrypted pools at boot over SSH.
- Automated system snapshots taken on a timer (sanoid).
- Remote rollback of snapshots at boot for system recovery over SSH.
- Creation of a separate encrypted data pool (single/mirror/raidz).
- SSH administration access set up unconditionally (openssh-server + your public key).

## Usage

Boot the target machine from a **Debian Live "standard" (cli-only) amd64 ISO**
(`debian-live-<version>-amd64-standard.iso`, from https://www.debian.org/CD/live/ — pick the release matching
`debianver` in the script, e.g. trixie). Log in as `root` at the live session prompt (or `sudo -i`).

Get the script onto the live system, e.g. by copying it over `scp` from another machine, or downloading it if
you've pushed it somewhere reachable:

	scp debian_server_encrypted_root_zfs.sh root@<live-host-ip>:~/
	chmod +x ~/debian_server_encrypted_root_zfs.sh

Configuration lives in a `debian_server_encrypted_root_zfs.env` file next to the script — named after the script
itself (not a bare `.env`), so the pair still finds each other if you rename or copy the script elsewhere. Only
`buildenv` creates or amends this file; every other option (`initial`/`postreboot`/`remoteaccess`/`datapool`)
requires it to already exist and stops with an error telling you to run `buildenv` first. Build it interactively:

	./debian_server_encrypted_root_zfs.sh buildenv

This walks you through every setting (disk topology, encryption, hostname, user, SSH key, data pool, remote
access, etc.), defaulting each question to its built-in default the first time, or to the value already saved
in the file on every run after that — so re-running it later — e.g. to add a data pool once the drive is
physically attached, well after the initial install — only asks about what's actually changed. It backs up any
existing `debian_server_encrypted_root_zfs.env` before writing a new one, and only writes at the end, so an
aborted run (Ctrl+C) never leaves a half-written file. If you'd rather edit by hand instead, run `buildenv` once
to create the file, then edit it directly:

	nano debian_server_encrypted_root_zfs.env

`debian_server_encrypted_root_zfs.env` holds plaintext passwords (and your SSH key, if set) — keep it private
(`chmod 600`, already set automatically; don't commit it to git — `.gitignore` in this directory already
excludes `*.env`).

Run the "initial" option of the script. It checks the env file up front and lists everything wrong with it
(fields missing from the file entirely, invalid combinations, disk IDs that don't match the chosen topology)
before touching any disks — if it complains, run `buildenv` again to fix what it lists, then retry:

	./debian_server_encrypted_root_zfs.sh initial

Reboot after the initial installation completes and log in to the new install (username/password as set via
`buildenv` — or your SSH key(s), if `admin_ssh_pubkeys` was set). The script copies both itself and its
environment file into `/home/<user>/` in the new install, so the remaining steps work the same way there. Run
the second
part of the script:

	./debian_server_encrypted_root_zfs.sh postreboot

## Optional: Remote access during boot

The script includes an optional feature to provide remote access during boot. Remote access over SSH allows
the system state to be rolled back to a previous snapshot without physical access to the system. This is
helpful to return a system to a bootable state following a failed upgrade.

If the root pool uses native ZFS encryption with a password, this is also how you unlock it. The passphrase is
stored in a keyfile (`/etc/zfs/$RPOOL.key`) baked into the *target* kernel's own initramfs, so the OS's own boot
stage auto-unlocks without prompting — but that keyfile only ever lives inside the encrypted root pool itself
(never in ZFSBootMenu's own image on the unencrypted ESP), and ZFSBootMenu can't reach it from within its own
bootloader environment. So ZFSBootMenu still halts at boot waiting for the passphrase, exactly as before.
Without remote access enabled, that passphrase can only be entered at the physical console; with it enabled,
connect over SSH as below, run `zfsbootmenu` (or `zbm`) at the dropbear shell, and enter the passphrase in its
TUI. This means an unattended reboot (crash, power loss, kernel update) will sit waiting at that prompt until
someone unlocks it — there's no automatic unlock.

Run the following optional part of the script to enable remote access to zfsbootmenu during boot. It must be run
from the installed system, not from the live environment, and `remoteaccess_dropbear_pubkeys` must be set to the
key(s) you will connect with — a boot environment nothing can log in to is of no use, so the stage stops rather
than building one. This is deliberately a separate key set from `admin_ssh_pubkeys`/openssh: a key that can SSH
into the running OS is not automatically also a key that can unlock the pool before it boots. Each key is written
into the pre-boot environment with `no-agent-forwarding` set, since that login has no legitimate use for it.

	./debian_server_encrypted_root_zfs.sh remoteaccess

Connect as `root` on port 222 to the server's IP address during the zfsbootmenu boot stage (this is a separate
pre-boot dropbear environment — not a way to SSH into the installed OS as root).

Enabling remote access also raises zfsbootmenu's countdown from `timeout_zbm_no_remote_access` to
`timeout_zbm_remote_access` (90 seconds by default) in `refind_linux.conf`, since that countdown is the whole
window in which a remote session can reach the menu before the default boot environment is booted. An encrypted
root still waits at its passphrase prompt indefinitely either way; the timeout is what makes *rollback* reachable
remotely, not just unlock. On a multi-ESP install the backup ESPs keep the old timeout until they are next synced
with `/etc/zfsbootmenu/generate-zbm.post.d/esp-sync.sh`.

Rebuild the image after adding SSH keys, or after a kernel or zfs update, with:

	/bin/sh /etc/zfsbootmenu/rebuild-zbm-remote.sh

That wrapper is written by the `remoteaccess` stage and holds the settings it chose (build directory, key source,
and the tor package when Tor is enabled). Upstream's own `contrib/remote-ssh-build.sh` is fetched and used as-is
underneath it. Re-running the `remoteaccess` stage itself is also supported, and is how settings are changed after
the fact — enabling Tor later, rotating the onion client-auth key, moving to a static IP. Existing dropbear host
keys are kept, so clients don't see a changed host key; deleting `/etc/zfsbootmenu/dropbear` by hand would
regenerate them and produce exactly that warning. Only an ed25519 host key is generated (not the rsa/ecdsa
dracut-crypt-ssh would otherwise also produce) — one private key in the image on unencrypted `/boot` instead of
three.

### Staying on top of updates to the remote-access image

`dropbear` and `tor` aren't version-pinned the way `zbm_ref`/`zbm_builder_image` are — `zbm-builder.sh` installs
both from Void Linux's rolling package repo at build time, so they're only ever as fresh as the last time the
image was rebuilt. The `remoteaccess` stage installs `/etc/zfsbootmenu/check-zbm-updates.sh`, run daily by the
`zbm-check-updates.timer` systemd timer, which checks: whether a newer `zfsbootmenu` release or `zbm_builder_image`
build is available upstream (the same check `buildenv` runs interactively, just non-interactive here), and whether
Void's repo currently has newer `dropbear`/`tor` versions than what actually got built into the image last time
(recorded in `/etc/zfsbootmenu/last-build-versions.txt` by `rebuild-zbm-remote.sh`). If anything's stale, it shows
up as a login notice (`/etc/update-motd.d/85-zbm-updates`) pointing at `rebuild-zbm-remote.sh` — nothing rebuilds
automatically. Both the checker and the timer are regenerated on every `remoteaccess` run, so they always reflect
the `zbm_ref`/`zbm_builder_image`/`remoteaccess_tor` that run used.

### Optional: also reach it over Tor

Set `remoteaccess_tor="yes"` (alongside the DHCP/static dropbear access above, not instead of it) to also build a
Tor v3 onion service into the same pre-boot environment, forwarding to the same dropbear listener. Useful when
the server is behind CGNAT or has no port-forwarding/static IP set up for it — the onion address is reachable
from anywhere Tor can reach, with no network configuration on the client's end beyond having Tor running.

Tor is a fallback for when the direct-IP dropbear path isn't reachable, not the regular way in — dropbear is
already listening well before tor would even be needed, since it hooks pre-udev rather than waiting on the
network. So tor deliberately waits before it starts: `remoteaccess_tor_start_delay` (300 seconds by default)
controls how long, counted from when the network comes up. This only matters while the boot is still sitting at
the zfsbootmenu prompt — with an unencrypted root pool and nothing holding the boot there (no connected dropbear
session, nobody at the console), the default environment auto-boots at `timeout_zbm_remote_access` and tor never
gets the chance to start; `buildenv` prints a note when the delay and timeout are set up that way. An encrypted
root waits at its passphrase prompt indefinitely regardless of the timeout, so tor's delay is never at risk there.

The onion service requires client authorization: only a connection from someone holding the matching private key
is even able to reach it. Generate the keypair once, before running `remoteaccess` (this script does not generate
it for you — same as `admin_ssh_pubkeys` above, you supply a public key rather than have the script create one):

	openssl genpkey -algorithm x25519 -out client.prv.pem
	cat client.prv.pem | grep -v " PRIVATE KEY" | openssl base64 -d | tail -c 32 | base32 | sed 's/=//g' > client.prv.key
	openssl pkey -in client.prv.pem -pubout | grep -v " PUBLIC KEY" | openssl base64 -d | tail -c 32 | base32 | sed 's/=//g' > client.pub.key

Set `remoteaccess_tor_client_auth_pubkey` in the environment file to `descriptor:x25519:<contents of
client.pub.key>` — easiest through `buildenv`, which rejects a malformed value on the spot rather than letting it
become a lockout at the boot prompt. Then run `remoteaccess` as usual. It prints the onion address (also stored
as `remoteaccess_tor_onion_hostname` in the environment file, and readable at
`/etc/zfsbootmenu/tor/hidden_service/hostname` on the
host). On the machine you'll connect *from*, keep `client.prv.pem`/`client.prv.key` private, and set up the client
side of onion auth:

	mkdir -p -m 700 /var/lib/tor/onion_auth
	echo "<onion-address-without-.onion>:descriptor:x25519:<contents of client.prv.key>" > /var/lib/tor/onion_auth/client.auth_private

and add `ClientOnionAuthDir /var/lib/tor/onion_auth` to that machine's own `torrc`. Then connect with:

	torify ssh root@<onion-address>.onion -p 22

(Full background on the key format: [Tor's client-auth documentation](https://community.torproject.org/onion-services/advanced/client-auth/).)

**Where the identity comes from:** the onion service's key is generated by `buildenv`, not by the boot image
build. With `remoteaccess_tor="yes"` and no key recorded yet, the wizard offers to work one out and stores all
three parts in the environment file: `remoteaccess_tor_onion_secret_key` (the identity), plus the derived
`remoteaccess_tor_onion_public_key` and `remoteaccess_tor_onion_hostname`, which are managed for you — change the
secret key and the other two are cleared and re-derived. Working this out needs the `tor` binary purely as a
calculator (nothing is published, and no traffic is carried), so if tor isn't installed, `buildenv` asks before
installing it and offers to remove it again afterwards. Running the wizard on a machine that already has an onion
service installed at `/etc/zfsbootmenu/tor/hidden_service` adopts that identity rather than replacing it.

Because the identity lives in the environment file, the `remoteaccess` stage just writes it into the image and
needs no tor on the server at all. If it finds the identity missing from the environment file it falls back to
working it out itself, with the same install-and-remove prompts, and then tells you to run `buildenv` to record
it.

**Stable address:** the address is therefore stable across image rebuilds *and* across a full reinstall with a
fresh ESP, as long as the environment file is kept (it holds a private key, so it stays `chmod 600` and out of
git). To move an address to another install by hand, copy `remoteaccess_tor_onion_secret_key` across on its own
and leave the other two blank — they get re-derived from it. If the machine already has a *different* identity
installed, `remoteaccess` shows both addresses and waits for confirmation before replacing the installed one with
the one from the environment file.

**Physical security note:** the onion service's private key lives at `/etc/zfsbootmenu/tor/hidden_service/` on
the unencrypted root filesystem, and gets baked into the ZFSBootMenu image on the unencrypted ESP — same
exposure class as the dropbear host key above. Anyone with physical access to the disk can extract it and
impersonate the onion service; client authorization limits who can *reach* the service, it doesn't change that.

## Optional: Create a zfs data pool

The script includes an optional feature to create an encrypted zfs data pool on a non-root drive. The data
pool will be unlocked automatically after the root drive password is entered at boot.

This is commonly run well after `initial`/`postreboot`, once the data drive is actually attached to the
running system. Once it is, run `buildenv` again on that system to select the drive's disk ID(s) (it re-runs
the same wizard, but only asks about what's still missing or needs picking again — your existing settings are
kept as-is), then run `datapool`:

	./debian_server_encrypted_root_zfs.sh buildenv
	./debian_server_encrypted_root_zfs.sh datapool

## Snapshots and rollback scope

**ZFSBootMenu's rollback is scoped to `$RPOOL/ROOT` only** (the boot environment mounted at `/`) — it reverts
OS/package state (`/`, `/etc`, `/bin`, `/lib`, `/sbin`, most of `/usr` and `/var`), not your data. That scope
doesn't change no matter what's snapshotted elsewhere: rollback and snapshotting are two different things, and
only `$RPOOL/ROOT` has both.

Snapshotting itself is broader, via two independent, automatic mechanisms:

- **sanoid** (installed by `sanoid_install`, config at `/etc/sanoid/sanoid.conf`), driven by `sanoid.timer`
  (the package's default systemd timer, which runs every 15 minutes), covers two policies:
  - `template_production`, applied recursively to `$RPOOL/ROOT`: 4 sub-hourly (`frequently`), 24 hourly, 7
    daily, 4 weekly, 6 monthly, 0 yearly.
  - `template_data`, applied to `$RPOOL/home` (recursive — covers every user's home directory and
    `$RPOOL/home/root`), `$RPOOL/srv`, `$RPOOL/usr/local`, `$RPOOL/var/log`, `$RPOOL/var/mail`,
    `$RPOOL/var/spool`, `$RPOOL/var/www`, and the optional data pool (added by `createdatapool` — see below):
    24 hourly, 30 daily, 8 weekly, 12 monthly, 0 yearly. No sub-hourly snapshots, since this data isn't meant
    to be undone minute-by-minute the way an apt run is — it's protected against accidental deletion or
    corruption over a longer window instead.
  - Both policies prune themselves automatically (`autoprune`). `/etc/sanoid/sanoid.conf` is a plain file you
    can hand-edit at any time — sanoid re-reads it on every timer tick, no reinstall or restart needed.
    Raising retention only affects snapshots taken from then on; lowering it can prune existing sanoid-taken
    snapshots down to the new count on the very next run. Snapshots taken by the apt hook below, or by hand,
    are unaffected either way — sanoid only prunes snapshots matching its own naming scheme.
- **apt pre-invoke hook** (`/etc/apt/apt.conf.d/80-zfs-snapshot`) snapshots `$RPOOL/ROOT` recursively before
  every `apt` operation, prefixed `pre-apt_<timestamp>`. These are outside sanoid's control and are instead
  pruned by a separate daily systemd timer once older than 7 days.

The data pool is added to `template_data` by `createdatapool` itself, once the pool actually exists — not by
`sanoid_install`, which only runs once, during `postreboot`, before the data pool is normally created. If you
run `datapool` before `postreboot` (sanoid not installed yet), it warns and skips; add a `[$datapool]` section
to `/etc/sanoid/sanoid.conf` by hand in that case, or just run `postreboot` first.

Not covered by either mechanism: `/var/cache`, `/var/tmp`, and `/var/lib/docker`, which are deliberately
excluded (created with `com.sun:auto-snapshot=false` — cache/ephemeral data and Docker's own datasets/snapshots
respectively). Back these up by your own means if you need recovery for them.

One consequence of the split above: a snapshot of `$RPOOL/home` (or the data pool) protects that data and lets
you restore it — via `zfs rollback` on that specific dataset, or by copying files out of its `.zfs/snapshot`
directory — but it will never show up as an option in ZFSBootMenu's own rollback menu, since that menu only
lists boot environments under `$RPOOL/ROOT`.

## Rescuing from a Live environment

If the installed system won't boot, boot a Debian Live environment and import the pools by hand:

	zpool export -a                # Export all pools.
	zpool import -N -R /mnt rpool  # "rpool" should be the root pool name.
	zfs load-key -r -L prompt -a   # -r: recurse into child datasets. -a: all encryption roots in all
	                                # imported pools. -L prompt: read the passphrase interactively.
	zfs mount -a                   # Mount all datasets.

## Maintenance

Every zfsbootmenu asset this script fetches or builds against is pinned by `zbm_ref` (the zfsbootmenu git tag)
and `zbm_builder_image` (the matching dated build-container tag), both set in `buildenv` and persisted to your
environment file. To move to a newer zfsbootmenu release:

1. Check the [zfsbootmenu releases page](https://github.com/zbm-dev/zfsbootmenu/releases) and bump `zbm_ref` in
   your environment file to the new tag.
2. Find the dated build-container tag published alongside that release at
   [the zbm-builder package page](https://github.com/orgs/zbm-dev/packages/container/package/zbm-builder)
   (match its `published_at` date to the release), and set `zbm_builder_image` to it.
3. Re-run `initial` (or `remoteaccess`, if only rebuilding remote access) to build against the new pins.
   `zbm_builder_image` is otherwise persisted in `/etc/zfsbootmenu/zbm-builder.conf` from the last time it was
   written there — `remoteaccess` re-syncs that file with the environment file on every run, so a bump takes
   effect the next time it's run, not only on a fresh `initial` install.

`initial` and `remoteaccess` also check both values against upstream automatically and prompt you if either is
behind, so this is only needed to make a bump permanent rather than one-off.

## Differences from the upstream Ubuntu script

- **Configuration lives in a `<script_name>.env` file, not inline edits to the script.** The upstream script has
  all its variables at the top of the file, edited in place; this port instead keeps built-in defaults inside
  `buildenv`, the only mode that creates or amends a same-named `.env` file (interactively, or by hand-editing
  the file it creates), so secrets aren't mixed into version-controlled script text and the script itself never
  needs editing for a normal install. Every other stage (`initial`/`postreboot`/`remoteaccess`/`datapool`) reads
  settings only from that file, never from an in-script default, and is entirely non-interactive except for its
  own press-enter/Ctrl+C safety gate and destructive-action warnings -- each one verifies the file has what it
  needs before touching anything, rather than prompting mid-run.
- **Live environment**: boots from a Debian Live "standard" ISO (`live-boot`, checked via `boot=live` on the
  kernel command line) instead of an Ubuntu live-desktop ISO (`casper`).
- **ZFS is not pre-built in Debian's kernel or live image.** The live environment builds `zfs-dkms` against
  the running live kernel before partitioning starts, and the chroot install builds it again against the
  installed kernel package. This is the newest/riskiest part of this port, so watch the "Waiting for the zfs
  DKMS module to build..." steps closely on first run, and be ready to check `dkms status` /
  `/var/lib/dkms/zfs/*/build/make.log` if it stalls.
- **apt sources**: Debian components (`main contrib non-free non-free-firmware`) instead of Ubuntu's
  (`main universe restricted multiverse`); contrib is required for `zfs-dkms`. Security updates come from the
  separate `debian-security` suite, not just a `-security` pocket of the main archive. No mirror speed-test —
  `deb.debian.org` is already geo-routed, so `mirror_archive_url` is a plain optional override instead.
- **Networking**: `systemd-networkd` (a plain DHCP `.network` file) instead of `netplan`, since Debian's base
  install has neither netplan nor NetworkManager.
- **Packages**: `linux-image-amd64`/`linux-headers-amd64` instead of `-generic`; `tasksel install standard`
  instead of the `ubuntu-server` metapackage; no desktop-flavour variants (KDE/Xfce/etc).
- **Groups**: dropped Ubuntu/snap-specific `lxd` and `lpadmin` groups.
- **SSH access is unconditional**, not gated behind an opt-in "extra programs" bundle: `openssh-server` is
  always installed and enabled during `postreboot`, and `usersetup` (during `initial`) prepares
  `~/.ssh/authorized_keys` for the admin user — pre-filled from `admin_ssh_pubkeys` (one or more keys, one per
  line) if you set it, otherwise left for you to populate before rebooting. The `remoteaccess` dropbear stage
  uses a separate key set, `remoteaccess_dropbear_pubkeys`, so a key authorized for openssh isn't automatically
  also authorized to unlock the pool pre-boot.

## Testing status

This script has been tested end-to-end against a real server. As with the upstream script: this could wipe out
all your data. Dry-run it against a throwaway VM (with virtual disks you don't care about) before pointing it at
real disks, and pay particular attention to the ZFS-in-live-environment DKMS build step called out above.

## Credits

Ported from [Sithuk/ubuntu-server-zfsbootmenu](https://github.com/Sithuk/ubuntu-server-zfsbootmenu), which
itself credits:

ahesford E39M5S62/zdykstra (https://github.com/zbm-dev/zfsbootmenu)

jimsalterjrs (https://github.com/jimsalterjrs/sanoid)

rlaager (https://openzfs.github.io/openzfs-docs/Getting%20Started/Debian/Debian%20Bookworm%20Root%20on%20ZFS.html)
