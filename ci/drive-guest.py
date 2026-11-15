#!/usr/bin/env python3
"""Boot the Debian Live ISO under QEMU and drive the install script over the serial console.

usage: drive-guest.py --log FILE [--boot-timeout S] [--idle-timeout S] [--total-timeout S] -- QEMU_COMMAND...

The guest must have the seed disk (serial "ciseed") holding the install script, its .env
and guest-verify.sh. Steps: log in -> copy the seed to /root/ci -> run "initial" (answering
its Enter-to-continue prompts) -> run guest-verify.sh -> power off.
Exit 0 only if initial and guest-verify.sh both exited 0.
"""
import argparse
import sys
import time

import pexpect

SCRIPT = "debian_server_encrypted_root_zfs.sh"
PROMPT = "CI-READY# "


class Tee:
    """Log sink that also records when output last arrived, to detect a hung guest."""

    def __init__(self, path):
        self.f = open(path, "w", buffering=1)
        self.last = time.monotonic()

    def write(self, s):
        self.f.write(s)
        sys.stdout.write(s)
        sys.stdout.flush()
        self.last = time.monotonic()

    def flush(self):
        self.f.flush()
        sys.stdout.flush()


def main():
    argv = sys.argv[1:]
    if "--" not in argv:
        sys.exit(__doc__)
    split = argv.index("--")
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--boot-timeout", type=int, default=600)
    ap.add_argument("--idle-timeout", type=int, default=900, help="fail if the guest prints nothing for this long")
    ap.add_argument("--total-timeout", type=int, default=3600)
    args = ap.parse_args(argv[:split])
    qemu = argv[split + 1:]

    tee = Tee(args.log)
    deadline = time.monotonic() + args.total_timeout
    child = pexpect.spawn(qemu[0], qemu[1:], encoding="utf-8", codec_errors="replace",
                          timeout=15, dimensions=(50, 200))
    child.logfile_read = tee

    def die(msg):
        tail = (child.before or "")[-1500:] if isinstance(child.before, str) else ""
        print(f"\n::error::{msg}\n--- last output ---\n{tail}", flush=True)
        child.close(force=True)
        sys.exit(1)

    def wait(patterns, idle):
        """expect() that fails on EOF, on no output for `idle` seconds, or on the total deadline."""
        pats = list(patterns) + [pexpect.EOF]
        while True:
            try:
                i = child.expect(pats, timeout=15)
            except pexpect.TIMEOUT:
                now = time.monotonic()
                if now - tee.last > idle:
                    die(f"guest printed nothing for {idle}s (hung, or waiting on a prompt this driver doesn't answer)")
                if now > deadline:
                    die(f"total timeout of {args.total_timeout}s exceeded")
                continue
            if i == len(patterns):
                die("QEMU exited unexpectedly")
            return i

    def run(cmd, idle=300):
        """Run a command at the shell prompt, return its exit status."""
        child.sendline(cmd)
        wait([PROMPT], idle)
        child.sendline('echo "CI_RC=$?"')
        wait([r"CI_RC=(\d+)"], idle)
        rc = int(child.match.group(1))
        wait([PROMPT], idle)
        return rc

    # Boot and log in (Debian Live default account is user/live).
    wait([r"login: "], args.boot_timeout)
    child.sendline("user")
    wait([r"Password: "], 60)
    child.sendline("live")
    wait([r"\$ "], 60)
    child.sendline("sudo -i")
    wait([r"# "], 60)
    # Prompt built from two quoted pieces so the echoed command line doesn't itself match PROMPT.
    child.sendline("export PS1=\"CI-READY\"'# '; dmesg -n 1; stty cols 200")
    wait([PROMPT], 60)

    if run("mkdir -p /root/ci /mnt/seed && mount -o ro /dev/disk/by-id/virtio-ciseed /mnt/seed "
           "&& cp -a /mnt/seed/. /root/ci/ && rm -rf /root/ci/lost+found && umount /mnt/seed "
           "&& chmod +x /root/ci/*.sh") != 0:
        die("could not copy the seed disk into the guest")

    # The install itself.
    print("\n=== CI: running initial ===", flush=True)
    child.sendline(f'cd /root/ci && ./{SCRIPT} initial; echo "CI_INITIAL_RC=$?"')
    while True:
        i = wait([r"Press Enter to Continue", r"\[C/u/e\]", r"CI_INITIAL_RC=(\d+)"], args.idle_timeout)
        if i == 0:
            child.send("\n")
        elif i == 1:
            print("\n::warning::A pinned zfsbootmenu version/image is behind upstream; continuing with the pin.", flush=True)
            child.sendline("C")
        else:
            rc = int(child.match.group(1))
            break
    wait([PROMPT], 60)
    if rc != 0:
        die(f"initial exited with status {rc}")

    print("\n=== CI: verifying ===", flush=True)
    if run("bash /root/ci/guest-verify.sh", idle=600) != 0:
        die("guest-verify.sh reported failures")

    child.sendline("poweroff")
    child.expect(pexpect.EOF, timeout=180)
    print("\n=== CI: initial install test passed ===", flush=True)


if __name__ == "__main__":
    main()
