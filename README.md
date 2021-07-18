# Ubuntu server zfsbootmenu install script

tldr; Ubuntu server installation script: native encrypted zfs on root, zfsbootmenu, pyzsnap snapshot management. Optional remote ssh access during boot to unlock the ZFS drive or to rollback system to a previous state.

The script should be run from an Ubuntu live desktop iso (zfs 2.0 support needed for native encryption, so minimum Ubuntu 21.04 should be used).

Reddit discussion thread:

https://www.reddit.com/r/zfs/comments/mj4nfa/ubuntu_server_2104_native_encrypted_root_on_zfs/

--

I've created a bash script to install ubuntu server using the zfsbootmenu (ZBM) bootloader. ZBM is a zfs boot environment manager that allows rollbacks in case of a bad upgrade. Unlike zsys, it allows for remote login at boot to select which snapshot to boot from. So it is more useful than zsys for headless servers.
Ubuntu uses grub as default. The Ubuntu server root on zfs guide uses a separate boot pool with a restricted feature set because grub lacks full zfs support. ZBM doesn't have this issue, so there is no need for a separate boot pool and the added complexity that can cause for snapshot management.

I've used pyznap as the snapshot manager. Pyznap author comments on pyznap vs sanoid here:

https://github.com/yboetz/pyznap/issues/1#issuecomment-351015432

The snapshot workflow is:
1. "sudo pyznap snap" to take snapshots as per settings in a config file.
2. At reboot the user can press tab to load the ZBM menu to select a historic snapshot to boot from. Otherwise the default boot sequence happens.

Snapshots are also taken automatically on a time based schedule and when installing upgrades with apt.

Special thank you to the following.

rlaager (https://openzfs.github.io/openzfs-docs/Getting%20Started/Ubuntu/Ubuntu%2020.04%20Root%20on%20ZFS.html)

ahesford E39M5S62/zdykstra (https://github.com/zbm-dev/zfsbootmenu)

cythoning (https://github.com/yboetz/pyznap)
