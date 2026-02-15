# Ubuntu ZFS Installation Script (Modular & Unencrypted)

This project provides a robust, modular script to install Ubuntu (Server or Desktop) on a ZFS root filesystem with **ZFSBootMenu** for advanced boot management and snapshot rollback support. It is designed for users who want the power of ZFS combined with a fast, unencrypted installation process.

## Key Features

- **Ubuntu Support**: Verified for Ubuntu 22.04 (Jammy) and 24.04 (Noble).
- **ZFS-on-Root**: Fully automated partitioning and ZFS pool/dataset creation.
- **Modular Design**: Refactored into a clean, modular structure for easier maintenance and customization.
- **ZFSBootMenu Integrated**: Boot directly from ZFS datasets with support for snapshot rollback and boot environment management.
- **Snapshot Management**: Integrated `sanoid` for automated snapshots and `pyznap` support.
- **Variant Selection**: Install Ubuntu Server, Desktop, Kubuntu, Xubuntu, Budgie, or MATE.
- **High Performance**: Optimized for unencrypted ZFS performance without the overhead of LUKS or native ZFS encryption.

## Project Structure

The script has been split into a main execution script, a configuration file, and several functional modules:

- `install.sh`: The main entry point for the installation process.
- `config.sh`: Centralized configuration for user settings, disk topology, and system preferences.
- `bin/`: Contains the logic modules:
    - `apt`: APT source management and IPv6 fixes.
    - `checks`: Pre-flight environment and hardware checks.
    - `disk`: Drive partitioning and formatting logic.
    - `software`: Post-install software and variant-specific packages.
    - `system`: Core system installation, chroot setup, and bootloader configuration.
    - `utility`: Shared logging and helper functions.
    - `zfs`: ZPOOL and dataset creation logic.

## Usage

### 1. Preparation
Boot your system with an Ubuntu Live Desktop ISO. Open a terminal and clone the repository:

```bash
git clone https://github.com/Sithuk/ubuntu-server-zfsbootmenu.git ~/ubuntu-zfs-install
```
```bash
cd ~/ubuntu-zfs-install/Ubuntu_install_ZFS
```
```bash
chmod -R +x install.sh ./bin/
```

### 2. Configuration
Edit `config.sh` to set your username, hostname, disk topology, and other preferences:

```bash
nano config.sh
```

### 3. Initial Installation
Run the initial phase to partition disks, create pools, and debootstrap the base system:

```bash
./install.sh initial
```

### 4. Post-Reboot Setup
After the initial installation completes, reboot into your new ZFS system and login with the credentials defined in `config.sh`. Then, run the second phase to finalize the configuration and install the chosen Ubuntu variant:

```bash
./install.sh postreboot
```

### Optional Actions
- **Install into Existing ZFS Pool**:
  ```bash
  sudo ./install.sh osinstall
  ```
  This command interactively allows you to select an imported ZFS pool and name a new Ubuntu installation to be created within it. It skips disk formatting and partitioning.

- **Re-install ZFSBootMenu**:
  ```bash
  sudo ./install.sh reinstall-zbm
  ```

## FAQ & Snapshot Management

### How do I rollback using a snapshot?
Reboot into **ZFSBootMenu**:
1. Select your boot environment and press `Ctrl+S`.
2. Select the desired snapshot.
3. Choose **Clone and Promote** (`Ctrl+X`) to create a new bootable environment from the snapshot.

### How do I manage automated snapshots?
The script installs `sanoid` by default. Configuration can be found in `/etc/sanoid/sanoid.conf`. System updates via `apt` also trigger automatic snapshots for safety.

## Credits & Resources

- **ZFSBootMenu**: [zfsbootmenu.org](https://zfsbootmenu.org/)
- **Sanoid**: [github.com/jimsalterjrs/sanoid](https://github.com/jimsalterjrs/sanoid)
- **OpenZFS**: [openzfs.github.io](https://openzfs.github.io/)

---
*Note: This version of the script focuses on unencrypted ZFS installations for maximum simplicity and speed. For encrypted installations, please refer to the original monolithic script versions.*
