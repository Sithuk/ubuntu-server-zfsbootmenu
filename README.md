# Ubuntu zfsbootmenu install script

This script creates an Ubuntu installation using the ZFS filesystem. The installation has integrated snapshot management using pyznap. Snapshots can be rolled back remotely at boot over ssh using zfsbootmenu. This is useful where there is no physical access to the machine.

Snapshots allow you to rollback your system to a previous state if there is a problem. The system automatically creates snapshots on a timer and also when the system is updated with apt. Snapshots are pruned over time to keep fewer older snapshots.

Supports:
- Ubuntu 22.04, 24.04.
- Root filesystem on ZFS.
- Choose from: Ubuntu Server, Ubuntu Desktop, Kubuntu, Xubuntu, Budgie, and Ubuntu MATE.
- Single, mirror, raid0, raidz1, raidz2, and raidz3 topologies.
- LUKS and native ZFS encryption.
- Remote unlocking of encrypted pools at boot over SSH.
- Automated system snapshots taken on a timer and also on system updates. 
- Remote rollback of snapshots at boot for system recovery over SSH.
- Creation of a separate encrypted data pool (single/mirror/raidz).

## Usage
Boot the system with an Ubuntu live desktop iso. Start the terminal (Ctrl+Alt+T) and enter the following.

	git clone https://github.com/Sithuk/ubuntu-server-zfsbootmenu.git ~/ubuntu-server-zfsbootmenu
    cd ~/ubuntu-server-zfsbootmenu
    chmod +x ubuntu_server_encrypted_root_zfs.sh
	
Edit the variables in the ubuntu_server_encrypted_root_zfs.sh file to your preferences.

	nano ubuntu_server_encrypted_root_zfs.sh
	
Run the "initial" option of the script.

	./ubuntu_server_encrypted_root_zfs.sh initial

Reboot after the initial installation completes and login to the new install. Username and password is as set in the script variables. Then run the second part of the script.

	./ubuntu_server_encrypted_root_zfs.sh postreboot

## Optional: Remote access during boot
The script includes an optional feature to provide remote access during boot. Remote access over ssh allows the system state to be rolled back to a previous snapshot without physical access to the system. This is helpful to return a system to a bootable state following a failed upgrade.

Run the following optional part of the script to enable remote access to zfsbootmenu during boot. Guidance on the use of zfsbootmenu can be found at its project website linked in the credits below.

	./ubuntu_server_encrypted_root_zfs.sh remoteaccess

## Optional: Create a zfs data pool
The script includes an optional feature to create an encrypted zfs data pool on a non-root drive. The data pool will be unlocked automatically after the root drive password is entered at boot.

	./ubuntu_server_encrypted_root_zfs.sh datapool

## FAQ
Additional guidance and notes can be found in the script.
1. How do I rollback the system using a snapshot in zfsbootmenu?

   You can rollback to a snapshot by doing the following, for example if an upgrade does not work and you wish to revert to a previous state. I recommend testing any changes out in a virtual machine first before rolling them out in a production environment.
   - Reboot and enter zfsbootmenu
   - Select the boot environment and press Ctrl+S to show the snapshots.
   - Select the pre-upgrade snapshot and choose one of the following options. Either option will provide the ability to boot into the system as it was pre-upgrade.
   
     - Press Enter to create a "duplicate" boot environment. Zfsbootmenu will create a new boot environment that is entirely independent of the upgraded boot environment and its snapshots. The down sides of the duplicate option are that:
       - it requires sufficient disk space to create the duplicate; and
       - snapshots linked to the previous boot environment will not be duplicated.
       
     - Press Ctrl+X to "clone and promote". Zfsbootmenu will create a new boot environment that will have all the snapshot history up to the point the snapshot was created. The new boot environment will consume little additional space. The zfsbootmenu authors recommend the "clone and promote" option to rollback.
    
2. How do I delete a boot environment I no longer need?
   
   You can delete a boot environment you no longer need using "zfs destroy". You can do this by booting into a running system or from zfsbootmenu. Zfsbootmenu will list the root datasets that contain a linux kernel on its main menu. You can make a note of the dataset you want to delete from there or you can use "zfs list" from a command line.

   - Delete a boot environment from a running system
       - Use "zfs destroy" to delete the dataset that corresponds to the boot environment. For example, if you want to delete a root dataset called "ubuntu.2022.10.01" then you can enter the command "zfs destroy -r rpool/ROOT/ubuntu.2022.10.01".

   - Delete a boot environment from zfsbootmenu
     - From the main menu, select the boot environment you want to destroy. Press CTRL+W to re-import the pool as read/write, then CTRL+R to enter the recovery shell. You can then use "zfs destroy" as in the point above. Press CTRL+D to exit the shell and return to the menu when done.

3. Can I upgrade the system normally using do-release-upgrade?
   - Zfsbootmenu
   
     It is possible that upgrading ubuntu will cause a newer zfs version to be installed that is unsupported by zfsbootmenu. The system may not be able to boot if the zfs root pool is upgraded beyond what is supported by zfsbootmenu. Create a test system in a virtual machine first to duplicate your setup and test the upgrade process.
   - Pyznap
   
     Pyznap is not included as a package in the ubuntu repos at present. It may need to be re-compiled and re-installed. You can reference the install script for the relevant code to re-compile and re-install. 

4. How do I change the password on a natively encrypted zfs root pool?

   You can change the password of your encrypted root as follows. Change "rpool" to the name of your root pool.
      - Update root pool password file.

        `nano /etc/zfs/rpool.key`
      - Update root pool key.

        `zfs change-key -o keylocation=file:///etc/zfs/rpool.key -o keyformat=passphrase rpool`
      - Optional: If you have an encrypted data pool that unlocks at boot using the root pool password, then update its key too. Change "datapool" to the name of your data pool.

        `zfs change-key -o keylocation=file:///etc/zfs/rpool.key -o keyformat=passphrase datapool`
      - Update initramfs.

        `update-initramfs -u -k all`

## Discussion threads
Please use the discussions section. \
https://github.com/Sithuk/ubuntu-server-zfsbootmenu/discussions

For historical reference, the initial discussion thread can be found on reddit.
https://www.reddit.com/r/zfs/comments/mj4nfa/ubuntu_server_2104_native_encrypted_root_on_zfs/

## Credits
ahesford E39M5S62/zdykstra (https://github.com/zbm-dev/zfsbootmenu)

cythoning (https://github.com/yboetz/pyznap)

rlaager (https://openzfs.github.io/openzfs-docs/Getting%20Started/Ubuntu/Ubuntu%2022.04%20Root%20on%20ZFS.html)
