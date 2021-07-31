# Ubuntu server zfsbootmenu install script

This script creates an ubuntu server installation using the ZFS filesystem. The installation has integrated snapshot management. Snapshots can be rolled back remotely at boot over ssh. This is useful where there is no physical access to the machine.

Snapshots allow you to rollback your system to a previous state if there is a problem. The system automatically creates snapshots on a timer and also when the system is updated with apt.


## Usage
Boot the system with an Ubuntu live desktop iso (ZFS 2.0 support needed for native encryption, so use Ubuntu 21.04 or later). Start the terminal (Ctrl+Alt+T) and enter the following.
	git clone git@gitlab.com:Sithuk/ubuntu-server-zfsbootmenu.git ~/ubuntu-server-zfsbootmenu
    cd ~/ubuntu-server-zfsbootmenu
    chmod +x ubuntu_server_encrypted_root_zfs.sh
	
Edit the variables in the ubuntu_server_encrypted_root_zfs.sh file to your preferences.
	nano ubuntu_server_encrypted_root_zfs.sh
	
Run the first part of the script.
	./ubuntu_server_encrypted_root_zfs.sh initial
	
Reboot after the initial installation completes and login to the new install. Username is root, password is as set in the script variables. Then run the second part of the script.
	./ubuntu_server_encrypted_root_zfs.sh postreboot

	Additional guidance and notes can be found in the script.

## Reddit discussion thread:
	https://www.reddit.com/r/zfs/comments/mj4nfa/ubuntu_server_2104_native_encrypted_root_on_zfs/

## Credits
	rlaager (https://openzfs.github.io/openzfs-docs/Getting%20Started/Ubuntu/Ubuntu%2020.04%20Root%20on%20ZFS.html)
	ahesford E39M5S62/zdykstra (https://github.com/zbm-dev/zfsbootmenu)
	cythoning (https://github.com/yboetz/pyznap)
