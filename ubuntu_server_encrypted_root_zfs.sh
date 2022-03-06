#!/bin/bash
##Scripts installs ubuntu server on encrypted zfs with headless remote unlocking and snapshot rollback at boot.
##Script date: 2022-03-06

set -euo pipefail
set -x

##Usage: <script_filename> initial | postreboot | remoteaccess | datapool

##Script: https://gitlab.com/Sithuk/ubuntu-server-zfsbootmenu
##Discussion: https://www.reddit.com/r/zfs/comments/mj4nfa/ubuntu_server_2104_native_encrypted_root_on_zfs/?utm_source=share&utm_medium=web2x&context=3

##Script to be run in two parts.
##Part 1: Run with "initial" option from Ubuntu 21.04 live iso (desktop version) terminal.
##Part 2: Reboot into new install.
##Part 2: Run with "postreboot" option after first boot into new install (login as root. p/w as set in variable section below). 

##Remote access can be installed by either:
##  setting the remoteaccess variable to "yes" in the variables section below, or
##  running the script with the "remoteaccess" option after part 1 and part 2 are run.
##Connect as "root" on port 222 to the server's ip.
##It's better to leave the remoteaccess variable below as "no" and run the script with the "remoteaccess" option
##  as that will use the user's authorized_keys file. Setting the remoteaccess variable to "yes" will use root's authorized_keys.
##Login as "root" during remote access, even if using a user's authorized_keys file. No other users are available during remote access.
##The user's authorized_keys file will not be available until the user account is created in part 2 of the script.
##So remote login using root's authorized_keys file is the only option during the first reboot.

##A non-root drive can be setup as an encrypted data pool using the "datapool" option.
##The drive will be unlocked automatically after the root drive password is entered at boot.

##If running in a Virtualbox virtualmachine, setup tips below:
##1. Enable EFI.
##2. Set networking to bridged mode so VM gets its own IP. Fewer problems with ubuntu keyserver.
##3. Minimum drive size of 5GB.

##Rescuing using a Live CD
##zpool export -a #Export all pools.
##zpool import -N -R /mnt rpool #"rpool" should be the root pool name.
##zfs load-key -r -L prompt -a #-r Recursively loads the keys. -a Loads the keys for all encryption roots in all imported pools. -L is for a keylocation or to "prompt" user for an input.
##zfs mount -a #Mount all datasets.

##Variables:
ubuntuver="hirsute" #Ubuntu release to install. Only tested with hirsute (21.04).
user="testuser" #Username for new install.
PASSWORD="testuser" #Password for user in new install.
hostname="ubuntu" #Name to identify the new install on the network. An underscore is DNS non-compliant.
zfspassword="testtest" #Password for root pool and data pool. Minimum 8 characters.
locale="en_GB.UTF-8" #New install language setting.
timezone="Europe/London" #New install timezone setting.
zfs_rpool_ashift="12" #Drive setting for zfs pool. ashift=9 means 512B sectors (used by all ancient drives), ashift=12 means 4KiB sectors (used by most modern hard drives), and ashift=13 means 8KiB sectors (used by some modern SSDs).

RPOOL="rpool" #Root pool name.
topology_root="single" #single, mirror, raidz1, raidz2, or raidz3 topology on root pool.
raidz_disks_root="0" #Number of disks in raidz array for root pool. Not used with single or mirror topology.
EFI_boot_size="512" #EFI boot loader partition size in mebibytes (MiB).
swap_size="500" #Swap partition size in mebibytes (MiB). Size of swap will be larger than defined here with Raidz topologies.
openssh="yes" #"yes" to install open-ssh server in new install.
datapool="datapool" #Non-root drive data pool name.
topology_data="mirror" #single, mirror, raidz1, raidz2, or raidz3 topology on data pool.
raidz_disks_data="2" #Number of disks in raidz array for data pool. Not used with single or mirror topology.
datapoolmount="/mnt/$datapool" #Non-root drive data pool mount point in new install.
zfs_dpool_ashift="12" #See notes for rpool ashift. If ashift is set too low, a significant read/write penalty is incurred. Virtually no penalty if set higher.
zfs_compression="zstd" #lz4 is the zfs default; zstd may offer better compression at a cost of higher cpu usage.
mountpoint="/mnt/ub_server" #Mountpoint in live iso.
remoteaccess="no" #"yes" to enable remoteaccess during first boot. Recommend leaving as "no" and run script with "remoteaccess". See notes in section above.
timeout_rEFInd="5" #Timeout in seconds for rEFInd boot screen until default choice selected.
timeout_zbm_no_remote_access="15" #Timeout in seconds for zfsbootmenu when no remote access enabled.
timeout_zbm_remote_access="30" #Timeout in seconds for zfsbootmenu when remote access enabled.
quiet_boot="yes" #Set to "no" to show boot sequence.
ethprefix="e" #First letter of ethernet interface. Used to identify ethernet interface to setup networking in new install.
install_log="ubuntu_setup_zfs_root.log" #Installation log filename.
log_loc="/var/log" #Installation log location.
ipv6_apt_fix_live_iso="no" #Try setting to "yes" if apt-get is slow in the ubuntu live iso. Doesn't affect ipv6 functionality in the new install.

##Check for root priviliges
if [ "$(id -u)" -ne 0 ]; then
   echo "Please run as root."
   exit 1
fi

##Check for EFI boot environment
if [ -d /sys/firmware/efi ]; then
   echo "Boot environment check passed. Found EFI boot environment."
else
   echo "Boot environment check failed. EFI boot environment not found. Script requires EFI."
   exit 1
fi

##Check that number of disks meets minimum number for selected RAIDZ topology.
for pool in "root" "data" 
do
	topology_pool_pointer="topology_$pool"
	eval echo \$"${topology_pool_pointer}"
	eval topology_pool_pointer="\$${topology_pool_pointer}"
	case "$topology_pool_pointer" in
		single | mirror) true ;;
		
		raidz1)
			raidz_disks_pointer="raidz_disks_${pool}"
			eval echo \$"${raidz_disks_pointer}"
			eval raidz_disks_pointer=\$"${raidz_disks_pointer}"
			if [ "$raidz_disks_pointer" -lt 2 ]
			then
				echo "Raidz1 topology requires at least 2 disks. Check variable for number of disks or change the selected topology."
				exit 1
			else true
			fi
		;;

		raidz2)
			raidz_disks_pointer="raidz_disks_${pool}"
			eval echo \$"${raidz_disks_pointer}"
			eval raidz_disks_pointer=\$"${raidz_disks_pointer}"
			if [ "$raidz_disks_pointer" -lt 3 ]
			then
				echo "Raidz2 topology requires at least 3 disks. Check variable for number of disks or change the selected topology."
				exit 1
			else true
			fi
		;;

		raidz3)
			raidz_disks_pointer="raidz_disks_${pool}"
			eval echo \$"${raidz_disks_pointer}"
			eval raidz_disks_pointer=\$"${raidz_disks_pointer}"
			if [ "$raidz_disks_pointer" -lt 4 ]
			then
				echo "Raidz3 topology requires at least 4 disks. Check variable for number of disks or change the selected topology."
				exit 1
			else true
			fi
		;;

		*)
			echo "Pool topology not recognised. Check pool topology variable."
			exit 1
		;;
	esac
echo "RAIDZ topology check passed for $pool pool."
done	

##Functions
logFunc(){
	# Log everything we do
	exec > >(tee -a "$log_loc"/"$install_log") 2>&1
}

disclaimer(){
	echo "***WARNING*** This script could wipe out all your data, or worse! I am not responsible for your decisions. Carefully enter the ID of the disk YOU WANT TO DESTROY in the next step to ensure no data is accidentally lost. Press Enter to Continue or CTRL+C to abort."
	read -r _
}

getdiskID(){
	pool="$1"
	diskidnum="$2"
	total_discs="$3"
	##Get disk UUID
	ls -la /dev/disk/by-id
	echo "Enter Disk ID for disk $diskidnum of $total_discs on $pool pool (must match exactly):"
	read -r DISKID
	#DISKID=ata-VBOX_HARDDISK_VBXXXXXXXX-XXXXXXXX ##manual override
	##error check
	errchk="$(find /dev/disk/by-id -maxdepth 1 -mindepth 1 -name "$DISKID")"
	if [ -z "$errchk" ];
	then
		echo "Disk ID not found. Exiting."
		exit 1
	fi
		
	errchk="$(grep "$DISKID" /tmp/diskid_check_"${pool}".txt || true)"
	if [ -n "$errchk" ];
	then
		echo "Disk ID has already been entered. Exiting."
		exit 1
	fi
	
	printf "%s\n" "$DISKID" >> /tmp/diskid_check_"${pool}".txt
	
	echo "Disk ID set to ""$DISKID"""
}

getdiskID_pool(){
	pool="$1" #root or data
	##Create temp file to check for duplicated UUID entry.
	true > /tmp/diskid_check_"${pool}".txt
	
	topology_pool_pointer="topology_$pool"
	eval echo \$"${topology_pool_pointer}"
	eval topology_pool_pointer="\$${topology_pool_pointer}"
	case "$topology_pool_pointer" in
		single)
			echo "The $pool pool disk topology is a single disk."
			getdiskID "$pool" "1" "1"
		;;

		mirror)
			echo "The $pool pool disk topology is a two disk mirror."
			for diskidnum in "1" "2"
			do
				getdiskID "$pool" "$diskidnum" "2"
			done
		;;
		
		raidz*)
			topology_pool_pointer="topology_$pool"
			eval echo \$"${topology_pool_pointer}"
			eval topology_pool_pointer="\$${topology_pool_pointer}"
			
			raidz_disks_pointer="raidz_disks_${pool}"
			eval echo \$"${raidz_disks_pointer}"
			eval raidz_disks_pointer=\$"${raidz_disks_pointer}"
			
			echo "The $pool pool disk topology is $topology_pool_pointer with $raidz_disks_pointer disks."
			diskidnum="1"
			while [ "$diskidnum" -le "$raidz_disks_pointer" ];
			do
				getdiskID "$pool" "$diskidnum" "$raidz_disks_pointer"
				diskidnum=$(( diskidnum + 1 ))
			done
		;;

		*)
			echo "Pool topology not recognised. Check pool topology variable."
			exit 1
		;;

	esac

}

clear_partition_table(){
	pool="$1" #root or data
	while IFS= read -r diskidnum;
	do
		echo "Clearing partition table on disk ${diskidnum}."
		sgdisk --zap-all /dev/disk/by-id/"$diskidnum"
	done < /tmp/diskid_check_"${pool}".txt
}

identify_ubuntu_dataset_uuid(){
	rootzfs_full_name=0
	rootzfs_full_name="$(zfs list -o name | awk '/ROOT\/ubuntu/{print $1;exit}'|sed -e 's,^.*/,,')"
}

ipv6_apt_live_iso_fix(){
	##Try diabling ipv6 in the live iso if setting the preference to ipv4 doesn't work \
	## to resolve slow apt-get and slow debootstrap in the live Ubuntu iso.
	##https://askubuntu.com/questions/620317/apt-get-update-stuck-connecting-to-security-ubuntu-com
	
	prefer_ipv4(){
		sed -i 's,#precedence ::ffff:0:0/96  100,precedence ::ffff:0:0/96  100,' /etc/gai.conf
	}
	
	dis_ipv6(){
		cat >> /etc/sysctl.conf <<-EOF
			net.ipv6.conf.all.disable_ipv6 = 1
			#net.ipv6.conf.default.disable_ipv6 = 1
			#net.ipv6.conf.lo.disable_ipv6 = 1
		EOF
		tail -n 3 /etc/sysctl.conf
		sudo sysctl -p /etc/sysctl.conf
		sudo netplan apply
	}

	if [ "$ipv6_apt_fix_live_iso" = "yes" ]; then
		prefer_ipv4
		#dis_ipv6
	else
		true
	fi

}

debootstrap_part1_Func(){
	##use closest mirrors
	cp /etc/apt/sources.list /etc/apt/sources.list.bak
	sed -i 's,deb http://security,#deb http://security,' /etc/apt/sources.list ##Uncomment to resolve security pocket time out. Security packages are copied to the other pockets frequently, so should still be available for update. See https://wiki.ubuntu.com/SecurityTeam/FAQ
	sed -i \
		-e 's/http:\/\/archive/mirror:\/\/mirrors/' \
		-e 's/\/ubuntu\//\/mirrors.txt/' \
		-e '/mirrors/ s,main restricted,main restricted universe multiverse,' \
		/etc/apt/sources.list
	cat /etc/apt/sources.list
	
	trap 'printf "%s\n%s" "The script has experienced an error during the first apt update. That may have been caused by a queried server not responding in time. Try running the script again." "If the issue is the security server not responding, then comment out the security server in the /etc/apt/sources.list. Alternatively, you can uncomment the command that does this in the install script. This affects the temporary live iso only. Not the permanent installation."' ERR
	apt update
	trap - ERR	##Resets the trap to doing nothing when the script experiences an error. The script will still exit on error if "set -e" is set.
	
	ssh_Func(){
		##1.2 Setup SSH to allow remote access in live environment
		apt install --yes openssh-server
		service sshd start
		ip addr show scope global | grep inet
	}
	#ssh_Func
	
	
	DEBIAN_FRONTEND=noninteractive apt-get -yq install debootstrap software-properties-common gdisk zfs-initramfs
	if service --status-all | grep -Fq 'zfs-zed'; then
		systemctl stop zfs-zed
	fi

	##2 Disk formatting
	
	##2.1 Disk variable name (set prev)
	
	##2.2 Wipe disk 
	
	##Clear partition table
	clear_partition_table "root"
	sleep 2

	##Partition disk
	partitionsFunc(){
		##gdisk hex codes:
		##EF02 BIOS boot partitions
		##EF00 EFI system
		##BE00 Solaris boot
		##BF00 Solaris root
		##BF01 Solaris /usr & Mac Z
		##8200 Linux swap
		##8300 Linux file system
		##FD00 Linux RAID

		case "$topology_root" in
			single)
				swap_hex_code="8200"
			;;

			mirror)
				swap_hex_code="8200"
			;;
			
			raidz*)
				swap_hex_code="FD00"
			;;

			*)
				echo ""
				exit 1
			;;
		esac
		
		while IFS= read -r diskidnum;
		do
			echo "Creating partitions on disk ${diskidnum}."
			##2.3 create bootloader partition
			sgdisk -n1:1M:+"$EFI_boot_size"M -t1:EF00 /dev/disk/by-id/"${diskidnum}"
		
			##2.4 create swap partition 
			##bug with swap on zfs zvol so use swap on partition:
			##https://github.com/zfsonlinux/zfs/issues/7734
			##hibernate needs swap at least same size as RAM
			##hibernate only works with unencrypted installs
			sgdisk -n2:0:+"$swap_size"M -t2:"$swap_hex_code" /dev/disk/by-id/"${diskidnum}"
		
			##2.6 Create root pool partition
			##Unencrypted or ZFS native encryption:
			sgdisk     -n3:0:0      -t3:BF00 /dev/disk/by-id/"${diskidnum}"
		
		done < /tmp/diskid_check_"${pool}".txt
		sleep 2
	}
	partitionsFunc
}

debootstrap_createzfspools_Func(){

	zpool_encrypted_Func(){
		##2.8b create root pool encrypted
		echo Password must be min 8 characters.
		
		zpool_create_temp="/tmp/${RPOOL}_creation.sh"
		cat > "$zpool_create_temp" <<-EOF
			zpool create -f \
				-o ashift=$zfs_rpool_ashift \
				-o autotrim=on \
				-O acltype=posixacl \
				-O canmount=off \
				-O compression=$zfs_compression \
				-O dnodesize=auto \
				-O normalization=formD \
				-O relatime=on \
				-O xattr=sa \
				-O encryption=aes-256-gcm -O keylocation=prompt -O keyformat=passphrase \
				-O mountpoint=/ -R "$mountpoint" \\
		EOF

		add_zpool_disks(){
			while IFS= read -r diskidnum;
			do
				echo "/dev/disk/by-id/${diskidnum}-part3 \\" >> "$zpool_create_temp"
			done < /tmp/diskid_check_root.txt
		
			sed -i '$s,\\,,' "$zpool_create_temp"
		}


		case "$topology_root" in
			single)
				echo "$RPOOL \\" >> "$zpool_create_temp"	
				add_zpool_disks
			;;

			mirror)
				echo "$RPOOL mirror \\" >> "$zpool_create_temp"
				add_zpool_disks
			;;
			
			raidz1)
				echo "$RPOOL raidz1 \\" >> "$zpool_create_temp"
				add_zpool_disks	
			;;

			raidz2)
				echo "$RPOOL raidz2 \\" >> "$zpool_create_temp"
				add_zpool_disks	
			;;

			raidz3)
				echo "$RPOOL raidz3 \\" >> "$zpool_create_temp"
				add_zpool_disks	
			;;

			*)
				echo "Pool topology not recognised. Check pool topology variable."
				exit 1
			;;

		esac
		
	}
	zpool_encrypted_Func
	echo -e "$zfspassword" | sh "$zpool_create_temp" 
	
	##3. System installation
	mountpointsFunc(){

		##zfsbootmenu setup for no separate boot pool
		##https://github.com/zbm-dev/zfsbootmenu/wiki/Debian-Buster-installation-with-ESP-on-the-zpool-disk
		
		sleep 2
		##3.1 Create filesystem datasets to act as containers
		zfs create -o canmount=off -o mountpoint=none "$RPOOL"/ROOT 
					
		##3.2 Create root filesystem dataset
		rootzfs_full_name="ubuntu.$(date +%Y.%m.%d)"
		zfs create -o canmount=noauto -o mountpoint=/ "$RPOOL"/ROOT/"$rootzfs_full_name" ##zfsbootmenu debian guide
		##assigns canmount=noauto on any file systems with mountpoint=/ (that is, on any additional boot environments you create).
		##With ZFS, it is not normally necessary to use a mount command (either mount or zfs mount). 
		##This situation is an exception because of canmount=noauto.
		zfs mount "$RPOOL"/ROOT/"$rootzfs_full_name"
		zpool set bootfs="$RPOOL"/ROOT/"$rootzfs_full_name" "$RPOOL"
		
		
		##3.3 create datasets
		##Aim is to separate OS from user data.
		##Allows root filesystem to be rolled back without rolling back user data such as logs.
		##https://didrocks.fr/2020/06/16/zfs-focus-on-ubuntu-20.04-lts-zsys-dataset-layout/
		##https://openzfs.github.io/openzfs-docs/Getting%20Started/Debian/Debian%20Buster%20Root%20on%20ZFS.html#step-3-system-installation
		##"-o canmount=off" is for a system directory that should rollback with the rest of the system.
		
		zfs create	"$RPOOL"/srv 						##server webserver content
		zfs create -o canmount=off	"$RPOOL"/usr
		zfs create	"$RPOOL"/usr/local					##locally compiled software
		zfs create -o canmount=off "$RPOOL"/var 
		zfs create -o canmount=off "$RPOOL"/var/lib
		#zfs create 	"$RPOOL"/var/lib/AccountsService	##If this system will use GNOME desktop
		zfs create	"$RPOOL"/var/games					##game files
		zfs create	"$RPOOL"/var/log 					##log files
		zfs create	"$RPOOL"/var/mail 					##local mails
		zfs create	"$RPOOL"/var/snap					##snaps handle revisions themselves
		zfs create	"$RPOOL"/var/spool					##printing tasks
		zfs create	"$RPOOL"/var/www					##server webserver content
		
		
		##USERDATA datasets
		zfs create "$RPOOL"/home
		zfs create -o mountpoint=/root "$RPOOL"/home/root
		chmod 700 "$mountpoint"/root

		
		##optional
		##exclude from snapshots
		zfs create -o com.sun:auto-snapshot=false "$RPOOL"/var/cache
		zfs create -o com.sun:auto-snapshot=false "$RPOOL"/var/tmp
		chmod 1777 "$mountpoint"/var/tmp
		zfs create -o com.sun:auto-snapshot=false "$RPOOL"/var/lib/docker ##Docker manages its own datasets & snapshots

	
		##Mount a tempfs at /run
		mkdir "$mountpoint"/run
		mount -t tmpfs tmpfs "$mountpoint"/run

	}
	mountpointsFunc
}

debootstrap_installminsys_Func(){
	##3.4 install minimum system
	##drivesizecheck
	FREE="$(df -k --output=avail "$mountpoint" | tail -n1)"
	if [ "$FREE" -lt 5242880 ]; then               # 15G = 15728640 = 15*1024*1024k
		 echo "Less than 5 GBs free!"
		 exit 1
	fi
	
	debootstrap "$ubuntuver" "$mountpoint"
}

remote_zbm_access_Func(){
	modulesetup="/usr/lib/dracut/modules.d/60crypt-ssh/module-setup.sh"
	cat <<-EOH >/tmp/remote_zbm_access.sh
		#!/bin/sh
		##https://github.com/zbm-dev/zfsbootmenu/wiki/Remote-Access-to-ZBM
		apt install -y dracut-network dropbear
		
		git -C /tmp clone 'https://github.com/dracut-crypt-ssh/dracut-crypt-ssh.git'
		mkdir /usr/lib/dracut/modules.d/60crypt-ssh
		cp /tmp/dracut-crypt-ssh/modules/60crypt-ssh/* /usr/lib/dracut/modules.d/60crypt-ssh/
		rm /usr/lib/dracut/modules.d/60crypt-ssh/Makefile
		
		##comment out references to /helper/ folder from module-setup.sh
		sed -i \
			-e 's,  inst "\$moddir"/helper/console_auth /bin/console_auth,  #inst "\$moddir"/helper/console_auth /bin/console_auth,' \
			-e 's,  inst "\$moddir"/helper/console_peek.sh /bin/console_peek,  #inst "\$moddir"/helper/console_peek.sh /bin/console_peek,' \
			-e 's,  inst "\$moddir"/helper/unlock /bin/unlock,  #inst "\$moddir"/helper/unlock /bin/unlock,' \
			-e 's,  inst "\$moddir"/helper/unlock-reap-success.sh /sbin/unlock-reap-success,  #inst "\$moddir"/helper/unlock-reap-success.sh /sbin/unlock-reap-success,' \
			"$modulesetup"
		
		##create host keys
		mkdir -p /etc/dropbear
		ssh-keygen -t rsa -m PEM -f /etc/dropbear/ssh_host_rsa_key -N ""
		ssh-keygen -t ecdsa -m PEM -f /etc/dropbear/ssh_host_ecdsa_key -N ""
		
		mkdir -p /etc/cmdline.d
		echo "ip=dhcp rd.neednet=1" > /etc/cmdline.d/dracut-network.conf ##Replace "dhcp" with specific IP if needed.
		
		##add remote session welcome message
		cat <<-EOF >/etc/zfsbootmenu/dracut.conf.d/banner.txt
			Welcome to the ZFSBootMenu initramfs shell. Enter "zbm" to start ZFSBootMenu.
		EOF
		chmod 755 /etc/zfsbootmenu/dracut.conf.d/banner.txt
		
		sed -i 's,  /sbin/dropbear -s -j -k -p \${dropbear_port} -P /tmp/dropbear.pid,  /sbin/dropbear -s -j -k -p \${dropbear_port} -P /tmp/dropbear.pid -b /etc/banner.txt,' /usr/lib/dracut/modules.d/60crypt-ssh/dropbear-start.sh
		
		##Copy files into initramfs
		sed -i '$ s,^},,' "$modulesetup"
		echo "  ##Copy dropbear welcome message" | tee -a "$modulesetup"
		echo "  inst /etc/zfsbootmenu/dracut.conf.d/banner.txt /etc/banner.txt" | tee -a "$modulesetup"
		echo "}" | tee -a "$modulesetup"
		
		cat <<-EOF >/etc/zfsbootmenu/dracut.conf.d/dropbear.conf
			## Enable dropbear ssh server and pull in network configuration args
			##The default configuration will start dropbear on TCP port 222.
			##This can be overridden with the dropbear_port configuration option.
			##You do not want the server listening on the default port 22.
			##Clients that expect to find your normal host keys when connecting to an SSH server on port 22 will \
			##refuse to connect when they find different keys provided by dropbear.
			add_dracutmodules+=" crypt-ssh "
			install_optional_items+=" /etc/cmdline.d/dracut-network.conf "
			## Copy system keys for consistent access
			dropbear_rsa_key=/etc/dropbear/ssh_host_rsa_key
			dropbear_ecdsa_key=/etc/dropbear/ssh_host_ecdsa_key
			##Access by authorized keys only. No password.
			##By default, the list of authorized keys is taken from /root/.ssh/authorized_keys on the host.
			##Remember to "generate-zbm" after adding the remote user key to the authorized_keys file. 
			##The last line is optional and assumes the specified user provides an authorized_keys file \
			##that will determine remote access to the ZFSBootMenu image.
			##Note that login to dropbear is "root" regardless of which authorized_keys is used.
			#dropbear_acl=/home/${user}/.ssh/authorized_keys
		EOF
		
		##Increase ZFSBootMenu timer to allow for remote connection
		sed -i 's,zbm.timeout=$timeout_zbm_no_remote_access,zbm.timeout=$timeout_zbm_remote_access,' /boot/efi/EFI/ubuntu/refind_linux.conf
		
		systemctl stop dropbear
		systemctl disable dropbear
		
		generate-zbm --debug
	EOH
	
	case "$1" in
	chroot)
		cp /tmp/remote_zbm_access.sh "$mountpoint"/tmp
		chroot "$mountpoint" /bin/bash -x /tmp/remote_zbm_access.sh
	;;
	base)
		/bin/bash /tmp/remote_zbm_access.sh
	;;
	*)
		exit 1
	;;
	esac
	
}


systemsetupFunc_part1(){

	##4. System configuration
	##4.1 configure hostname
	echo "$hostname" > "$mountpoint"/etc/hostname
	echo "127.0.1.1       $hostname" >> "$mountpoint"/etc/hosts
	
	##4.2 configure network interface
	
	##get ethernet interface
	ethernetinterface="$(basename "$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${ethprefix}*")")"
	echo "$ethernetinterface"
		
	##troubleshoot: sudo netplan --debug generate
	cat > "$mountpoint"/etc/netplan/01-"$ethernetinterface".yaml <<-EOF
		network:
		  version: 2
		  ethernets:
		    $ethernetinterface:
		      dhcp4: yes
	EOF
	
	
	##4.4 bind virtual filesystems from LiveCD to new system
	mount --rbind /dev  "$mountpoint"/dev
	mount --rbind /proc "$mountpoint"/proc
	mount --rbind /sys  "$mountpoint"/sys 

	
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##4.3 configure package sources
		cp /etc/apt/sources.list /etc/apt/sources.bak
		cat > /etc/apt/sources.list <<-EOLIST
			deb http://archive.ubuntu.com/ubuntu $ubuntuver main universe restricted multiverse
			#deb-src http://archive.ubuntu.com/ubuntu $ubuntuver main universe restricted multiverse
			
			deb http://archive.ubuntu.com/ubuntu $ubuntuver-updates main universe restricted multiverse
			#deb-src http://archive.ubuntu.com/ubuntu $ubuntuver-updates main universe restricted multiverse
			
			deb http://archive.ubuntu.com/ubuntu $ubuntuver-backports main universe restricted multiverse
			#deb-src http://archive.ubuntu.com/ubuntu $ubuntuver-backports main universe restricted multiverse
			
			deb http://security.ubuntu.com/ubuntu $ubuntuver-security main universe restricted multiverse
			#deb-src http://security.ubuntu.com/ubuntu $ubuntuver-security main universe restricted multiverse
		EOLIST

		##4.5 configure basic system
		apt update
		
		#dpkg-reconfigure locales
		locale-gen en_US.UTF-8 $locale
		echo 'LANG="$locale"' > /etc/default/locale
		
		##set timezone
		ln -fs /usr/share/zoneinfo/"$timezone" /etc/localtime
		dpkg-reconfigure -f noninteractive tzdata
		
	EOCHROOT
}

systemsetupFunc_part2(){
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##install zfs
		apt update

		apt install --no-install-recommends -y linux-headers-generic linux-image-generic ##need to use no-install-recommends otherwise installs grub
		
		apt install --yes --no-install-recommends dkms wget nano
		
		apt install -yq software-properties-common
		
		DEBIAN_FRONTEND=noninteractive apt-get -yq install zfs-dkms
		apt install --yes zfsutils-linux zfs-zed

		apt install --yes zfs-initramfs

		
	EOCHROOT
}

systemsetupFunc_part3(){
	
	identify_ubuntu_dataset_uuid

	mkdosfs -F 32 -s 1 -n EFI /dev/disk/by-id/"$DISKID"-part1 
	sleep 2
	blkid_part1=""
	blkid_part1="$(blkid -s UUID -o value /dev/disk/by-id/"${DISKID}"-part1)"
	echo "$blkid_part1"
	
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##4.7 Create the EFI filesystem

		##create FAT32 filesystem in EFI partition
		apt install --yes dosfstools
		
		mkdir -p /boot/efi
		
		##fstab entries
		
		echo /dev/disk/by-uuid/"$blkid_part1" \
			/boot/efi vfat \
			defaults \
			0 0 >> /etc/fstab
		
		##mount from fstab entry
		mount /boot/efi
		##If mount fails error code is 0. Script won't fail. Need the following check.
		##Could use "mountpoint" command but not all distros have it. 
		if grep /boot/efi /proc/mounts; then
			echo "/boot/efi mounted."
		else
			echo "/boot/efi not mounted."
			exit 1
		fi
	EOCHROOT


	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		
		DEBIAN_FRONTEND=noninteractive apt-get -yq install refind kexec-tools
		apt install --yes dpkg-dev git systemd-sysv
		
		##Adjust timer on initial rEFInd screen
		sed -i 's,^timeout .*,timeout $timeout_rEFInd,' /boot/efi/EFI/refind/refind.conf

		echo REMAKE_INITRD=yes > /etc/dkms/zfs.conf
		sed -i 's,LOAD_KEXEC=false,LOAD_KEXEC=true,' /etc/default/kexec

		apt install -y dracut-core ##core dracut components only for zbm initramfs 

	EOCHROOT

}

systemsetupFunc_part4(){
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		zfsbootmenuinstall(){

			##convert rpool to use keyfile
			echo $zfspassword > /etc/zfs/$RPOOL.key ##This file will live inside your initramfs stored ON the ZFS boot environment.
			chmod 600 /etc/zfs/$RPOOL.key
			zfs change-key -o keylocation=file:///etc/zfs/$RPOOL.key -o keyformat=passphrase $RPOOL
							
			if [ "$quiet_boot" = "yes" ]; then
				zfs set org.zfsbootmenu:commandline="spl_hostid=\$( hostid ) ro quiet" "$RPOOL"/ROOT
			else
				zfs set org.zfsbootmenu:commandline="spl_hostid=\$( hostid ) ro" "$RPOOL"/ROOT
			fi

			##install zfsbootmenu
			compile_zbm_git(){
				apt install -y git make
				cd /tmp
				git clone 'https://github.com/zbm-dev/zfsbootmenu.git'
				cd zfsbootmenu
				make install
			}
			compile_zbm_git
				
			##configure zfsbootmenu
			config_zbm(){
				cat <<-EOF > /etc/zfsbootmenu/config.yaml
					Global:
					  ManageImages: true
					  BootMountPoint: /boot/efi
					  DracutConfDir: /etc/zfsbootmenu/dracut.conf.d
					Components:
					  ImageDir: /boot/efi/EFI/ubuntu
					  Versions: false
					  Enabled: true
					  syslinux:
					    Config: /boot/syslinux/syslinux.cfg
					    Enabled: false
					EFI:
					  ImageDir: /boot/efi/EFI/ubuntu
					  Versions: false
					  Enabled: false
					Kernel:
					  CommandLine: ro quiet loglevel=0
				EOF
			
                		if [ "$quiet_boot" = "no" ]; then
                    			sed -i 's,ro quiet,ro,' /etc/zfsbootmenu/config.yaml
                		fi

				##Omit systemd dracut modules to prevent ZBM boot breaking
				cat <<-EOF >> /etc/zfsbootmenu/dracut.conf.d/zfsbootmenu.conf
					omit_dracutmodules+=" systemd systemd-initrd dracut-systemd "
				EOF
			
				##Install zfsbootmenu dependencies
				apt install --yes libconfig-inifiles-perl libsort-versions-perl libboolean-perl fzf mbuffer
				cpan 'YAML::PP'

				update-initramfs -k all -c
				
				##Generate ZFSBootMenu
				generate-zbm
				
				##Update refind_linux.conf
				##zfsbootmenu command-line parameters:
				##https://github.com/zbm-dev/zfsbootmenu/blob/master/pod/zfsbootmenu.7.pod
				cat <<-EOF > /boot/efi/EFI/ubuntu/refind_linux.conf
					"Boot default"  "zfsbootmenu:POOL=$RPOOL zbm.import_policy=hostid zbm.set_hostid zbm.timeout=$timeout_zbm_no_remote_access ro quiet loglevel=0"
					"Boot to menu"  "zfsbootmenu:POOL=$RPOOL zbm.import_policy=hostid zbm.set_hostid zbm.show ro quiet loglevel=0"
				EOF
				
				if [ "$quiet_boot" = "no" ]; then
                    			sed -i 's,ro quiet,ro,' /boot/efi/EFI/ubuntu/refind_linux.conf
                		fi

			}
			config_zbm	
		}
		zfsbootmenuinstall

	EOCHROOT
	
	if [ "$remoteaccess" = "yes" ];
	then
		remote_zbm_access_Func "chroot"
	else true
	fi
	
}

systemsetupFunc_part5(){
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##4.11 set root password
		echo -e "root:$PASSWORD" | chpasswd
	EOCHROOT
	
	##4.12 configure swap
	multi_disc_swap_loc="/tmp/multi_disc_swap.sh"
	
	multi_disc_swap_Func(){
		mdadm_level="$1" ##ZFS raidz = MDADM raid5, raidz2 = raid6. MDADM does not have raid7, so no raidz3 3 disk parity equivalent.
		mdadm_devices="$2" ##Number of disks.
	
		cat > "$multi_disc_swap_loc" <<-EOF
			##Swap setup for mirror or raidz topology.
			apt install --yes cryptsetup mdadm

			##Set MDADM level and number of disks.
			mdadm --create /dev/md0 --metadata=1.2 \
			--level="$mdadm_level" \
			--raid-devices="$mdadm_devices" \\
		EOF
	
		##Add swap disks.
		while IFS= read -r diskidnum;
		do
			echo "/dev/disk/by-id/${diskidnum}-part2 \\" >> "$multi_disc_swap_loc"
		done < /tmp/diskid_check_root.txt
		sed -i '$s,\\,,' "$zpool_create_temp" ##Remove escape characters needed for last line of EOF code block.
	
		##Update fstab and cryptsetup.
		cat >> "$multi_disc_swap_loc" <<-EOF
			##"plain" required in crypttab to avoid message at boot: "From cryptsetup: couldn't determine device type, assuming default (plain)."
			echo swap /dev/md0 /dev/urandom \
				  plain,swap,cipher=aes-xts-plain64:sha256,size=512 >> /etc/crypttab
			echo /dev/mapper/swap none swap defaults 0 0 >> /etc/fstab
		EOF
		
		##Check MDADM status.
		cat >> "$multi_disc_swap_loc" <<-EOF
			cat /proc/mdstat
			mdadm --detail /dev/md0
		EOF
		
		##Copy MDADM setup file into chroot and run. 
		cp "$multi_disc_swap_loc" "$mountpoint"/tmp/
		chroot "$mountpoint" /bin/bash -x "$multi_disc_swap_loc"
	}
	
	case "$topology_root" in
		single)
			chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
			##Single disk install
			apt install --yes cryptsetup
			##"plain" required in crypttab to avoid message at boot: "From cryptsetup: couldn't determine device type, assuming default (plain)."
			echo swap /dev/disk/by-id/"$DISKID"-part2 /dev/urandom \
				plain,swap,cipher=aes-xts-plain64:sha256,size=512 >> /etc/crypttab
			echo /dev/mapper/swap none swap defaults 0 0 >> /etc/fstab
			EOCHROOT
		;;

		mirror)
			##mdadm --level=mirror is the same as --level=1.
			multi_disc_swap_Func "mirror" "2"
		;;

		raidz1)
			multi_disc_swap_Func "5" "$raidz_disks_root"
		;;

		raidz2)
			multi_disc_swap_Func "6" "$raidz_disks_root"
		;;

		raidz3)
			##mdadm has no equivalent raid7 to raidz3. Use raid6.
			multi_disc_swap_Func "6" "$raidz_disks_root"
		;;

		*)
			echo "Pool topology not recognised. Check pool topology variable."
			exit 1
		;;

	esac
	
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##4.13 mount a tmpfs to /tmp
		cp /usr/share/systemd/tmp.mount /etc/systemd/system/
		systemctl enable tmp.mount

		##4.14 Setup system groups
		addgroup --system lpadmin
		addgroup --system lxd
		addgroup --system sambashare

	EOCHROOT
	
	chroot "$mountpoint" /bin/bash -x <<-"EOCHROOT"

		##5.2 refresh initrd files
		
		ls /usr/lib/modules
		
		update-initramfs -c -k all
		
	EOCHROOT
	
}

systemsetupFunc_part6(){
	
	identify_ubuntu_dataset_uuid

	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##5.8 Fix filesystem mount ordering
		

		
		fixfsmountorderFunc(){
			mkdir -p /etc/zfs/zfs-list.cache
			
			
			touch /etc/zfs/zfs-list.cache/$RPOOL
			ln -s /usr/lib/zfs-linux/zed.d/history_event-zfs-list-cacher.sh /etc/zfs/zed.d
			zed -F &
			sleep 2
			
			##Verify that zed updated the cache by making sure this is not empty:
			##If it is empty, force a cache update and check again:
			##Note can take a while. c.30 seconds for loop to succeed.
			cat /etc/zfs/zfs-list.cache/$RPOOL
			while [ ! -s /etc/zfs/zfs-list.cache/$RPOOL ]
			do
				zfs set canmount=noauto $RPOOL/ROOT/${rootzfs_full_name}
				sleep 1
			done
			cat /etc/zfs/zfs-list.cache/$RPOOL	
			
			
			

			##Stop zed:
			pkill -9 "zed*"

			##Fix the paths to eliminate $mountpoint:
			sed -Ei "s|$mountpoint/?|/|" /etc/zfs/zfs-list.cache/$RPOOL
			cat /etc/zfs/zfs-list.cache/$RPOOL

		}
		fixfsmountorderFunc
	EOCHROOT
	
}

systemsetupFunc_part7(){
	
	identify_ubuntu_dataset_uuid
		
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		
		##install samba mount access
		apt install -yq cifs-utils
		
		##install openssh-server
		if [ "$openssh" = "yes" ];
		then
			apt install -y openssh-server
		fi

		##6.2 exit chroot
		echo 'Exiting chroot.'
	
	EOCHROOT

	##Copy script into new installation
	cp "$(readlink -f "$0")" "$mountpoint"/root/
	if [ -f "$mountpoint"/root/"$(basename "$0")" ];
	then
		echo "Install script copied to /root/ in new installation."
	else
		echo "Error copying install script to new installation."
	fi
	
}

usersetup(){
	##6.6 create user account and setup groups
	zfs create -o mountpoint=/home/"$user" "$RPOOL"/home/${user}

	##gecos parameter disabled asking for finger info
	adduser --disabled-password --gecos "" "$user"
	cp -a /etc/skel/. /home/"$user"
	chown -R "$user":"$user" /home/"$user"
	usermod -a -G adm,cdrom,dip,lpadmin,lxd,plugdev,sambashare,sudo "$user"
	echo -e "$user:$PASSWORD" | chpasswd
}

distroinstall(){
	##7.1 Upgrade the minimal system
	#if [ ! -e /var/lib/dpkg/status ]
	#then touch /var/lib/dpkg/status
	#fi
	apt update 
	
	DEBIAN_FRONTEND=noninteractive apt dist-upgrade --yes
	##7.2a Install command-line environment only
	
	#rm -f /etc/resolv.conf ##Gives an error during ubuntu-server install. "Same file as /run/systemd/resolve/stub-resolv.conf". https://bugs.launchpad.net/ubuntu/+source/systemd/+bug/1774632
	#ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
	
	apt install --yes ubuntu-server
	
	##7.2b Install a full GUI environment
	#apt install --yes ubuntu-desktop
	
	##additional programs
	apt install --yes man-db tldr locate
}

logcompress(){
	##7.3 Disable log compression
	for file in /etc/logrotate.d/* ; do
		if grep -Eq "(^|[^#y])compress" "$file" ; then
			sed -i -r "s/(^|[^#y])(compress)/\1#\2/" "$file"
		fi
	done
}

pyznapinstall(){
	##snapshot management
	snapshotmanagement(){
		##https://github.com/yboetz/pyznap
		apt install -y python3-pip
		pip3 --version
		##https://docs.python-guide.org/dev/virtualenvs/
		pip3 install virtualenv
		virtualenv --version
		pip3 install virtualenvwrapper
		mkdir /root/pyznap
		cd /root/pyznap
		virtualenv venv
		source venv/bin/activate ##enter virtual env
		pip install pyznap
		deactivate ##exit virtual env
		ln -s /root/pyznap/venv/bin/pyznap /usr/local/bin/pyznap
		/root/pyznap/venv/bin/pyznap setup ##config file created /etc/pyznap/pyznap.conf
		chown root:root -R /etc/pyznap/
		##update config
		cat >> /etc/pyznap/pyznap.conf <<-EOF
			[$RPOOL/ROOT]
			frequent = 4                    
			hourly = 24
			daily = 7
			weekly = 4
			monthly = 6
			yearly = 1
			snap = yes
			clean = yes
		EOF
		
		cat > /etc/cron.d/pyznap <<-EOF
			SHELL=/bin/sh
			PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
			*/15 * * * *   root    /root/pyznap/venv/bin/pyznap snap >> /var/log/pyznap.log 2>&1
		EOF

		##integrate with apt
		cat > /etc/apt/apt.conf.d/80-zfs-snapshot <<-EOF
			DPkg::Pre-Invoke {"if [ -x /usr/local/bin/pyznap ]; then /usr/local/bin/pyznap snap; fi"};
		EOF
	
		pyznap snap ##Take ZFS snapshots and perform cleanup as per config file.
	}
	snapshotmanagement
}

setupremoteaccess(){
	if [ -f /etc/zfsbootmenu/dracut.conf.d/dropbear.conf ];
	then echo "Remote access already appears to be installed owing to the presence of /etc/zfsbootmenu/dracut.conf.d/dropbear.conf. Install cancelled."
	else 
		disclaimer
		remote_zbm_access_Func "base"
		sed -i 's,#dropbear_acl,dropbear_acl,' /etc/zfsbootmenu/dracut.conf.d/dropbear.conf
		mkdir -p /home/"$user"/.ssh
		touch /home/"$user"/.ssh/authorized_keys
		chmod 644 /home/"$user"/.ssh/authorized_keys
		chown "$user":"$user" /home/"$user"/.ssh/authorized_keys
		hostname -I
		echo "Remote access installed. Connect as root on port 222."
		echo "Your SSH public key must be placed in \"/home/$user/.ssh/authorized_keys\" prior to reboot or remote access will not work."
		echo "Run \"generate-zbm\" after copying across the remote user's public ssh key into the authorized_keys file."
	fi

}

createdatapool(){
	disclaimer
		
	##Check on whether data pool already exists
	if [ "$(zpool status "$datapool")" ];
	then
		echo "Warning: $datapool already exists. Are you use you want to wipe the drive and destroy $datapool? Press Enter to Continue or CTRL+C to abort."
		read -r _
	else true
	fi
	
	##Get datapool disk UUID
	echo "Enter diskID for non-root drive to create data pool on."
	getdiskID_pool "data"
	
	##Clear partition table
	clear_partition_table "data"
	sleep 2
	
	##create pool mount point
	if [ -d "$datapoolmount" ]; then
		echo "Data pool mount point exists."
	else
		mkdir -p "$datapoolmount"
		chown "$user":"$user" "$datapoolmount"
		echo "Data pool mount point created."
	fi
		
	##automount with zfs-mount-generator
	touch /etc/zfs/zfs-list.cache/"$datapool"

	##Set data pool key to use rpool key for single unlock at boot. So data pool uses the same password as the root pool.
	datapool_keyloc="/etc/zfs/$RPOOL.key"

	##Create data pool
	create_dpool_Func(){
		echo "$datapoolmount"
		
		zpool_create_temp="/tmp/${datapool}_creation.sh"
		cat > "$zpool_create_temp" <<-EOF
			zpool create \
				-o ashift="$zfs_dpool_ashift" \
				-O acltype=posixacl \
				-O compression="$zfs_compression" \
				-O normalization=formD \
				-O relatime=on \
				-O dnodesize=auto \
				-O xattr=sa \
				-O encryption=aes-256-gcm \
				-O keylocation=file://"$datapool_keyloc" \
				-O keyformat=passphrase \
				-O mountpoint="$datapoolmount" \\
		EOF

		add_zpool_disks(){
			while IFS= read -r diskidnum;
			do
				echo "/dev/disk/by-id/${diskidnum} \\" >> "$zpool_create_temp"
			done < /tmp/diskid_check_data.txt
		
			sed -i '$s,\\,,' "$zpool_create_temp"
		}


		case "$topology_root" in
			single)
				echo "$datapool \\" >> "$zpool_create_temp"	
				add_zpool_disks
			;;

			mirror)
				echo "$datapool mirror \\" >> "$zpool_create_temp"
				add_zpool_disks
			;;
			
			raidz1)
				echo "$datapool raidz1 \\" >> "$zpool_create_temp"
				add_zpool_disks	
			;;

			raidz2)
				echo "$datapool raidz2 \\" >> "$zpool_create_temp"
				add_zpool_disks	
			;;

			raidz3)
				echo "$datapool raidz3 \\" >> "$zpool_create_temp"
				add_zpool_disks	
			;;

			*)
				echo "Pool topology not recognised. Check pool topology variable."
				exit 1
			;;

		esac
	
	}
	create_dpool_Func
	sh "$zpool_create_temp" 
	
	##Verify that zed updated the cache by making sure the cache file is not empty.
	cat /etc/zfs/zfs-list.cache/"$datapool"
	##If it is empty, force a cache update and check again.
	##Note can take a while. c.30 seconds for loop to succeed.
	while [ ! -s /etc/zfs/zfs-list.cache/"$datapool" ]
	do
		##reset any pool property to update cache files
		zfs set canmount=on "$datapool"
		sleep 1
	done
	cat /etc/zfs/zfs-list.cache/"$datapool"	
	
	##Create link to datapool mount point in user home directory.
	ln -s "$datapoolmount" "/home/$user/"
	chown -R "$user":"$user" {"$datapoolmount","/home/$user/$datapool"}
	
	zpool status
	zfs list
	
}


##--------
logFunc
date
resettime(){
	##Manual reset time to correct out of date virtualbox clock
	timedatectl
	timedatectl set-ntp off
	sleep 1
	timedatectl set-time "2021-01-01 00:00:00"
	timedatectl
}
#resettime

initialinstall(){
	disclaimer
	getdiskID_pool "root"
	ipv6_apt_live_iso_fix #Only if ipv6_apt_fix_live_iso variable is set to "yes".
	debootstrap_part1_Func
	debootstrap_createzfspools_Func
	debootstrap_installminsys_Func
	systemsetupFunc_part1 #Basic system configuration.
	systemsetupFunc_part2 #Install zfs.
	systemsetupFunc_part3 #Format EFI partition. 
	systemsetupFunc_part4 #Install zfsbootmenu.
	systemsetupFunc_part5 #Config swap, tmpfs, rootpass.
	systemsetupFunc_part6 #ZFS file system mount ordering.
	systemsetupFunc_part7 #Samba.
	
	logcopy(){
		##Copy install log into new installation.
		if [ -d "$mountpoint" ]; then
			cp "$log_loc"/"$install_log" "$mountpoint""$log_loc"
		else 
			echo "No mountpoint dir present. Install log not copied."
		fi
	}
	logcopy
	
	echo "Reboot."
	echo "Post reboot login as root and run script with postreboot function enabled."
	echo "Script should be in the root login dir following reboot (/root/)"
	echo "First login is root:${PASSWORD-}"
}


postreboot(){
	disclaimer
	usersetup #Create user account and setup groups.
	distroinstall #Upgrade the minimal system.
	logcompress #Disable log compression.
	dpkg-reconfigure keyboard-configuration && setupcon #Configure keyboard and console.
	pyznapinstall #Snapshot management.
	
	echo "Install complete."
}

case "${1-default}" in
	initial)
		echo "Running initial install. Press Enter to Continue or CTRL+C to abort."
		read -r _
		initialinstall
	;;
	postreboot)
		echo "Running postreboot setup. Press Enter to Continue or CTRL+C to abort."
		read -r _
		postreboot
	;;
	remoteaccess)
		echo "Running remote access to ZFSBootMenu install. Press Enter to Continue or CTRL+C to abort."
		read -r _
		setupremoteaccess
	;;
	datapool)
		echo "Running create data pool on non-root drive. Press Enter to Continue or CTRL+C to abort."
		read -r _
		createdatapool
	;;
	*)
		echo -e "Usage: $0 initial | postreboot | remoteaccess | datapool"
	;;
esac

date
exit 0
