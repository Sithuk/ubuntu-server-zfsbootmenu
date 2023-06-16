#!/bin/bash
##Script installs ubuntu on the zfs file system with snapshot rollback at boot. Options include encryption and headless remote unlocking.
##Script: https://github.com/Sithuk/ubuntu-server-zfsbootmenu
##Script date: 2023-04-23

set -euo pipefail
#set -x

##Usage: <script_filename> install | remoteaccess | datapool

##Run with "install" option from Ubuntu live iso (desktop version) terminal.

##Remote access can be installed by either:
##  setting the remoteaccess variable to "yes" in the variables section below, or
##  running the script with the "remoteaccess" option after rebooting into the new installation.
##Connect as "root" on port 222 to the server's ip address.
##It's better to leave the remoteaccess variable below as "no" and run the script with the "remoteaccess" option
##  as that will use the user's authorized_keys file. Setting the remoteaccess variable to "yes" will use root's authorized_keys.
##Login as "root" during remote access, even if using a user's authorized_keys file. No other users are available during remote access.

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
ubuntuver="jammy" #Ubuntu release to install. "jammy" (22.04).
distro_variant="server" #Ubuntu variant to install. "server" (Ubuntu server; cli only.) "desktop" (Default Ubuntu desktop install). "kubuntu" (KDE plasma desktop variant). "xubuntu" (Xfce desktop variant). "budgie" (Budgie desktop variant). "MATE" (MATE desktop variant).
user="testuser" #Username for new install.
PASSWORD="testuser" #Password for user in new install.
hostname="ubuntu" #Name to identify the main system on the network. An underscore is DNS non-compliant.
zfs_root_password="testtest" #Password for encrypted root pool. Minimum 8 characters. "" for no password encrypted protection. Unlocking root pool also unlocks data pool, unless the root pool has no password protection, then a separate data pool password can be set below.
locale="en_GB.UTF-8" #New install language setting.
timezone="Europe/London" #New install timezone setting.
zfs_rpool_ashift="12" #Drive setting for zfs pool. ashift=9 means 512B sectors (used by all ancient drives), ashift=12 means 4KiB sectors (used by most modern hard drives), and ashift=13 means 8KiB sectors (used by some modern SSDs).

RPOOL="rpool" #Root pool name.
topology_root="single" #"single", "mirror", "raid0", "raidz1", "raidz2", or "raidz3" topology on root pool.
disks_root="1" #Number of disks in array for root pool. Not used with single topology.
EFI_boot_size="512" #EFI boot loader partition size in mebibytes (MiB).
swap_size="500" #Swap partition size in mebibytes (MiB). Size of swap will be larger than defined here with Raidz topologies.
datapool="datapool" #Non-root drive data pool name.
topology_data="single" #"single", "mirror", "raid0", "raidz1", "raidz2", or "raidz3" topology on data pool.
disks_data="1" #Number of disks in array for data pool. Not used with single topology.
zfs_data_password="testtest" #If no root pool password is set, a data pool password can be set here. Minimum 8 characters. "" for no password protection.
datapoolmount="/mnt/$datapool" #Non-root drive data pool mount point in new install.
zfs_dpool_ashift="12" #See notes for rpool ashift. If ashift is set too low, a significant read/write penalty is incurred. Virtually no penalty if set higher.
zfs_compression="zstd" #"lz4" is the zfs default; "zstd" may offer better compression at a cost of higher cpu usage.
mountpoint="/mnt/ub_server" #Mountpoint in live iso.
remoteaccess_first_boot="no" #"yes" to enable remoteaccess during first boot. Recommend leaving as "no" and run script with "remoteaccess". See notes in section above.
timeout_rEFInd="3" #Timeout in seconds for rEFInd boot screen until default choice selected.
timeout_zbm_no_remote_access="3" #Timeout in seconds for zfsbootmenu when no remote access enabled.
timeout_zbm_remote_access="45" #Timeout in seconds for zfsbootmenu when remote access enabled. The password prompt for an encrypted root pool with allow an indefinite time to connect. An unencrypted root pool will boot the system when the timer runs out, preventing remote access.
quiet_boot="yes" #Set to "no" to show boot sequence.
ethprefix="e" #First letter of ethernet interface. Used to identify ethernet interface to setup networking in new install.
install_log="ubuntu_setup_zfs_root.log" #Installation log filename.
log_loc="/var/log" #Installation log location.
ipv6_apt_fix_live_iso="no" #Try setting to "yes" gif apt-get is slow in the ubuntu live iso. Doesn't affect ipv6 functionality in the new install.
remoteaccess_hostname="zbm" #Name to identify the zfsbootmenu system on the network.
remoteaccess_ip_config="dhcp" #"dhcp", "dhcp,dhcp6", "dhcp6", or "static". Automatic (dhcp) or static IP assignment for zfsbootmenu remote access.
remoteaccess_ip="192.168.0.222" #Remote access static IP address to connect to ZFSBootMenu. Not used for automatic IP configuration.
remoteaccess_netmask="255.255.255.0" #Remote access subnet mask. Not used for "dhcp" automatic IP configuration.
install_warning_level="PRIORITY=critical" #"PRIORITY=critical", or "FRONTEND=noninteractive". Pause install to show critical messages only or do not pause (noninteractive). Script still pauses for keyboard selection at the end.
extra_programs="no" #"yes", or "no". Install additional programs if not included in the ubuntu distro package. Programs: cifs-utils, locate, man-db, openssh-server, tldr.

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

##Functions
live_desktop_check(){
	##Check for live desktop environment
	if [ "$(dpkg -l ubuntu-desktop)" ];
	then
		echo "Desktop environment test passed."
		if grep casper /proc/cmdline;
		then
			echo "Live environment test passed."
		else
			echo "Live environment test failed. Run script from a live desktop environment."
			exit 1
		fi
	else
		echo "Desktop environment test failed. Run script from a live desktop environment."
		exit 1
	fi
}

topology_min_disk_check(){
	##Check that number of disks meets minimum number for selected topology.
	pool="$1"
	echo "Checking script variables for $pool pool..."
	
	topology_pool_pointer="topology_$pool"
	eval echo "User defined topology for ${pool} pool: \$${topology_pool_pointer}"
	eval topology_pool_pointer="\$${topology_pool_pointer}"
	
	disks_pointer="disks_${pool}"
	eval echo "User defined number of disks in pool: \$${disks_pointer}"
	eval disks_pointer=\$"${disks_pointer}"

	num_disks_check(){
		min_num_disks="$1"
		
		if [ "$disks_pointer" -lt "$min_num_disks" ]
		then
			echo "A ${topology_pool_pointer} topology requires at least ${min_num_disks} disks. Check variable for number of disks or change the selected topology."
			exit 1
		else true
		fi
	}
	
	case "$topology_pool_pointer" in
		single) true ;;
		
		mirror|raid0|raidz1)
			num_disks_check "2"
		;;
		
		raidz2)
			num_disks_check "3"
		;;

		raidz3)
			num_disks_check "4"
		;;

		*)
			echo "Pool topology not recognised. Check pool topology variable."
			exit 1
		;;
	esac
	printf "%s\n\n" "Minimum disk topology check passed for $pool pool."
}

logFunc(){
	# Log everything we do
	exec > >(tee -a "$log_loc"/"$install_log") 2>&1
}

disclaimer(){
	echo "***WARNING*** This script could wipe out all your data, or worse! I am not responsible for your decisions. Press Enter to Continue or CTRL+C to abort."
	read -r _
}

connectivity_check(){
	##https://unix.stackexchange.com/a/190610
	test_site=google.com
	if nc -zw1 "${test_site}" 443
	then
		echo "Internet connectivity test passed."
	else
		echo "No internet connectivity available. Please check connectivity."
		exit 1
	fi
}

getdiskID(){
	pool="$1"
	diskidnum="$2"
	total_discs="$3"
	
	##Get disk ID(s)	
	
	manual_read(){
		ls -la /dev/disk/by-id
		echo "Enter Disk ID for disk $diskidnum of $total_discs on $pool pool (must match exactly):"
		read -r DISKID
	}
	#manual_read
	
	menu_read(){
		diskidmenu_loc="/tmp/diskidmenu.txt"
		ls -la /dev/disk/by-id | awk '{ print $9, $11 }' | sed -e '1,3d' | grep -v "part\|CD-ROM" > "$diskidmenu_loc"
		
		echo "Please enter Disk ID option for disk $diskidnum of $total_discs on $pool pool."
		nl "$diskidmenu_loc"
		count="$(wc -l "$diskidmenu_loc" | cut -f 1 -d' ')"
		n=""
		while true; 
		do
			read -r -p 'Select option: ' n
			if [ "$n" -eq "$n" ] && [ "$n" -gt 0 ] && [ "$n" -le "$count" ]; then
				break
			fi
		done
		DISKID="$(sed -n "${n}p" "$diskidmenu_loc" | awk '{ print $1 }' )"
		printf "%s\n\n" "Option number $n selected: '$DISKID'"
	}
	menu_read
	
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
}

getdiskID_pool(){
	pool="$1"

	##Check that number of disks meets minimum number for selected topology.
	topology_min_disk_check "$pool"

	echo "Carefully enter the ID of the disk(s) YOU WANT TO DESTROY in the next step to ensure no data is accidentally lost."
	
	##Create temp file to check for duplicated disk ID entry.
	true > /tmp/diskid_check_"${pool}".txt
	
	topology_pool_pointer="topology_$pool"
	#eval echo \$"${topology_pool_pointer}"
	eval topology_pool_pointer="\$${topology_pool_pointer}"
	
	disks_pointer="disks_${pool}"
	#eval echo \$"${disks_pointer}"
	eval disks_pointer=\$"${disks_pointer}"

	case "$topology_pool_pointer" in
		single)
			echo "The $pool pool disk topology is a single disk."
			getdiskID "$pool" "1" "1"
		;;

		mirror|raid0|raidz*)
			echo "The $pool pool disk topology is $topology_pool_pointer with $disks_pointer disks."
			diskidnum="1"
			while [ "$diskidnum" -le "$disks_pointer" ];
			do
				getdiskID "$pool" "$diskidnum" "$disks_pointer"
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

activate_mirror(){
	##Identify and use fastest mirror.
	ubuntu_original="$(grep -v '^ *#\|security\|cdrom' /etc/apt/sources.list.bak | sed '/^[[:space:]]*$/d' | awk '{ print $2 }' | sort -u | head -n 1)"
	
	echo "Choosing fastest up-to-date ubuntu mirror based on download speed."
	apt update
	apt install -y curl
	ubuntu_mirror=$({
	##Choose mirrors that are up-to-date by checking the Last-Modified header.
	##https://github.com/actions/runner-images/issues/675#issuecomment-1381837292
	{
	curl -s http://mirrors.ubuntu.com/mirrors.txt
	} | xargs -I {} sh -c 'echo "$(curl -m 5 -sI {}dists/$(lsb_release -c | cut -f2)-security/Contents-$(dpkg --print-architecture).gz | sed s/\\r\$//|grep Last-Modified|awk -F": " "{ print \$2 }" | LANG=C date -f- -u +%s)" "{}"' | sort -rg | awk '{ if (NR==1) TS=$1; if ($1 == TS) print $2 }'
	} | xargs -I {} sh -c 'echo "$(curl -r 0-102400 -m 5 -s -w %{speed_download} -o /dev/null {}ls-lR.gz)" {}' \
	| sort -g -r | head -1 | awk '{ print $2  }')

	if [ -z "${ubuntu_mirror}" ];
	then
		echo "No mirror identified. No changes made."
	else
		if [ "${ubuntu_original}" != "${ubuntu_mirror}" ];
		then
			sed -i "s,${ubuntu_original},${ubuntu_mirror},g" /etc/apt/sources.list
			echo "Selected '${ubuntu_mirror}'."
		else
			echo "Identified mirror is already selected. No changes made."
		fi
	fi
}

reinstate_non_mirror(){
	mv ${mountpoint}/etc/apt/sources.list.non-mirror ${mountpoint}/etc/apt/sources.list ##Reinstate non-mirror package sources in new install.
}

apt_sources(){
	source_archive="$1"
	sources_list="$2"
	cat > "${sources_list}" <<-EOLIST
		deb ${source_archive} $ubuntuver main universe restricted multiverse
		#deb-src ${source_archive} $ubuntuver main universe restricted multiverse
		
		deb ${source_archive} $ubuntuver-updates main universe restricted multiverse
		#deb-src ${source_archive} $ubuntuver-updates main universe restricted multiverse
		
		deb ${source_archive} $ubuntuver-backports main universe restricted multiverse
		#deb-src ${source_archive} $ubuntuver-backports main universe restricted multiverse
		
		deb http://security.ubuntu.com/ubuntu $ubuntuver-security main universe restricted multiverse
		#deb-src http://security.ubuntu.com/ubuntu $ubuntuver-security main universe restricted multiverse
	EOLIST
}

logcopy(){
	##Copy install log to new installation.
	if [ -d "$mountpoint" ]; then
		cp "$log_loc"/"$install_log" "$mountpoint""$log_loc"
		echo "Log file copied into new installation at ${log_loc}."
	else 
		echo "No mountpoint dir present. Install log not copied."
	fi
}

script_copy(){
	##Copy script to new installation
	cp "$(readlink -f "$0")" "$mountpoint"/home/"${user}"/
	script_new_install_loc=/home/"${user}"/"$(basename "$0")"
	
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		chown "${user}":"${user}" "$script_new_install_loc"
		chmod +x "$script_new_install_loc"
	EOCHROOT

	if [ -f "$mountpoint""$script_new_install_loc" ];
	then
		echo "Install script copied to ${user} home directory in new installation."
	else
		echo "Error copying install script to new installation."
	fi
}

debootstrap_part1_Func(){
	export DEBIAN_"${install_warning_level}"
	
	update_live_iso_data_sources(){
		cp /etc/apt/sources.list /etc/apt/sources.list.bak
		activate_mirror	

		#sed -i 's,deb http://security,#deb http://security,' /etc/apt/sources.list ##Uncomment to resolve security pocket time out. Security packages are copied to the other pockets frequently, so should still be available for update. See https://wiki.ubuntu.com/SecurityTeam/FAQ
		
		cat /etc/apt/sources.list
		trap 'printf "%s\n%s" "The script has experienced an error during the first apt update. That may have been caused by a queried server not responding in time. Try running the script again." "If the issue is the security server not responding, then comment out the security server in the /etc/apt/sources.list. Alternatively, you can uncomment the command that does this in the install script. This affects the temporary live iso only. Not the permanent installation."' ERR
		apt update
		trap - ERR	##Resets the trap to doing nothing when the script experiences an error. The script will still exit on error if "set -e" is set.
		}
	update_live_iso_data_sources	

	ssh_Func(){
		##Setup SSH to allow remote access in live environment
		apt install --yes openssh-server
		service sshd start
		ip addr show scope global | grep inet
	}
	#ssh_Func
	
	apt-get -yq install debootstrap software-properties-common gdisk zfs-initramfs
	if service --status-all | grep -Fq 'zfs-zed'; then
		systemctl stop zfs-zed
	fi

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
			single|mirror)
				swap_hex_code="8200"
			;;

			raid0|raidz*)
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

	create_rpool_Func(){
		##Create root pool
		
		zpool_create_temp="/tmp/${RPOOL}_creation.sh"
		cat > "$zpool_create_temp" <<-EOF
			zpool create -f \\
				-o ashift=$zfs_rpool_ashift \\
				-o autotrim=on \\
				-O acltype=posixacl \\
				-O canmount=off \\
				-O compression=$zfs_compression \\
				-O dnodesize=auto \\
				-O normalization=formD \\
				-O relatime=on \\
				-O xattr=sa \\
		EOF
	
		if [ -n "$zfs_root_password" ];
		then
			echo "-O encryption=aes-256-gcm -O keylocation=prompt -O keyformat=passphrase \\" >> "$zpool_create_temp"
		else
			true
		fi	
		
		echo "-O mountpoint=/ -R $mountpoint \\" >> "$zpool_create_temp"

		add_zpool_disks(){
			while IFS= read -r diskidnum;
			do
				echo "/dev/disk/by-id/${diskidnum}-part3 \\" >> "$zpool_create_temp"
			done < /tmp/diskid_check_root.txt
		
			sed -i '$s,\\,,' "$zpool_create_temp" ##Remove escape character at end of file.
		}


		case "$topology_root" in
			single|raid0)
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
	create_rpool_Func
	echo -e "$zfs_root_password" | sh "$zpool_create_temp" 
	
	##System installation
	mountpointsFunc(){

		##zfsbootmenu setup for no separate boot pool
		##https://github.com/zbm-dev/zfsbootmenu/wiki/Debian-Buster-installation-with-ESP-on-the-zpool-disk
		
		sleep 2
		##Create filesystem datasets to act as containers
		zfs create -o canmount=off -o mountpoint=none "$RPOOL"/ROOT 
					
		##Create root filesystem dataset
		rootzfs_full_name="ubuntu.$(date +%Y.%m.%d)"
		zfs create -o canmount=noauto -o mountpoint=/ "$RPOOL"/ROOT/"$rootzfs_full_name" ##zfsbootmenu debian guide
		##assigns canmount=noauto on any file systems with mountpoint=/ (that is, on any additional boot environments you create).
		##With ZFS, it is not normally necessary to use a mount command (either mount or zfs mount). 
		##This situation is an exception because of canmount=noauto.
		zfs mount "$RPOOL"/ROOT/"$rootzfs_full_name"
		zpool set bootfs="$RPOOL"/ROOT/"$rootzfs_full_name" "$RPOOL"
		
		
		##Create datasets
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
	##Install minimum system
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
		apt update
		apt install -y dracut-network dropbear
		
		git -C /tmp clone 'https://github.com/dracut-crypt-ssh/dracut-crypt-ssh.git'
		mkdir /usr/lib/dracut/modules.d/60crypt-ssh
		cp /tmp/dracut-crypt-ssh/modules/60crypt-ssh/* /usr/lib/dracut/modules.d/60crypt-ssh/
		rm /usr/lib/dracut/modules.d/60crypt-ssh/Makefile
		
		##comment out references to /helper/ folder in module-setup.sh
		sed -i \\
			-e 's,  inst "\$moddir"/helper/console_auth /bin/console_auth,  #inst "\$moddir"/helper/console_auth /bin/console_auth,' \\
			-e 's,  inst "\$moddir"/helper/console_peek.sh /bin/console_peek,  #inst "\$moddir"/helper/console_peek.sh /bin/console_peek,' \\
			-e 's,  inst "\$moddir"/helper/unlock /bin/unlock,  #inst "\$moddir"/helper/unlock /bin/unlock,' \\
			-e 's,  inst "\$moddir"/helper/unlock-reap-success.sh /sbin/unlock-reap-success,  #inst "\$moddir"/helper/unlock-reap-success.sh /sbin/unlock-reap-success,' \\
			"$modulesetup"
		
		##create host keys
		mkdir -p /etc/dropbear
		ssh-keygen -t rsa -m PEM -f /etc/dropbear/ssh_host_rsa_key -N ""
		ssh-keygen -t ecdsa -m PEM -f /etc/dropbear/ssh_host_ecdsa_key -N ""
		
		##setup network	
		mkdir -p /etc/cmdline.d
		
		remoteaccess_dhcp_ver(){
			dhcpver="\$1"
			echo "ip=\${dhcpver:-default} rd.neednet=1" > /etc/cmdline.d/dracut-network.conf
		}

		##Dracut network options: https://github.com/dracutdevs/dracut/blob/master/modules.d/35network-legacy/ifup.sh
		case "$remoteaccess_ip_config" in
		dhcp | dhcp,dhcp6 | dhcp6)
			remoteaccess_dhcp_ver "$remoteaccess_ip_config"
		;;
		static)
			echo "ip=$remoteaccess_ip:::$remoteaccess_netmask:::none rd.neednet=1 rd.break" > /etc/cmdline.d/dracut-network.conf
		;;
		*)
			echo "Remote access IP option not recognised."
			exit 1
		;;
		esac
		
		echo "send fqdn.fqdn \"$remoteaccess_hostname\";" >> /usr/lib/dracut/modules.d/35network-legacy/dhclient.conf

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
		
		##Set ownership of initramfs authorized_keys
		sed -i '/inst "\${dropbear_acl}"/a \\  chown root:root "\${initdir}/root/.ssh/authorized_keys"' "$modulesetup"

		cat <<-EOF >/etc/zfsbootmenu/dracut.conf.d/dropbear.conf
			## Enable dropbear ssh server and pull in network configuration args
			##The default configuration will start dropbear on TCP port 222.
			##This can be overridden with the dropbear_port configuration option.
			##You do not want the server listening on the default port 22.
			##Clients that expect to find your normal host keys when connecting to an SSH server on port 22 will
			##   refuse to connect when they find different keys provided by dropbear.
			
			add_dracutmodules+=" crypt-ssh network-legacy "
			install_optional_items+=" /etc/cmdline.d/dracut-network.conf "
			
			## Copy system keys for consistent access
			dropbear_rsa_key="/etc/dropbear/ssh_host_rsa_key"
			dropbear_ecdsa_key="/etc/dropbear/ssh_host_ecdsa_key"
			
			##Access is by authorized keys only. No password.
			##By default, the list of authorized keys is taken from /root/.ssh/authorized_keys on the host.
			##A custom authorized_keys location can also be specified with the dropbear_acl variable.
			##You can add your remote user key to a user authorized_keys file from a remote machine's terminal using:
			##"ssh-copy-id -i ~/.ssh/id_rsa.pub $user@{IP_ADDRESS or FQDN of the server}"
			##Then amend/uncomment the dropbear_acl variable to match:
			#dropbear_acl="/home/${user}/.ssh/authorized_keys"
			##Remember to "sudo generate-zbm" on the host after adding the remote user key to the authorized_keys file.
			
			##Note that login to dropbear is "root" regardless of which authorized_keys is used.
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
		##Test for live environment.
		if grep casper /proc/cmdline;
		then
			echo "Live environment present. Reboot into new installation to install remoteaccess."
			exit 1
		else	
			/bin/bash /tmp/remote_zbm_access.sh
		fi
	;;
	*)
		exit 1
	;;
	esac
	
}


systemsetupFunc_part1(){

	##System configuration
	
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		export DEBIAN_"${install_warning_level}"
	EOCHROOT

	##Configure hostname
	echo "$hostname" > "$mountpoint"/etc/hostname
	echo "127.0.1.1       $hostname" >> "$mountpoint"/etc/hosts
	
	##Configure network interface
	
	##Get ethernet interface
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

	##Bind virtual filesystems from LiveCD to new system
	mount --rbind /dev  "$mountpoint"/dev
	mount --rbind /proc "$mountpoint"/proc
	mount --rbind /sys  "$mountpoint"/sys 

	##Configure package sources
	apt_sources "${ubuntu_original}" "$mountpoint/etc/apt/sources.list.non-mirror"
	apt_sources "${ubuntu_mirror}" "$mountpoint/etc/apt/sources.list.mirror"
	
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##Select mirror package sources
		cp /etc/apt/sources.list /etc/apt/sources.list.bak
		cp /etc/apt/sources.list.mirror /etc/apt/sources.list
	EOCHROOT

	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##4.5 configure basic system
		apt update
		
		#dpkg-reconfigure locales
		locale-gen en_US.UTF-8 $locale
		echo 'LANG="$locale"' > /etc/default/locale
		
		##set timezone
		ln -fs /usr/share/zoneinfo/"$timezone" /etc/localtime
		dpkg-reconfigure tzdata
		
	EOCHROOT
}

systemsetupFunc_part2(){
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##install zfs
		apt update

		apt install --no-install-recommends -y linux-headers-generic linux-image-generic ##need to use no-install-recommends otherwise installs grub
		
		apt install --yes --no-install-recommends dkms wget nano
		
		apt install -yq software-properties-common
		
		##Ubuntu kernels come with zfs module installed. No need to install zfs-dkms for zfs version in the default repositories.
		#apt-get -yq install zfs-dkms
		
		apt install --yes zfsutils-linux zfs-zed

		apt install --yes zfs-initramfs

		
	EOCHROOT
}

systemsetupFunc_part3(){
	identify_ubuntu_dataset_uuid

	##Create the EFI filesystem
	apt install --yes dosfstools

	loop_counter="$(mktemp)"
	echo 0 > "$loop_counter" ##Assign starting counter value.
	while IFS= read -r diskidnum;
	do
		i="$(cat "$loop_counter")"
		echo "$i"
		if [ "$i" -eq 0 ];
		then
			esp_mount="/boot/efi"
		else
			esp_mount="/boot/efi$i"
			echo "$esp_mount" >> "$mountpoint"/tmp/backup_esp_mounts.txt
			initial_boot_order="$(efibootmgr | grep "BootOrder" | cut -d " " -f 2)"
		fi

		echo "Creating FAT32 filesystem in EFI partition of disk ${diskidnum}. ESP mountpoint is ${esp_mount}"
		mkdosfs -F 32 -s 1 -n EFI /dev/disk/by-id/"${diskidnum}"-part1
		sleep 2
		blkid_part1=""
		blkid_part1="$(blkid -s UUID -o value /dev/disk/by-id/"${diskidnum}"-part1)"
		echo "$blkid_part1" >> /tmp/esp_partition_list_uuid.txt

		chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
			mkdir -p "${esp_mount}"

			##fstab entry
			echo /dev/disk/by-uuid/"$blkid_part1" \
				"${esp_mount}" vfat \
				defaults \
				0 0 >> /etc/fstab

			##mount from fstab entry
			mount "${esp_mount}"
			##If mount fails error code is 0. Script won't fail. Need the following check.
			##Could use "mountpoint" command but not all distros have it.
			if grep "${esp_mount}" /proc/mounts; then
				echo "${esp_mount} mounted."
			else
				echo "${esp_mount} not mounted."
				exit 1
			fi
		EOCHROOT

		i=$((i + 1)) ##Increment counter.
		echo "$i" > "$loop_counter"

	done < /tmp/diskid_check_"${pool}".txt

	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		apt-get -yq install refind kexec-tools
		apt install --yes dpkg-dev git systemd-sysv
		
		##Adjust timer on initial rEFInd screen
		sed -i 's,^timeout .*,timeout $timeout_rEFInd,' /boot/efi/EFI/refind/refind.conf

		echo REMAKE_INITRD=yes > /etc/dkms/zfs.conf
		sed -i 's,LOAD_KEXEC=false,LOAD_KEXEC=true,' /etc/default/kexec
	EOCHROOT

}

systemsetupFunc_part4(){
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		zfsbootmenuinstall(){

			if [ -n "$zfs_root_password" ];
			then
				##Convert rpool to use keyfile.
				echo $zfs_root_password > /etc/zfs/$RPOOL.key ##This file will live inside your initramfs stored on the ZFS boot environment.
				chmod 600 /etc/zfs/$RPOOL.key ##Set access rights to keyfile.
				echo "UMASK=0077" > /etc/initramfs-tools/conf.d/umask.conf ##Set access rights for initramfs images generated by mkinitramfs. 
				zfs change-key -o keylocation=file:///etc/zfs/$RPOOL.key -o keyformat=passphrase $RPOOL
				
				##Setup key caching in zfsbootmenu
				zfs set org.zfsbootmenu:keysource="$RPOOL/ROOT" $RPOOL
			else
				true
			fi	
							
			if [ "$quiet_boot" = "yes" ]; then
				zfs set org.zfsbootmenu:commandline="spl_hostid=\$( hostid ) ro quiet" "$RPOOL"/ROOT
			else
				zfs set org.zfsbootmenu:commandline="spl_hostid=\$( hostid ) ro" "$RPOOL"/ROOT
			fi

			##install zfsbootmenu
			compile_zbm_git(){
				##https://github.com/zbm-dev/zfsbootmenu/blob/master/testing/helpers/chroot-ubuntu.sh
				##Prevent interactive prompts
				#export DEBIAN_"${install_warning_level}"
				#export DEBCONF_NONINTERACTIVE_SEEN=true
				
				##bsdextrautils contains column utility used in zfsbootmenu UI.
				apt-get install --yes bsdextrautils
				
				##Install optional mbuffer package.
				##https://github.com/zbm-dev/zfsbootmenu/blob/master/zfsbootmenu/install-helpers.sh
				apt-get install --yes mbuffer
				
				##Install packages needed for zfsbootmenu
				apt-get install --yes --no-install-recommends git dracut-core fzf kexec-tools cpanminus gcc make
				
				##Remove temporary directory if already present
				if [ -d /tmp/zfsbootmenu ];
				then
					rm -rf /tmp/zfsbootmenu
				fi
				
				apt install -y git make
				cd /tmp
				git clone 'https://github.com/zbm-dev/zfsbootmenu.git'
				cd zfsbootmenu
				make core dracut ##"make install" installs mkinitcpio, not needed.
				
				##Install perl dependencies
				cpanm --notest --installdeps .
				
			}
			compile_zbm_git
				
			##configure zfsbootmenu
			config_zbm(){
				##https://github.com/zbm-dev/zfsbootmenu/blob/master/testing/helpers/configure-ubuntu.sh
				##Update configuration file
				sed \\
				-e 's,ManageImages:.*,ManageImages: true,' \\
				-e 's@ImageDir:.*@ImageDir: /boot/efi/EFI/ubuntu@' \\
				-e 's,Versions:.*,Versions: false,' \\
				-i /etc/zfsbootmenu/config.yaml
			
				if [ "$quiet_boot" = "no" ]; then
					sed -i 's,ro quiet,ro,' /etc/zfsbootmenu/config.yaml
				fi
				
			}
			config_zbm
				
			update-initramfs -c -k all
			generate-zbm --debug
				
			##Update refind_linux.conf
			config_refind(){
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
			config_refind
			
		}
		zfsbootmenuinstall

	EOCHROOT
	
	zbm_multiple_ESP(){
		esp_sync_path="/etc/zfsbootmenu/generate-zbm.post.d/esp-sync.sh"
		chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
			mkdir -p "/etc/zfsbootmenu/generate-zbm.post.d/"

			#find /boot -maxdepth 1 -mindepth 1 -type d -not -path "/boot/efi" -path "/boot/efi*" > /tmp/backup_esp_mounts.txt

			cat > "$esp_sync_path" <<-"EOT"
				#!/bin/sh
				
				sync_func(){
					
				   rsync --delete-after -axHAWXS --info=progress2 /boot/efi/ "\$1"
				
				}

			EOT

			while IFS= read -r esp_mount;
			do
				echo "sync_func \"\$esp_mount"\" >> "$esp_sync_path"
			done < /tmp/backup_esp_mounts.txt

			chmod +x "$esp_sync_path"
			apt install rsync
			sh "$esp_sync_path" ##Sync main ESP to backup ESPs.
			
		EOCHROOT
		
		update_boot_manager(){
			##Add backup ESPs to the EFI boot manager
			loop_counter="$(mktemp)"
			echo 0 > "$loop_counter" ##Assign starting counter value.
			while IFS= read -r diskidnum;
			do
				i="$(cat "$loop_counter")"
				echo "$i"
				if [ "$i" -eq 0 ];
				then
					true
				else
					device_name="$(readlink -f /dev/disk/by-id/"${diskidnum}")"
					efibootmgr --create --disk "${device_name}" --label "rEFInd Boot Manager Backup $i" --loader \\EFI\\refind\\refind_x64.efi
				fi
				i=$((i + 1)) ##Increment counter.
				echo "$i" > "$loop_counter"
			done < /tmp/diskid_check_"${pool}".txt
		
			##Adjust ESP boot order
			primary_esp_num="$(efibootmgr | grep -v "Backup" | grep -w "rEFInd Boot Manager" | cut -d " " -f 1 | sed 's,Boot,,' | sed 's,*,,')"
			num_disks="$(wc -l /tmp/diskid_check_"${pool}".txt | awk '{ print $1 }')"
			last_esp_num=$(( "$primary_esp_num" + "$num_disks" ))
						
			i="$primary_esp_num"
			while [ "$i" -ne "$last_esp_num" ]
			do
				if [ "$i" -eq "$primary_esp_num" ];
				then
					echo "$primary_esp_num," > /tmp/revised_boot_order.txt
				else
					sed -i "s/$/$i,/g" /tmp/revised_boot_order.txt
				fi
				i=$((i + 1))
			done 
			sed -i "s/$/$initial_boot_order/g" /tmp/revised_boot_order.txt
			revised_boot_order="$(cat /tmp/revised_boot_order.txt)"
			efibootmgr -o "$revised_boot_order"
		}
		update_boot_manager
	}

	case "$topology_pool_pointer" in
		single)
			true
		;;

		mirror|raid0|raidz*)
			echo "Configuring zfsbootmenu to update all ESPs."
			zbm_multiple_ESP
		;;

		*)
			echo "Pool topology not recognised. Check pool topology variable."
			exit 1
		;;
	esac

	if [ "${remoteaccess_first_boot}" = "yes" ];
	then
		remote_zbm_access_Func "chroot"
	else true
	fi
	
}

systemsetupFunc_part5(){

	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##Set root password
		echo -e "root:$PASSWORD" | chpasswd -c SHA256
	EOCHROOT
	
	##Configure swap
	
	##"plain" required in crypttab to avoid message at boot: "From cryptsetup: couldn't determine device type, assuming default (plain)."
	crypttab_parameters="/dev/urandom plain,swap,cipher=aes-xts-plain64:sha256,size=512"

	mdadm_swap_Func(){
		mdadm_swap_loc="/tmp/multi_disc_swap.sh"
		mdadm_level="$1" ##ZFS raidz = MDADM raid5, raidz2 = raid6. MDADM does not have raid7, so no triple parity equivalent to raidz3.
		mdadm_devices="$2" ##Number of disks.
	
		cat > "$mdadm_swap_loc" <<-EOF
			##Swap setup for mirror or raidz topology.
			apt install --yes mdadm

			##Set MDADM level and number of disks.
			mdadm --create /dev/md0 --metadata=1.2 \\
			--level="$mdadm_level" \\
			--raid-devices="$mdadm_devices" \\
		EOF
	
		##Add swap disks.
		while IFS= read -r diskidnum;
		do
			echo "/dev/disk/by-id/${diskidnum}-part2 \\" >> "$mdadm_swap_loc"
		done < /tmp/diskid_check_root.txt
		
		sed -i '$s,\\,,' "$mdadm_swap_loc" ##Remove escape characters needed for last line of EOF code block.

		##Update fstab and cryptsetup.
		if [ -n "$zfs_root_password" ];
		then
			cat >> "$mdadm_swap_loc" <<-EOF
				apt install --yes cryptsetup
				echo swap /dev/md0 ${crypttab_parameters} >> /etc/crypttab
				echo /dev/mapper/swap none swap defaults 0 0 >> /etc/fstab
			EOF
		else
			cat >> "$mdadm_swap_loc" <<-EOF
				mkswap -f /dev/md0
				blkid_md0=""
				blkid_md0="\$(blkid -s UUID -o value /dev/md0)"
				echo /dev/disk/by-uuid/\${blkid_md0} none swap defaults 0 0 >> /etc/fstab
			EOF
		fi

		##Update mdadm configuration file
		cat >> "$mdadm_swap_loc" <<-EOF
			mdadm --detail --scan --verbose | tee -a /etc/mdadm/mdadm.conf
		EOF

		##Check MDADM status.
		cat >> "$mdadm_swap_loc" <<-EOF
			cat /proc/mdstat
			mdadm --detail /dev/md0
		EOF
		
		##Copy MDADM setup file into chroot and run. 
		cp "$mdadm_swap_loc" "$mountpoint"/tmp/
		chroot "$mountpoint" /bin/bash -x "$mdadm_swap_loc"
	}
	
	case "$topology_root" in
		single)
			if [ -n "$zfs_root_password" ];
			then
				chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
					apt install --yes cryptsetup
					echo swap /dev/disk/by-id/"$DISKID"-part2 ${crypttab_parameters} >> /etc/crypttab
					echo /dev/mapper/swap none swap defaults 0 0 >> /etc/fstab
				EOCHROOT
			else
				blkid_part2=""
				chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
					mkswap -f /dev/disk/by-id/"$DISKID"-part2
					blkid_part2="\$(blkid -s UUID -o value /dev/disk/by-id/$DISKID-part2)"
					echo /dev/disk/by-uuid/\${blkid_part2} none swap defaults 0 0 >> /etc/fstab
					swapon -a
				EOCHROOT
			fi
		;;

		mirror)
			##mdadm --level=mirror is the same as --level=1.
			mdadm_swap_Func "mirror" "$disks_root"
		;;

		raid0)
			##No need for RAID0 for swap. The kernel supports stripe swapping on multiple devices if given the same priority in fstab.
			##https://raid.wiki.kernel.org/index.php/Why_RAID%3F#Swapping_on_RAID

			loop_counter="$(mktemp)"
			echo 0 > "$loop_counter" ##Assign starting counter value.
			while IFS= read -r diskidnum;
			do
				i="$(cat "$loop_counter")"
				echo "$i"
				swap_part_num="swap$i"

				if [ -n "$zfs_root_password" ];
				then
					echo "${swap_part_num}" /dev/disk/by-id/"${diskidnum}"-part2 ${crypttab_parameters} >> ${mountpoint}/etc/crypttab
					echo /dev/mapper/"${swap_part_num}" none swap defaults,pri=1 0 0 >> ${mountpoint}/etc/fstab

				else
					mkswap -f /dev/disk/by-id/${diskidnum}-part2
					blkid_part2=""
					blkid_part2="$(blkid -s UUID -o value /dev/disk/by-id/${diskidnum}-part2)"
					echo /dev/disk/by-uuid/${blkid_part2} none swap defaults,pri=1 0 0 >> ${mountpoint}/etc/fstab
				fi

				i=$((i + 1)) ##Increment counter.
				echo "$i" > "$loop_counter"

			done < /tmp/diskid_check_root.txt
		;;

		raidz1)
			mdadm_swap_Func "5" "$disks_root"
		;;

		raidz2)
			mdadm_swap_Func "6" "$disks_root"
		;;

		raidz3)
			##mdadm has no equivalent raid7 to raidz3. Use raid6.
			mdadm_swap_Func "6" "$disks_root"
		;;

		*)
			echo "Pool topology not recognised. Check pool topology variable."
			exit 1
		;;

	esac
	
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##Mount a tmpfs to /tmp
		cp /usr/share/systemd/tmp.mount /etc/systemd/system/
		systemctl enable tmp.mount

		##Setup system groups
		addgroup --system lpadmin
		addgroup --system lxd
		addgroup --system sambashare

	EOCHROOT
	
	chroot "$mountpoint" /bin/bash -x <<-"EOCHROOT"

		##Refresh initrd files
		
		ls /usr/lib/modules
		
		update-initramfs -c -k all
		
	EOCHROOT
	
}

systemsetupFunc_part6(){
	
	identify_ubuntu_dataset_uuid

	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##Fix filesystem mount ordering
		
		fixfsmountorderFunc(){
			mkdir -p /etc/zfs/zfs-list.cache
			
			touch /etc/zfs/zfs-list.cache/$RPOOL
			#ln -s /usr/lib/zfs-linux/zed.d/history_event-zfs-list-cacher.sh /etc/zfs/zed.d
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

usersetup(){
	##Create user account and setup groups
	zfs create -o mountpoint=/home/"$user" "$RPOOL"/home/${user}

	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT

		##gecos parameter disabled asking for finger info
		adduser --disabled-password --gecos "" "$user"
		cp -a /etc/skel/. /home/"$user"
		chown -R "$user":"$user" /home/"$user"
		usermod -a -G adm,cdrom,dip,lpadmin,lxd,plugdev,sambashare,sudo "$user"
		echo -e "$user:$PASSWORD" | chpasswd
	
	EOCHROOT
}

distroinstall(){
	##Upgrade the minimal system
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT

		export DEBIAN_"${install_warning_level}"
		
		#if [ ! -e /var/lib/dpkg/status ]
		#then touch /var/lib/dpkg/status
		#fi
		
		apt update 
		
		apt dist-upgrade --yes
		##Install command-line environment only
		
		#rm -f /etc/resolv.conf ##Gives an error during ubuntu-server install. "Same file as /run/systemd/resolve/stub-resolv.conf". https://bugs.launchpad.net/ubuntu/+source/systemd/+bug/1774632
		#ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
		
		if [ "$distro_variant" != "server" ];
		then
			zfs create 	"$RPOOL"/var/lib/AccountsService
		fi

		case "$distro_variant" in
			server)	
				##Server installation has a command line interface only.
				##Minimal install: ubuntu-server-minimal
				apt install --yes ubuntu-server
			;;
			desktop)
				##Ubuntu default desktop install has a full GUI environment.
				##Minimal install: ubuntu-desktop-minimal
				apt install --yes ubuntu-desktop
			;;
			kubuntu)
				##Ubuntu KDE plasma desktop install has a full GUI environment.
				##Select sddm as display manager.
				echo sddm shared/default-x-display-manager select sddm | debconf-set-selections
				apt install --yes kubuntu-desktop
			;;
			xubuntu)
				##Ubuntu xfce desktop install has a full GUI environment.
				##Select lightdm as display manager.
				echo lightdm shared/default-x-display-manager select lightdm | debconf-set-selections
				apt install --yes xubuntu-desktop
			;;
			budgie)
				##Ubuntu budgie desktop install has a full GUI environment.
				##Select lightdm as display manager.
				echo lightdm shared/default-x-display-manager select lightdm | debconf-set-selections
				apt install --yes ubuntu-budgie-desktop
			;;
			MATE)
				##Ubuntu MATE desktop install has a full GUI environment.
				##Select lightdm as display manager.
				echo lightdm shared/default-x-display-manager select lightdm | debconf-set-selections
				apt install --yes ubuntu-mate-desktop
			;;
			#cinnamon)
			##ubuntucinnamon-desktop package unavailable in 22.04.
			#	##Ubuntu cinnamon desktop install has a full GUI environment.
			#	apt install --yes ubuntucinnamon-desktop
			#;;
			*)
				echo "Ubuntu variant variable not recognised. Check ubuntu variant variable."
				exit 1
			;;
		esac

	EOCHROOT
}

NetworkManager_config(){
	
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		
		##Update netplan config to use NetworkManager if installed. Otherwise will default to networkd.
		if [ "\$(dpkg-query --show --showformat='\${db:Status-Status}\n' "network-manager")" = "installed" ];
		then
			##Update netplan configuration for NetworkManager.
			ethernetinterface="\$(basename "\$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${ethprefix}*")")"
			rm /etc/netplan/01-"\$ethernetinterface".yaml
			cat > /etc/netplan/01-network-manager-all.yaml <<-EOF
				#Let NetworkManager manage all devices on this system.
				network:
				  version: 2
				  renderer: NetworkManager
			EOF
			
			##Disable systemd-networkd to prevent conflicts with NetworkManager.
			systemctl stop systemd-networkd
			systemctl disable systemd-networkd
			#systemctl mask systemd-networkd
			
			netplan apply
		else true
		fi
	
	EOCHROOT

}

extra_programs(){

	case "$extra_programs" in
	yes)	
		chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
			
			##additional programs
			
			##install samba mount access
			apt install -yq cifs-utils
			
			##install openssh-server
			apt install -y openssh-server

			apt install --yes man-db tldr locate
			
		EOCHROOT
	;;
	no)
		true
	;;
	*)
		echo "Extra_programs variable not recognised. Check extra_programs variable."
		exit 1
	;;
	esac

}

keyboard_console(){

	chroot "$mountpoint" <<-EOCHROOT

		#dpkg-reconfigure --priority=medium --frontend=dialog keyboard-configuration console-setup && setupcon #Priority needs to be set to medium or low to trigger console-setup dialog.

		export DEBIAN_PRIORITY=high
		export DEBIAN_FRONTEND=dialog

		dpkg-reconfigure keyboard-configuration
		dpkg-reconfigure console-setup #Priority needs to be set to medium or low to trigger console-setup dialog.
		setupcon

	EOCHROOT

}

logcompress(){
	
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		
		##Disable log compression
		for file in /etc/logrotate.d/* ; do
			if grep -Eq "(^|[^#y])compress" "\$file" ; then
				sed -i -r "s/(^|[^#y])(compress)/\1#\2/" "\$file"
			fi
		done
	
	EOCHROOT

}

pyznapinstall(){
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##snapshot management
		snapshotmanagement(){
			##https://github.com/yboetz/pyznap
			apt install -y python3-pip
			pip3 --version
			##https://docs.python-guide.org/dev/virtualenvs/
			apt install -y python3-virtualenv
			virtualenv --version
			apt install -y python3-virtualenvwrapper
			mkdir /opt/pyznap
			cd /opt/pyznap
			virtualenv venv
			source venv/bin/activate ##enter virtual env
			pip install pyznap
			deactivate ##exit virtual env
			ln -s /opt/pyznap/venv/bin/pyznap /usr/local/bin/pyznap
			/opt/pyznap/venv/bin/pyznap setup ##config file created /etc/pyznap/pyznap.conf
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
				*/15 * * * *   root    /opt/pyznap/venv/bin/pyznap snap >> /var/log/pyznap.log 2>&1
			EOF

			##integrate with apt
			cat > /etc/apt/apt.conf.d/80-zfs-snapshot <<-EOF
				DPkg::Pre-Invoke {"if [ -x /usr/local/bin/pyznap ]; then /usr/local/bin/pyznap snap; fi"};
			EOF
		
			pyznap snap ##Take ZFS snapshots and perform cleanup as per config file.
		}
		snapshotmanagement

	EOCHROOT

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
		#hostname -I
		echo "Zfsbootmenu remote access installed. Connect as root on port 222 during boot: \"ssh root@{IP_ADDRESS or FQDN of zfsbootmenu} -p 222\""
		echo "Your SSH public key must be placed in \"/home/$user/.ssh/authorized_keys\" prior to reboot or remote access will not work."
		echo "You can add your remote user key using the following command from the remote user's terminal if openssh-server is active on the host."
	        echo "\"ssh-copy-id -i ~/.ssh/id_rsa.pub $user@{IP_ADDRESS or FQDN of the server}\""
		echo "Run \"sudo generate-zbm\" after copying across the remote user's public ssh key into the authorized_keys file."
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
	
	##Get datapool disk ID(s)
	getdiskID_pool "data"
	
	##Clear partition table
	clear_partition_table "data"
	sleep 2
	
	##Create pool mount point
	if [ -d "$datapoolmount" ]; then
		echo "Data pool mount point exists."
	else
		mkdir -p "$datapoolmount"
		chown "$user":"$user" "$datapoolmount"
		echo "Data pool mount point created."
	fi
		
	##Automount with zfs-mount-generator
	touch /etc/zfs/zfs-list.cache/"$datapool"

	##Create data pool
	create_dpool_Func(){
		echo "$datapoolmount"
		
		zpool_create_temp="/tmp/${datapool}_creation.sh"
		cat > "$zpool_create_temp" <<-EOF
			zpool create \
				-o ashift="$zfs_dpool_ashift" \\
				-O acltype=posixacl \\
				-O compression="$zfs_compression" \\
				-O normalization=formD \\
				-O relatime=on \\
				-O dnodesize=auto \\
				-O xattr=sa \\
		EOF

		if [ -n "$zfs_root_password" ];
		then
			##Set data pool key to use rpool key for single unlock at boot. So data pool uses the same password as the root pool.
			datapool_keyloc="/etc/zfs/$RPOOL.key"
			echo "-O encryption=aes-256-gcm -O keylocation=file://$datapool_keyloc -O keyformat=passphrase \\" >> "$zpool_create_temp"
		else
			if [ -n "$zfs_data_password" ];
			then
				echo "-O encryption=aes-256-gcm -O keylocation=prompt -O keyformat=passphrase \\" >> "$zpool_create_temp"
			else
				true
			fi
		fi	
		
		echo "-O mountpoint=$datapoolmount \\" >> "$zpool_create_temp"


		add_zpool_disks(){
			while IFS= read -r diskidnum;
			do
				echo "/dev/disk/by-id/${diskidnum} \\" >> "$zpool_create_temp"
			done < /tmp/diskid_check_data.txt
		
			sed -i '$s,\\,,' "$zpool_create_temp" ##Remove escape character at end of file.
		}


		case "$topology_data" in
			single|raid0)
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
	echo -e "$zfs_data_password" | sh "$zpool_create_temp" 
	
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

install(){
	disclaimer
	live_desktop_check
	connectivity_check #Check for internet connectivity.
	getdiskID_pool "root"
	ipv6_apt_live_iso_fix #Only active if ipv6_apt_fix_live_iso variable is set to "yes".

	debootstrap_part1_Func
	debootstrap_createzfspools_Func
	debootstrap_installminsys_Func
	systemsetupFunc_part1 #Basic system configuration.
	systemsetupFunc_part2 #Install zfs.
	systemsetupFunc_part3 #Format EFI partition.
	systemsetupFunc_part4 #Install zfsbootmenu.
	systemsetupFunc_part5 #Config swap, tmpfs, rootpass.
	systemsetupFunc_part6 #ZFS file system mount ordering.
	
	usersetup #Create user account and setup groups.
	distroinstall #Upgrade the minimal system to the selected distro.
	NetworkManager_config #Adjust networking config for NetworkManager, if installed by distro.
	pyznapinstall #Snapshot management.
	extra_programs #Install extra programs.
	logcompress #Disable log compression.
	reinstate_non_mirror #Reinstate non-mirror package sources in new install.

	keyboard_console #Configure keyboard and console.
	script_copy #Copy script to new installation.
	logcopy #Copy install log to new installation.

	echo "Install complete: ${distro_variant}."
	echo "First login is ${user}:${PASSWORD-}"
	echo "Reboot."
}


case "${1-default}" in
	install)
		echo "Running installation. Press Enter to Continue or CTRL+C to abort."
		read -r _
		install
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
		printf "%s\n%s\n%s\n" "-----" "Usage: $0 install | remoteaccess | datapool" "-----"
	;;
esac

date
exit 0
