#!/bin/bash
##Script installs ubuntu on the zfs file system with snapshot rollback at boot. Options include encryption and headless remote unlocking.
##Script: https://github.com/Sithuk/ubuntu-server-zfsbootmenu
##Script date: 2026-02-07

# shellcheck disable=SC2317  # Don't warn about unreachable commands in this file

set -euo pipefail
#set -x

##Usage: <script_filename> initial | postreboot | remoteaccess | datapool

##Script to be run in two parts.
##Part 1: Run with "initial" option from Ubuntu live iso (desktop version) terminal.
##Part 2: Reboot into new install.
##Part 2: Run with "postreboot" option after first boot into new install (login as user/password defined in variable section below). 

##Remote access can be installed by either:
##  setting the remoteaccess variable to "yes" in the variables section below, or
##  running the script with the "remoteaccess" option after part 1 and part 2 are run.
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
ubuntuver="noble" #Ubuntu release to install. "jammy" (22.04). "noble" (24.04). "questing" (25.10).
distro_variant="server" #Ubuntu variant to install. "server" (Ubuntu server; cli only.) "desktop" (Default Ubuntu desktop install). "kubuntu" (KDE plasma desktop variant). "xubuntu" (Xfce desktop variant). "budgie" (Budgie desktop variant). "MATE" (MATE desktop variant).
user="testuser" #Username for new install.
PASSWORD="testuser" #Password for user in new install.
hostname="ubuntu" #Name to identify the main system on the network. An underscore is DNS non-compliant.
zfs_root_password="testtest" #Password for encrypted root pool. Minimum 8 characters. "" for no password encrypted protection. Unlocking root pool also unlocks data pool, unless the root pool has no password protection, then a separate data pool password can be set below.
zfs_root_encrypt="native" #Encryption type. "native" for native zfs encryption. "luks" for luks. Required if there is a root pool password, otherwise ignored.
locale="en_GB.UTF-8" #New install language setting.
timezone="Europe/London" #New install timezone setting.
zfs_rpool_ashift="12" #Drive setting for zfs pool. ashift=9 means 512B sectors (used by all ancient drives), ashift=12 means 4KiB sectors (used by most modern hard drives), and ashift=13 means 8KiB sectors (used by some modern SSDs).
mirror_archive="" #"" to use the default ubuntu repository. Set to an ISO 3166-1 alpha-2 country code to use a country mirror archive, e.g. "GB". A speed test is run and the fastest archive is selected. Country codes: https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2

RPOOL="rpool" #Root pool name.
topology_root="single" #"single", "mirror", "raid0", "raidz1", "raidz2", or "raidz3" topology on root pool.
disks_root="1" #Number of disks in array for root pool. Not used with single topology.
EFI_boot_size="512" #EFI boot loader partition size in mebibytes (MiB).
swap_size="500" #Swap partition size in mebibytes (MiB). Size of swap will be larger than defined here with Raidz topologies.
datapool="datapool" #Non-root drive data pool name.
topology_data="single" #"single", "mirror", "raid0", "raidz1", "raidz2", or "raidz3" topology on data pool.
# shellcheck disable=SC2034 #disks_data used indirectly via eval in topology_min_disk_check()
disks_data="1" #Number of disks in array for data pool. Not used with single topology.
zfs_data_password="testtest" #If no root pool password is set, a data pool password can be set here. Minimum 8 characters. "" for no password protection.
zfs_data_encrypt="native" #Encryption type. "native" for native zfs encryption. "luks" for luks. Required if there is a data pool password, otherwise ignored.
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
ubuntu_original="http://archive.ubuntu.com/ubuntu" #Default ubuntu repository.
install_warning_level="PRIORITY=critical" #"PRIORITY=critical", or "FRONTEND=noninteractive". Pause install to show critical messages only or do not pause (noninteractive). Script still pauses for keyboard selection.
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

##Check encryption defined if password defined
if [ -n "$zfs_root_password" ];
then	
	if [ -z $zfs_root_encrypt ];
	then
		echo "Password entered but no encryption method defined. Please define the zfs_root_encrypt variable."
	else true
	fi
else true
fi

##Functions
live_desktop_check(){
	##Check for live desktop environment
	if [ "$(dpkg -l ubuntu-desktop)" ];
	then
		echo "Desktop environment test passed."
		if grep casper /proc/cmdline >/dev/null 2>&1;
		then
			echo "Live environment present."
		else
			echo "Live environment test failed. Run script from a live desktop environment."
			exit 1
		fi
	else
		echo "Desktop environment test failed. Run script from a live desktop environment."
		exit 1
	fi

	##Check live desktop version
	live_desktop_version="$( . /etc/os-release && echo ${VERSION_CODENAME} )"
	if [ "$(echo "${live_desktop_version}" | tr '[:upper:]' '[:lower:]')" = "$(echo "${ubuntuver}" | tr '[:upper:]' '[:lower:]')" ];
	then
		echo "Live environment version test passed."
	else
		##The zfs pool will be created with the zfs version of the live environment.
		##If the zfs version is older in the distro to be installed than in the live environment then zfsbootmenu may be unable to mount the root pool at boot.
		##The system will then fail to load. The reason is that Zfsbootmenu is installed with the zfs version in the distro to be installed, not the version in the live environment.
		echo "Live environment version test failed."
		echo "The live environment version does not match the Ubuntu version to be installed. Re-run script from an environment which matches the version to be installed. This is to avoid zfs version conflicts."
		exit 1
	fi

}

keyboard_console_settings(){
	kb_console_settings=/tmp/kb_console_selections.conf
	
	apt install -y debconf-utils
	
	export DEBIAN_PRIORITY=high
	export DEBIAN_FRONTEND=dialog
	dpkg-reconfigure keyboard-configuration
	dpkg-reconfigure console-setup
	export DEBIAN_"${install_warning_level}"
	
	debconf-get-selections | grep keyboard-configuration | tee "${kb_console_settings}"
	debconf-get-selections | grep console-setup | tee -a "${kb_console_settings}"
}

topology_min_disk_check(){
	##Check that number of disks meets minimum number for selected topology. Disks_{root,data} variable ignored for single topology.
	pool="$1"
	echo "Checking script variables for $pool pool..."
	
	topology_pool_pointer="topology_$pool"
	eval echo "User defined topology for ${pool} pool: \$${topology_pool_pointer}"
	eval topology_pool_pointer="\$${topology_pool_pointer}"
	topology_pool_pointer_tmp="/tmp/topology_pool_pointer.txt"
	printf "%s" "${topology_pool_pointer}" > "${topology_pool_pointer_tmp}"
	
	disks_pointer="disks_${pool}"
	eval echo "User defined number of disks in pool: \$${disks_pointer}"
	eval disks_pointer=\$"${disks_pointer}"
	disks_pointer_tmp="/tmp/disks_pointer.txt"
	printf "%s" "${disks_pointer}" > "${disks_pointer_tmp}"

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

identify_apt_data_sources(){

	if [ -f /etc/apt/sources.list.d/ubuntu.sources ];
	then
		apt_data_sources_loc="/etc/apt/sources.list.d/ubuntu.sources"
	else
		apt_data_sources_loc="/etc/apt/sources.list"
	fi

}

apt_sources(){
	##Initial system apt sources config
	script_env="$1" ##chroot, base
	source_archive="$2"
	
	cat > /tmp/apt_sources.sh <<-EOF
		#!/bin/sh
		if [ -f /etc/apt/sources.list.d/ubuntu.sources ];
		then
			apt_data_sources_loc="/etc/apt/sources.list.d/ubuntu.sources"
			cp "\${apt_data_sources_loc}" "\${apt_data_sources_loc}".orig
			if [ "${ubuntu_original}" != "${source_archive}" ];
			then
				sed -i 's,${ubuntu_original},${source_archive},g' "\${apt_data_sources_loc}"
			else true
			fi
		else
			apt_data_sources_loc="/etc/apt/sources.list"
			cp "\${apt_data_sources_loc}" "\${apt_data_sources_loc}".orig
			
			cat > "\${apt_data_sources_loc}" <<-EOLIST
				deb ${ubuntu_original} $ubuntuver main universe restricted multiverse
				#deb-src ${ubuntu_original} $ubuntuver main universe restricted multiverse
				
				deb ${ubuntu_original} $ubuntuver-updates main universe restricted multiverse
				#deb-src ${ubuntu_original} $ubuntuver-updates main universe restricted multiverse
				
				deb ${ubuntu_original} $ubuntuver-backports main universe restricted multiverse
				#deb-src ${ubuntu_original} $ubuntuver-backports main universe restricted multiverse
				
				deb http://security.ubuntu.com/ubuntu $ubuntuver-security main universe restricted multiverse
				#deb-src http://security.ubuntu.com/ubuntu $ubuntuver-security main universe restricted multiverse
			EOLIST
			
			if [ "${ubuntu_original}" != "${source_archive}" ];
			then
				cp "\${apt_data_sources_loc}" "\${apt_data_sources_loc}".non-mirror
				sed -i 's,${ubuntu_original},${source_archive},g' "\${apt_data_sources_loc}"
			else true
			fi
			
		fi
	EOF

	case "${script_env}" in
	chroot)
		cp /tmp/apt_sources.sh "$mountpoint"/tmp
		chroot "$mountpoint" /bin/bash -x /tmp/apt_sources.sh
	;;
	base)
		/bin/bash /tmp/apt_sources.sh
	;;
	*)
		exit 1
	;;
	esac

}

apt_mirror_source(){
	
	identify_apt_data_sources
	
	identify_apt_mirror(){
		##Identify fastest mirror.
		echo "Choosing fastest up-to-date ubuntu mirror based on download speed."
		apt update
		apt install -y curl
		ubuntu_mirror=$({
		##Choose mirrors that are up-to-date by checking the Last-Modified header.
		##https://github.com/actions/runner-images/issues/675#issuecomment-1381837292
		{
		curl -s http://mirrors.ubuntu.com/"${mirror_archive}".txt | shuf -n 20
		} | xargs -I {} sh -c 'echo "$(curl -m 5 -sI {}dists/$(lsb_release -c | cut -f2)-security/Contents-$(dpkg --print-architecture).gz | sed s/\\r\$//|grep Last-Modified|awk -F": " "{ print \$2 }" | LANG=C date -f- -u +%s)" "{}"' | sort -rg | awk '{ if (NR==1) TS=$1; if ($1 == TS) print $2 }'
		} | xargs -I {} sh -c 'echo "$(curl -r 0-102400 -m 5 -s -w %{speed_download} -o /dev/null {}ls-lR.gz)" {}' \
		| sort -g -r | tee /tmp/mirrors_speed.txt | head -1 | awk '{ print $2  }')
	}
	identify_apt_mirror

	if [ -z "${ubuntu_mirror}" ];
	then
		echo "No mirror identified. No changes made."
	else
		if [ "${ubuntu_original}" != "${ubuntu_mirror}" ];
		then
			cp "${apt_data_sources_loc}" "${apt_data_sources_loc}".non-mirror
			sed -i "s,${ubuntu_original},${ubuntu_mirror},g" "${apt_data_sources_loc}"
			echo "Selected '${ubuntu_mirror}'."
		else
			echo "Identified mirror is already selected. No changes made."
		fi
	fi

}

reinstate_apt(){
	script_env="$1" ##chroot, base
	
	cat > /tmp/reinstate_apt.sh <<-EOF
		
		#!/bin/sh
		if [ -n "${mirror_archive}" ];
		then
			
			if [ -f /etc/apt/sources.list.d/ubuntu.sources ];
			then
				apt_data_sources_loc="/etc/apt/sources.list.d/ubuntu.sources"
			else
				apt_data_sources_loc="/etc/apt/sources.list"
			fi
			
			cp "\${apt_data_sources_loc}" /tmp
						
			if [ -f "\${apt_data_sources_loc}".non-mirror ];
			then
				cp "\${apt_data_sources_loc}".non-mirror /tmp
				mv "\${apt_data_sources_loc}".non-mirror "\${apt_data_sources_loc}"
			else true
			fi
	
		else true
		fi

		if [ -f /etc/apt/apt.conf.d/30apt_error_on_transient ];
		then
			mv /etc/apt/apt.conf.d/30apt_error_on_transient /tmp ##Remove apt update error on transient in new install.
		else true
		fi

	EOF

	case "${script_env}" in
	chroot)
		cp /tmp/reinstate_apt.sh "$mountpoint"/tmp
		chroot "$mountpoint" /bin/bash -x /tmp/reinstate_apt.sh
	;;
	base)
		/bin/bash /tmp/reinstate_apt.sh
	;;
	*)
		exit 1
	;;
	esac

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

create_zpool_Func(){
		
	##Create zfs pool
	pool=$1 ##root, data
	
	##Set pool variables
	case "$pool" in
	root)
		ashift="$zfs_rpool_ashift"
		keylocation="prompt"
		zpool_password="$zfs_root_password"
		zpool_encrypt="$zfs_root_encrypt"
		zpool_partition="-part3"
		zpool_name="$RPOOL"
		topology_pool="${topology_root}"
	;;
	
	data)
		ashift="$zfs_dpool_ashift"
		
		if [ -n "$zfs_root_password" ];
		then
			##Set data pool key to use rpool key for single unlock at boot. So data pool uses the same password as the root pool.
			case "$zfs_root_encrypt" in
				native)
					datapool_keyloc="/etc/zfs/$RPOOL.key"
				;;
				luks)
					datapool_keyloc="/etc/cryptsetup-keys.d/$RPOOL.key"
				;;
			esac
			keylocation="file://$datapool_keyloc"
		else
			if [ -n "$zfs_data_password" ];
			then
				keylocation="prompt"
			else
				true
			fi
		fi
		
		zpool_password="$zfs_data_password"
		zpool_encrypt="$zfs_data_encrypt"
		zpool_partition=""
		zpool_name="$datapool"
		topology_pool="${topology_data}"
	;;
	esac
	
	zpool_create_temp="/tmp/${pool}_creation.sh"
	cat > "$zpool_create_temp" <<-EOF
		zpool create -f \\
			-o ashift="$ashift" \\
			-o autotrim=on \\
			-O acltype=posixacl \\
			-O compression=$zfs_compression \\
			-O normalization=formD \\
			-O relatime=on \\
			-O dnodesize=auto \\
			-O xattr=sa \\
	EOF

	case "$pool" in
	root)
		echo -O canmount=off \\ >> "$zpool_create_temp"
	;;
	esac

	if [ -n "$zpool_password" ];
	then
		case "$zpool_encrypt" in
			native)
				echo "-O encryption=aes-256-gcm -O keylocation=$keylocation -O keyformat=passphrase \\" >> "$zpool_create_temp"
			;;
		esac
	else
		true
	fi	
	
	case "$pool" in
	root)
		echo "-O mountpoint=/ -R $mountpoint \\" >> "$zpool_create_temp"
	;;
	data)
		echo "-O mountpoint=$datapoolmount \\" >> "$zpool_create_temp"
	;;
	esac


	add_zpool_disks(){
		
		loop_counter="$(mktemp)"
		echo 1 > "$loop_counter" ##Assign starting counter value.
		
		while IFS= read -r diskidnum;
		do
			if [ -n "$zpool_password" ];
			then
				
				case "$zpool_encrypt" in
				
					native)
						echo "/dev/disk/by-id/${diskidnum}${zpool_partition} \\" >> "$zpool_create_temp"
					;;

					luks)
						echo -e "$zpool_password" | cryptsetup -q luksFormat -c aes-xts-plain64 -s 512 -h sha256 /dev/disk/by-id/${diskidnum}${zpool_partition}
						
						i="$(cat "$loop_counter")"
						echo "$i"
						luks_dmname_base=luks
						luks_dmname=${luks_dmname_base}$i
						
						##Check for luks device name conflict
						while [ "$(find /dev/mapper -name ${luks_dmname} | wc -l)" = 1 ];
						do
							i=$((i + 1)) ##Increment counter.
							luks_dmname=${luks_dmname_base}$i
						done
						
						echo -e "$zpool_password" | cryptsetup luksOpen /dev/disk/by-id/${diskidnum}${zpool_partition} "${luks_dmname}"
						printf "%s\n" "${luks_dmname}" >> /tmp/luks_dmname_"${pool}".txt
						
						echo "/dev/mapper/${luks_dmname} \\" >> "$zpool_create_temp"
						
						i=$((i + 1)) ##Increment counter.
						echo "$i" > "$loop_counter"
					;;

					*)
						echo "zpool_encrypt variable not recognised."
						exit 1
					;;
				
				esac
		
			else
				echo "/dev/disk/by-id/${diskidnum}${zpool_partition} \\" >> "$zpool_create_temp"
			fi
		
		done < /tmp/diskid_check_"$pool".txt
	
		sed -i '$s,\\,,' "$zpool_create_temp" ##Remove escape character at end of file.
	}


	case "${topology_pool}" in
		single|raid0)
			echo "${zpool_name} \\" >> "$zpool_create_temp"	
			add_zpool_disks
		;;

		mirror)
			echo "${zpool_name} mirror \\" >> "$zpool_create_temp"
			add_zpool_disks
		;;
		
		raidz1)
			echo "${zpool_name} raidz1 \\" >> "$zpool_create_temp"
			add_zpool_disks	
		;;

		raidz2)
			echo "${zpool_name} raidz2 \\" >> "$zpool_create_temp"
			add_zpool_disks	
		;;

		raidz3)
			echo "${zpool_name} raidz3 \\" >> "$zpool_create_temp"
			add_zpool_disks	
		;;

		*)
			echo "Pool topology not recognised. Check pool topology variable."
			exit 1
		;;

	esac
	
	echo "$zpool_password" | sh "$zpool_create_temp" 
}

update_crypttab_Func(){
	##Auto unlock using crypttab and keyfile
	
	script_env=$1 ##chroot, base
	pool=$2 ##root, data	
		
	cat <<-EOH >/tmp/update_crypttab_$pool.sh
		
		##Set pool variables
		case "$pool" in
		root)
			zpool_password="$zfs_root_password"
			zpool_partition="-part3"
			crypttab_parameters="luks,discard,initramfs"
		;;
		
		data)
			zpool_password="$zfs_data_password"
			zpool_partition=""
			crypttab_parameters="luks,discard"
		;;
		esac
		
		apt install -y cryptsetup
							
		loop_counter="\$(mktemp)"
		echo 1 > "\${loop_counter}" ##Assign starting counter value.
		
		while IFS= read -r diskidnum;
		do
			i="\$(cat "\$loop_counter")"
			echo "\$i"
			luks_dmname="\$(sed "\${i}q;d" /tmp/luks_dmname_"${pool}".txt)"
			
			blkid_luks="\$(blkid -s UUID -o value /dev/disk/by-id/\${diskidnum}\${zpool_partition})"
			
			echo "\${zpool_password}" | cryptsetup -v luksAddKey /dev/disk/by-uuid/\${blkid_luks} /etc/cryptsetup-keys.d/$RPOOL.key
			cryptsetup luksDump /dev/disk/by-uuid/\${blkid_luks}
			
			##https://cryptsetup-team.pages.debian.net/cryptsetup/README.initramfs.html
			echo \${luks_dmname} UUID=\${blkid_luks} /etc/cryptsetup-keys.d/$RPOOL.key \${crypttab_parameters} >> /etc/crypttab
			
			i=\$((i + 1)) ##Increment counter.
			echo "\$i" > "\$loop_counter"
			
		done < /tmp/diskid_check_"${pool}".txt
		
		##https://cryptsetup-team.pages.debian.net/cryptsetup/README.initramfs.html
		sed -i 's,#KEYFILE_PATTERN=,KEYFILE_PATTERN="/etc/cryptsetup-keys.d/*.key",' /etc/cryptsetup-initramfs/conf-hook

	EOH

	case "${script_env}" in
	chroot)
		cp /tmp/diskid_check_"${pool}".txt "$mountpoint"/tmp
		cp /tmp/update_crypttab_${pool}.sh "$mountpoint"/tmp
		chroot "$mountpoint" /bin/bash -x /tmp/update_crypttab_$pool.sh
	;;
	base)
		##Test for live environment.
		if grep casper /proc/cmdline >/dev/null 2>&1;
		then
			echo "Live environment present. Reboot into new installation."
			exit 1
		else	
			/bin/bash /tmp/update_crypttab_$pool.sh
		fi
	;;
	*)
		exit 1
	;;
	esac

}

debootstrap_part1_Func(){
	export DEBIAN_"${install_warning_level}"
	
	##Error out script on apt update error such as network failure during package download.
	##https://bugs.launchpad.net/ubuntu/+source/apt/+bug/1693900
	cat > /etc/apt/apt.conf.d/30apt_error_on_transient <<-EOF
		APT::Update::Error-Mode "any";
	EOF
	
	##Identify apt sources
	identify_apt_data_sources
	
	##Identify live iso default archive
	#ubuntu_original="$(grep -v '^ *#\|security\|cdrom\|.*gpg' "${apt_data_sources_loc}" | sed '/^[[:space:]]*$/d' | awk '{ print $2 }' | sort -u | grep ubuntu)"
	
	apt_sources "base" "${ubuntu_original}"
	
	if [ -n "${mirror_archive}" ];
	then
		apt_mirror_source
	else
		true
	fi
	
	cat "${apt_data_sources_loc}"
	#sed -i 's,deb http://security,#deb http://security,' "${apt_data_sources_loc}" ##Uncomment to resolve security pocket time out. Security packages are copied to the other pockets frequently, so should still be available for update. See https://wiki.ubuntu.com/SecurityTeam/FAQ
	
	trap 'printf "%s\n%s" "The script has experienced an error during the first apt update. That may have been caused by a queried server not responding in time. Try running the script again." "If the issue is the security server not responding, then comment out the security server in the "${apt_data_sources_loc}". Alternatively, you can uncomment the command that does this in the install script. This affects the temporary live iso only. Not the permanent installation."' ERR
	apt update
	trap - ERR	##Resets the trap to doing nothing when the script experiences an error. The script will still exit on error if "set -e" is set.

	keyboard_console_settings #Request keyboard and console settings.

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
	partprobe
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
		##8309 Linux LUKS
		##FD00 Linux RAID

		case "$topology_root" in
			single|mirror)
				swap_hex_code="8200"
			;;

			raid0|raidz*)
				swap_hex_code="FD00"
			;;

			*)
				echo "topology_root variable not recognised."
				exit 1
			;;
		esac
		
		if [ -n "$zfs_root_password" ];
		then
			case "$zfs_root_encrypt" in
				native)
					root_hex_code="BF00" ##ZFS native encryption
				;;

				luks)
					root_hex_code="FD00" ##luks
				;;

				*)
					echo "zfs_root_encrypt variable not recognised."
					exit 1
				;;
			esac
		else
			root_hex_code="BF00" ##unencrypted ZFS
		fi
		
		while IFS= read -r diskidnum;
		do
			echo "Creating partitions on disk ${diskidnum}."
			##2.3 create bootloader partition
			sgdisk -n1:1M:+"${EFI_boot_size}"M -t1:EF00 /dev/disk/by-id/"${diskidnum}"
		
			##2.4 create swap partition 
			##bug with swap on zfs zvol so use swap on partition:
			##https://github.com/zfsonlinux/zfs/issues/7734
			##hibernate needs swap at least same size as RAM
			##hibernate only works with unencrypted installs
			sgdisk -n2:0:+"${swap_size}"M -t2:"${swap_hex_code}" /dev/disk/by-id/"${diskidnum}"
		
			##2.6 Create root pool partition
			sgdisk     -n3:0:0      -t3:"${root_hex_code}" /dev/disk/by-id/"${diskidnum}"
		
		done < /tmp/diskid_check_"${pool}".txt
		partprobe
		sleep 2
	}
	partitionsFunc
}

debootstrap_createzfspools_Func(){

	##Create root pool
	create_zpool_Func root
	
	##System installation
	mountpointsFunc(){

		##zfsbootmenu setup for no separate boot pool
		##https://github.com/zbm-dev/zfsbootmenu/wiki/Debian-Buster-installation-with-ESP-on-the-zpool-disk
		
		partprobe
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

zfsbootmenu_install_config_Func(){
	zfsbootmenu_install_config_loc="/tmp/zfsbootmenu_install_config.sh"
	cat <<-EOH >"${zfsbootmenu_install_config_loc}"
		#!/bin/bash
		set -euo pipefail
		set -x
		apt update

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
			apt-get install --yes --no-install-recommends \\
				libsort-versions-perl \\
				libboolean-perl \\
				libyaml-pp-perl \\
				git \\
				fzf \\
				make \\
				kexec-tools \\
				dracut-core \\
				fzf \\
				cpio

			apt-get install --yes curl
			
			mkdir -p /usr/local/src/zfsbootmenu
			cd /usr/local/src/zfsbootmenu

			##Download zfsbootmenu
			zbm_release="git" ##"git" for git master. "release" for latest release.

			case "\${zbm_release}" in
			git)

				##Download the latest zfsbootmenu git master
				git clone https://github.com/zbm-dev/zfsbootmenu .

			;;

			release)

				##Download the latest zbm release
				#latest_zbm_source="https://get.zfsbootmenu.org/source" #Source code from zfsbootmenu website.

				use_yq="no"
				case "\${use_yq}" in
				yes)
					##https://github.com/mikefarah/yq
					wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && chmod +x /usr/bin/yq

					latest_zbm_source="\$(curl -s https://api.github.com/repos/zbm-dev/zfsbootmenu/releases/latest | yq '.tarball_url')"
				;;
				no)
					latest_zbm_source="\$(curl -s https://api.github.com/repos/zbm-dev/zfsbootmenu/releases/latest | grep tarball | cut -d : -f 2,3 | tr -d \"|sed 's/^[ \t]*//'|sed 's/,//')"
				;;
				esac

				curl -L "\${latest_zbm_source-default}" | tar -zxv --strip-components=1 -f -

			;;

			*)
				echo "Zfsbootmenu release version not recognised."
				exit 1
			;;

			esac

			make core dracut ##"make install" installs mkinitcpio, not needed.

		}
		compile_zbm_git

		##configure zfsbootmenu
		config_zbm(){
			
			kb_layoutcode="\$(debconf-get-selections | grep keyboard-configuration/layoutcode | awk '{print \$4}')"
			
			##https://github.com/zbm-dev/zfsbootmenu/blob/master/testing/helpers/configure-ubuntu.sh
			##Update configuration file
			sed \\
			-e 's,ManageImages:.*,ManageImages: true,' \\
			-e 's@ImageDir:.*@ImageDir: /boot/efi/EFI/ubuntu@' \\
			-e 's,Versions:.*,Versions: false,' \\
			-e "/CommandLine/s,ro,rd.vconsole.keymap=\${kb_layoutcode} ro," \\
			-i /etc/zfsbootmenu/config.yaml

			if [ "$quiet_boot" = "no" ]; then
				sed -i 's,ro quiet,ro,' /etc/zfsbootmenu/config.yaml
			fi
			
			if [ -n "$zfs_root_password" ];
			then
				case "$zfs_root_encrypt" in
					luks)
						##https://github.com/agorgl/zbm-luks-unlock
						zfsbootmenu_hook_root=/etc/zfsbootmenu/hooks ##https://docs.zfsbootmenu.org/en/v2.3.x/man/zfsbootmenu.7.html
						
						mkdir -p \${zfsbootmenu_hook_root}/early-setup.d
						cd \${zfsbootmenu_hook_root}/early-setup.d
						curl -L -O https://raw.githubusercontent.com/agorgl/zbm-luks-unlock/master/hooks/early-setup.d/luks-unlock.sh
						chmod +x \${zfsbootmenu_hook_root}/early-setup.d/luks-unlock.sh
						
						#mkdir -p \${zfsbootmenu_hook_root}/boot-sel.d
						#cd \${zfsbootmenu_hook_root}/boot-sel.d
						#curl -L -O https://raw.githubusercontent.com/agorgl/zbm-luks-unlock/master/hooks/boot-sel.d/initramfs-inject.sh
						#chmod +x \${zfsbootmenu_hook_root}/early-setup.d/initramfs-inject.sh
						
						cd /etc/zfsbootmenu/dracut.conf.d/
						curl -L -O https://raw.githubusercontent.com/agorgl/zbm-luks-unlock/master/dracut.conf.d/99-crypt.conf
					;;
				esac
			else
				true
			fi	
			
			
		}
		config_zbm

		update-initramfs -c -k all
		generate-zbm --debug

	EOH

	case "$1" in
	chroot)
		cp "${zfsbootmenu_install_config_loc}" "$mountpoint"/tmp
		chroot "$mountpoint" /bin/bash -x "${zfsbootmenu_install_config_loc}"
	;;
	base)
		/bin/bash "${zfsbootmenu_install_config_loc}"
	;;
	*)
		exit 1
	;;
	esac

}

remote_zbm_access_Func(){
	modulesetup="/usr/lib/dracut/modules.d/60crypt-ssh/module-setup.sh"
	cat <<-EOH >/tmp/remote_zbm_access.sh
		#!/bin/sh
		##Configure SSH server in Dracut
		##https://github.com/zbm-dev/zfsbootmenu/wiki/Remote-Access-to-ZBM
		apt update
		apt install -y dracut-network dropbear
		apt install -y isc-dhcp-client

		config_dracut_crypt_ssh_module(){
			git -C /tmp clone 'https://github.com/dracut-crypt-ssh/dracut-crypt-ssh.git'
			mkdir /usr/lib/dracut/modules.d/60crypt-ssh
			cp /tmp/dracut-crypt-ssh/modules/60crypt-ssh/* /usr/lib/dracut/modules.d/60crypt-ssh/
			rm /usr/lib/dracut/modules.d/60crypt-ssh/Makefile
			
			##Comment out references to /helper/ folder in module-setup.sh. Components not required for ZFSBootMenu.
			sed -i \\
				-e 's,  inst "\$moddir"/helper/console_auth /bin/console_auth,  #inst "\$moddir"/helper/console_auth /bin/console_auth,' \\
				-e 's,  inst "\$moddir"/helper/console_peek.sh /bin/console_peek,  #inst "\$moddir"/helper/console_peek.sh /bin/console_peek,' \\
				-e 's,  inst "\$moddir"/helper/unlock /bin/unlock,  #inst "\$moddir"/helper/unlock /bin/unlock,' \\
				-e 's,  inst "\$moddir"/helper/unlock-reap-success.sh /sbin/unlock-reap-success,  #inst "\$moddir"/helper/unlock-reap-success.sh /sbin/unlock-reap-success,' \\
				"$modulesetup"
		}
		config_dracut_crypt_ssh_module
		
		setup_dracut_network(){
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
		}
		setup_dracut_network

		add_welcome_message(){
			##add remote session welcome message
			cat <<-EOF >/etc/zfsbootmenu/dracut.conf.d/banner.txt
				Welcome to the ZFSBootMenu initramfs shell. Enter "zfsbootmenu" or "zbm" to start ZFSBootMenu.
			EOF
			chmod 755 /etc/zfsbootmenu/dracut.conf.d/banner.txt
			
			sed -i 's,  /sbin/dropbear -s -j -k -p \${dropbear_port} -P /tmp/dropbear.pid,  /sbin/dropbear -s -j -k -p \${dropbear_port} -P /tmp/dropbear.pid -b /etc/banner.txt,' /usr/lib/dracut/modules.d/60crypt-ssh/dropbear-start.sh
			
			##Copy files into initramfs
			sed -i '$ s,^},,' "$modulesetup"
			echo "  ##Copy dropbear welcome message" | tee -a "$modulesetup"
			echo "  inst /etc/zfsbootmenu/dracut.conf.d/banner.txt /etc/banner.txt" | tee -a "$modulesetup"
			echo "}" | tee -a "$modulesetup"
		}
		add_welcome_message
		
		create_host_keys(){
			##create host keys
			mkdir -p /etc/dropbear
			for keytype in rsa ecdsa ed25519; do
				#dropbearkey -t "\${keytype}" -f "/etc/dropbear/ssh_host_\${keytype}_key"
				ssh-keygen -t "\${keytype}" -m PEM -f "/etc/dropbear/ssh_host_\${keytype}_key" -N ""
				##-t key type
				##-m key format
				##-f filename
				##-N passphrase
			done
		}
		create_host_keys
		
		##Set ownership of initramfs authorized_keys
		sed -i '/inst "\${dropbear_acl}"/a \\  chown root:root "\${initdir}/root/.ssh/authorized_keys"' "$modulesetup"
		
		config_dropbear(){
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
				dropbear_ed25519_key="/etc/dropbear/ssh_host_ed25519_key"
				
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
		
			systemctl stop dropbear
			systemctl disable dropbear
		}
		config_dropbear
		
		##Increase ZFSBootMenu timer to allow for remote connection
		sed -i 's,zbm.timeout=$timeout_zbm_no_remote_access,zbm.timeout=$timeout_zbm_remote_access,' /boot/efi/EFI/ubuntu/refind_linux.conf

		generate-zbm --debug

	EOH

	case "$1" in
	chroot)
		cp /tmp/remote_zbm_access.sh "$mountpoint"/tmp
		chroot "$mountpoint" /bin/bash -x /tmp/remote_zbm_access.sh
	;;
	base)
		##Test for live environment.
		if grep casper /proc/cmdline >/dev/null 2>&1;
		then
			echo "Live environment present. Reboot into new installation to install remoteaccess."
			exit 1
		else	
			/bin/bash /tmp/remote_zbm_access.sh

			sed -i 's,#dropbear_acl,dropbear_acl,' /etc/zfsbootmenu/dracut.conf.d/dropbear.conf
			mkdir -p /home/"$user"/.ssh
			chown "$user":"$user" /home/"$user"/.ssh
			touch /home/"$user"/.ssh/authorized_keys
			chmod 644 /home/"$user"/.ssh/authorized_keys
			chown "$user":"$user" /home/"$user"/.ssh/authorized_keys
			#hostname -I
			echo "Zfsbootmenu remote access installed. Connect as root on port 222 during boot: \"ssh root@{IP_ADDRESS or FQDN of zfsbootmenu} -p 222\""
			echo "Your SSH public key must be placed in \"/home/$user/.ssh/authorized_keys\" prior to reboot or remote access will not work."
			echo "You can add your remote user key using the following command from the remote user's terminal if openssh-server is active on the host."
			echo "\"ssh-copy-id -i $user@{IP_ADDRESS or FQDN of the server}\""
			echo "Run \"sudo generate-zbm\" after copying across the remote user's public ssh key into the authorized_keys file."
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

	##Error out script on apt update error such as network failure during package download.
	cp /etc/apt/apt.conf.d/30apt_error_on_transient "$mountpoint"/etc/apt/apt.conf.d/

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
	##https://netplan.readthedocs.io/en/stable/reference/
	chmod 600 "$mountpoint"/etc/netplan/01-"$ethernetinterface".yaml

	##Bind virtual filesystems from LiveCD to new system
	mount --rbind /dev  "$mountpoint"/dev
	mount --rbind /proc "$mountpoint"/proc
	mount --rbind /sys  "$mountpoint"/sys 

	##Configure package sources
	if [ -n "${mirror_archive}" ];
	then
		apt_sources "chroot" "${ubuntu_mirror}"
	else
		apt_sources "chroot" "${ubuntu_original}"
	fi

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
		fi

		echo "Creating FAT32 filesystem in EFI partition of disk ${diskidnum}. ESP mountpoint is ${esp_mount}"
		umount -q /dev/disk/by-id/"${diskidnum}"-part1 || true
		mkdosfs -F 32 -s 1 -n EFI /dev/disk/by-id/"${diskidnum}"-part1
		partprobe
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

	initial_boot_order="$(efibootmgr | grep "BootOrder" | cut -d " " -f 2)" ##Initial boot order before refind installed.

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

	cp /tmp/diskid_check_"${pool}".txt "$mountpoint"/tmp/
	
	if [ -f /tmp/luks_dmname_"${pool}".txt ];
	then
		cp /tmp/luks_dmname_"${pool}".txt "$mountpoint"/tmp/
	else true
	fi
	
	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		encrypt_config(){
			if [ -n "$zfs_root_password" ];
			then
				case "$zfs_root_encrypt" in
					native)
						##Convert rpool to use keyfile.
						echo $zfs_root_password > /etc/zfs/$RPOOL.key ##This file will live inside your initramfs stored on the ZFS boot environment.
						chmod 600 /etc/zfs/$RPOOL.key ##Set access rights to keyfile. 
						
						zfs change-key -o keylocation=file:///etc/zfs/$RPOOL.key -o keyformat=passphrase $RPOOL
						
						##Setup key caching in zfsbootmenu
						zfs set org.zfsbootmenu:keysource="$RPOOL/ROOT" $RPOOL
					;;
					luks)
						##https://askubuntu.com/questions/996155/how-do-i-automatically-decrypt-an-encrypted-filesystem-on-the-next-reboot
						
						mkdir -p /etc/cryptsetup-keys.d/
						dd if=/dev/urandom of=/etc/cryptsetup-keys.d/$RPOOL.key bs=1024 count=4
						chmod 600 /etc/cryptsetup-keys.d/$RPOOL.key ##Set access rights to keyfile.
						
					;;
				esac
				
			else
				true
			fi
			
			echo "UMASK=0077" > /etc/initramfs-tools/conf.d/umask.conf ##Set access rights for initramfs images generated by mkinitramfs.				
		
		}
		encrypt_config			
	EOCHROOT

	##Update crypttab if luks used
	if [ "$zfs_root_encrypt" = "luks" ];
	then
		update_crypttab_Func "chroot" "root"
	else true
	fi

	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT					
			if [ "$quiet_boot" = "yes" ]; then
				zfs set org.zfsbootmenu:commandline="spl_hostid=\$( hostid ) ro quiet" "$RPOOL"/ROOT
			else
				zfs set org.zfsbootmenu:commandline="spl_hostid=\$( hostid ) ro" "$RPOOL"/ROOT
			fi
	EOCHROOT

	zfsbootmenu_install_config_Func "chroot"

	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##Update refind_linux.conf
		config_refind(){
			##zfsbootmenu command-line parameters:
			##https://github.com/zbm-dev/zfsbootmenu/blob/master/pod/zfsbootmenu.7.pod
			cat <<-EOF > /boot/efi/EFI/ubuntu/refind_linux.conf
				"Boot default"  "zbm.timeout=$timeout_zbm_no_remote_access ro quiet loglevel=0"
				"Boot to menu"  "zbm.show ro quiet loglevel=0"
			EOF

			if [ "$quiet_boot" = "no" ]; then
				sed -i 's,ro quiet,ro,' /boot/efi/EFI/ubuntu/refind_linux.conf
			fi
		}
		config_refind
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
			##Each boot entry in efibootmgr is identified by a boot number in hexadecimal.
			primary_esp_hex="$(efibootmgr | grep -v "Backup" | grep -w "rEFInd Boot Manager" | cut -d " " -f 1 | sed 's,Boot,,' | sed 's,*,,')"
			primary_esp_dec="$(printf "%d" 0x"${primary_esp_hex}")"
			num_disks="$(wc -l /tmp/diskid_check_"${pool}".txt | awk '{ print $1 }')"
			esp_loop_exit_dec="$(( "${primary_esp_dec}" + "${num_disks}" ))"

			i="${primary_esp_dec}"
			while [ "$i" -ne "${esp_loop_exit_dec}" ]
			do
				if [ "$i" -eq "$primary_esp_dec" ];
				then
					echo "${primary_esp_hex}," > /tmp/revised_boot_order.txt
				else
					loop_counter_hex="$(printf "%04X" "$i")"
					sed -i "s/$/${loop_counter_hex},/g" /tmp/revised_boot_order.txt
				fi
				i=$((i + 1))
			done 
			sed -i "s/$/${initial_boot_order}/g" /tmp/revised_boot_order.txt
			revised_boot_order="$(cat /tmp/revised_boot_order.txt)"
			efibootmgr -o "${revised_boot_order}"
		}
		update_boot_manager
	}

	topology_pool_pointer="$(cat "/tmp/topology_pool_pointer.txt")"
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
				DISKID="$(cat /tmp/diskid_check_root.txt)"
				chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
					apt install --yes cryptsetup
					echo swap /dev/disk/by-id/"$DISKID"-part2 ${crypttab_parameters} >> /etc/crypttab
					echo /dev/mapper/swap none swap defaults 0 0 >> /etc/fstab
				EOCHROOT
			else
				blkid_part2=""
				DISKID="$(cat /tmp/diskid_check_root.txt)"
				chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
					mkswap -f /dev/disk/by-id/"$DISKID"-part2
					blkid_part2="\$(blkid -s UUID -o value /dev/disk/by-id/$DISKID-part2)"
					echo /dev/disk/by-uuid/\${blkid_part2} none swap defaults 0 0 >> /etc/fstab
					sleep 2
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

		##Disable root login with password. Login as root with SSH key is possible if configured.
		##https://help.ubuntu.com/community/RootSudo
		passwd -dl root
	
	EOCHROOT
}

distroinstall(){
	##Upgrade the minimal system
	
	##Configure package sources
	if [ -n "${mirror_archive}" ];
	then
		apt_mirror_source
	else
		true
	fi
	
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

}

NetworkManager_config(){
		
	##Update netplan config to use NetworkManager if installed. Otherwise will default to networkd.
	if [ "$(dpkg-query --show --showformat='${db:Status-Status}\n' "network-manager")" = "installed" ];
	then
		##Update netplan configuration for NetworkManager.
		ethernetinterface="$(basename "$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${ethprefix}*")")"
		rm /etc/netplan/01-"$ethernetinterface".yaml
		cat > /etc/netplan/01-NetworkManager.yaml <<-EOF
			network:
			  version: 2
			  renderer: NetworkManager
			  ethernets:
			    "$ethernetinterface":
			      dhcp4: true
		EOF
		chmod 600 /etc/netplan/01-NetworkManager.yaml
		
		##Disable systemd-networkd to prevent conflicts with NetworkManager.
		systemctl stop systemd-networkd.service
		systemctl disable systemd-networkd.service

		systemctl stop systemd-networkd.socket
		systemctl disable systemd-networkd.socket
		
		netplan apply
	else true
	fi
	
}

pyznapinstall(){
	##snapshot management
	
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
		pip install setuptools ##Setuptools not present in virtual environments created with venv. Need to install it.
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

sanoid_install(){
	##snapshot and replication management
	##https://github.com/jimsalterjrs/sanoid
	apt update
	apt install -y sanoid 
	
	##create config file
	##https://github.com/jimsalterjrs/sanoid/wiki/Sanoid
	##https://github.com/jimsalterjrs/sanoid/blob/master/sanoid.conf
	mkdir -p /etc/sanoid
	cat > /etc/sanoid/sanoid.conf <<-EOF
		[$RPOOL/ROOT]
			use_template = template_production
			recursive = yes
			process_children_only = yes #Do not snapshot the parent dataset $RPOOL/ROOT. The OS root dataset is a child dataset of $RPOOL/ROOT.
			
		#############################
		# templates below this line #
		#############################
		
		[template_production]
			##Number of sub-hourly backups to be kept: 4 × 15-minute snapshots
			frequently = 4

			##Number of hourly backups to be kept: 24 x One hour snapshots
			hourly = 24

			##Then one per day for a week, one per week for a month, and one per month for six months.
			daily = 7
			weekly = 4
			monthly = 6
			yearly = 0

			autosnap = yes #Sets whether snapshots should be taken automatically
			autoprune = yes #Should old snapshots be pruned
			
	EOF
	
	pre-apt-snapshot(){
		##Integrate with apt to take a snapshot before system change. Don't need to use. Can rely on sanoid time based snapshots instead.
		##Immediate snapshotting not supported with sanoid.
		##https://github.com/jimsalterjrs/sanoid/issues/108
		
		##Approach below relies on "zfs snapshot" with a defined prefix. A systemd timer prunes the snapshots as they won't be managed by sanoid.
		pre_apt_prefix="pre-apt"
		
		cat > /etc/apt/apt.conf.d/80-zfs-snapshot <<-EOF
			
			DPkg::Pre-Invoke { "echo 'Creating ZFS snapshot.'; ts=${pre_apt_prefix}_\$(date +%F_%H:%M:%S); zfs snapshot -r $RPOOL/ROOT@\${ts} && zfs destroy $RPOOL/ROOT@\${ts} || true"; };

		EOF
		
		cat > /usr/local/bin/apt-snapshot-prune.sh <<-EOF
			#!/bin/sh
			##Prune all ZFS snapshots containing ${pre_apt_prefix} that are older than 7 days.

			##Find all snapshots with ${pre_apt_prefix} in the name.
			zfs list -H -p -o name,creation -t snapshot -r $(zpool list -H -o name) | grep '${pre_apt_prefix}' |
			while read name creation; 
			do
				age=\$(( \$(date +%s) - creation ))
				one_week=\$(( 7 * 24 * 3600 ))
				if [ \$age -gt \$one_week ]; then
					echo "Deleting old pre-apt snapshot: \$name (age: \$((age / 86400)) days)"
					zfs destroy "\$name"
				fi
			  done
		EOF
		chmod +x /usr/local/bin/apt-snapshot-prune.sh
		
		cat > /etc/systemd/system/apt-snapshot-prune.service <<-EOF
			[Unit]
			Description=Prune old ${pre_apt_prefix} ZFS snapshots

			[Service]
			Type=oneshot
			ExecStart=/usr/local/bin/apt-snapshot-prune.sh
			Nice=19 ##Set lowest system priority.
			IOSchedulingClass=3 ##Only run when disk is idle.
		EOF

		cat > /etc/systemd/system/apt-snapshot-prune.timer <<-EOF
			[Unit]
			Description=Daily cleanup of old ${pre_apt_prefix} ZFS snapshots
			Requires=apt-snapshot-prune.service

			[Timer]
			OnCalendar=daily
			Persistent=true
			Unit=apt-snapshot-prune.service

			[Install]
			WantedBy=timers.target
		EOF
		
	}
	pre-apt-snapshot
	
	/usr/sbin/sanoid --take-snapshots --verbose ##Take ZFS snapshots and perform cleanup as per config file.
	
	systemctl enable --now sanoid.timer
	
}

extra_programs(){

	case "$extra_programs" in
	yes)	
		##additional programs
		
		##install samba mount access
		apt install -yq cifs-utils
		
		##install openssh-server
		apt install -y openssh-server

		apt install --yes man-db tldr locate
			
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

keyboard_console_setup(){

	cp "${kb_console_settings}" "$mountpoint"/tmp
	
	chroot "$mountpoint" <<-EOCHROOT
		
		apt install -y debconf-utils
		cat "${kb_console_settings}"
		debconf-set-selections < "${kb_console_settings}"
		
		##https://serverfault.com/questions/539911/setting-debconf-selections-for-keyboard-configuration-fails-layout-ends-up-as
		##Delete the keyboard config file before running dpkg-reconfigure. Otherwise config file will not be updated and will stay as "us" default.
		rm /etc/default/keyboard
		
		dpkg-reconfigure -f noninteractive keyboard-configuration
		dpkg-reconfigure -f noninteractive console-setup

	EOCHROOT
}

fixfsmountorder(){

	identify_ubuntu_dataset_uuid

	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		##Fix filesystem mount ordering

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
		sleep 2
		
		##Fix the paths to eliminate $mountpoint:
		sed -Ei "s|$mountpoint/?|/|" /etc/zfs/zfs-list.cache/$RPOOL
		cat /etc/zfs/zfs-list.cache/$RPOOL
		#update-initramfs -u -k all ##Update zfs cache in initramfs

	EOCHROOT

}

unmount_datasets(){
	##https://unix.stackexchange.com/questions/120827/recursive-umount-after-rbind-mount/371208#371208
	##https://unix.stackexchange.com/a/120901
	mount --make-rslave  "$mountpoint"/dev
	mount --make-rslave "$mountpoint"/proc
	mount --make-rslave  "$mountpoint"/sys
	
	grep "$mountpoint" /proc/mounts | cut -f2 -d" " | sort -r | xargs umount -n
}

setupremoteaccess(){
	if [ -f /etc/zfsbootmenu/dracut.conf.d/dropbear.conf ];
	then echo "Remote access already appears to be installed owing to the presence of /etc/zfsbootmenu/dracut.conf.d/dropbear.conf. Install cancelled."
	else 
		disclaimer
		remote_zbm_access_Func "base"
	fi
}

createdatapool(){
	disclaimer
		
	##Check on whether data pool already exists
	if [ "$(zpool status "$datapool")" ];
	then
		echo "Warning: $datapool already exists. Are you use you want to wipe the drive and destroy $datapool? Press Enter to Continue or CTRL+C to abort."
		read -r _
	else
		echo "$datapool pre-existance check passed."
	fi
	
	##Warning on auto unlock
	if [ -n "$zfs_data_password" ];
	then
		echo "Warning: Encryption selected. If the root pool is also encrypted then the root pool keyfile will be used to auto unlock the data pool at boot. Press Enter to Continue or CTRL+C to abort."
		read -r _
	else true
	fi
	
	##Get datapool disk ID(s)
	getdiskID_pool "data"
	
	##Clear partition table
	clear_partition_table "data"
	partprobe
	sleep 2
	
	##Create pool mount point
	if [ -d "$datapoolmount" ]; then
		echo "Data pool mount point exists."
	else
		mkdir -p "$datapoolmount"
		chown "$user":"$user" "$datapoolmount"
		echo "Data pool mount point created."
	fi
	echo "$datapoolmount"
		
	##Automount with zfs-mount-generator
	touch /etc/zfs/zfs-list.cache/"$datapool"

	##Create data pool
	create_zpool_Func "data"
	
	##Update crypttab for autounlock if luks used on root pool
	if [ "$zfs_data_encrypt" = "luks" ];
	then
		if [ -f "/etc/cryptsetup-keys.d/$RPOOL.key" ];
		then
			update_crypttab_Func "base" "data"
		else
			echo "$RPOOL.key not found in /etc/cryptsetup-keys.d/."
			exit 1
		fi
	else true
	fi
	
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

reinstall-zbm(){
	
	isolate_generate_zbm_version(){
		##generate-zbm quits after printing version number. Isolate in a function to allow script to continue.
		set +e
		generate-zbm --showver > /tmp/zfs_installed_version.txt || echo "No version number reported by generate-zbm --showver." > /tmp/zfs_installed_version.txt
		set -e
	}
	
	disclaimer
	connectivity_check #Check for internet connectivity.
	
	##Live environment check.
	if grep casper /proc/cmdline >/dev/null 2>&1;
	then
		echo "Live environment present. Reboot into new installation to re-install zfsbootmenu."
		exit 1
	else
		true
	fi
	
	command -v generate-zbm >/dev/null 2>&1 || { echo >&2 "Please install zfsbootmenu before attempting to re-install. Exiting."; exit 1; } #Check for Zfsbootmenu.
	
	##Version check
	zbm_github_latest_version="$(curl -s https://api.github.com/repos/zbm-dev/zfsbootmenu/releases/latest | grep tag_name | cut -d : -f 2,3 | tr -d \"|sed 's/^[ \t]*//'|sed 's/,//'|sed 's,^v,,')"
	printf '%s%s\n' "Latest zfsbootmenu github release version: " "${zbm_github_latest_version}" 
	
	isolate_generate_zbm_version
	
	zbm_installed_version="$(cat /tmp/zfs_installed_version.txt)"
	printf '%s%s\n' "Installed zfsbootmenu version: " "${zbm_installed_version}" 
	if [ "${zbm_github_latest_version}" = "${zbm_installed_version}" ];
	then
		printf '%s\n' "Installed version of zfsbootmenu is the latest release. Enter Y to re-install or N to exit."
		read -r reinstall_selection
		case "${reinstall_selection-default}" in
		Y|y)
			echo "Re-installing zfsbootmenu."
			zfsbootmenu_install_config_Func "base"
		;;
		*)
			printf "%s\n" "Exiting."
			exit 0
		;;
		esac
	else
		zfsbootmenu_install_config_Func "base"
	fi
}

reinstall-pyznap(){

	if [ -f /etc/apt/apt.conf.d/80-zfs-snapshot ];
	then
		rm /etc/apt/apt.conf.d/80-zfs-snapshot
	else true
	fi

	if [ -f /usr/local/bin/pyznap ];
	then
		rm /usr/local/bin/pyznap
	else true
	fi

	if [ -d /opt/pyznap ];
	then
		rm -rf /opt/pyznap
	else true
	fi

	if [ -f /etc/pyznap/pyznap.conf ];
	then
		rm /etc/pyznap/pyznap.conf
	else true
	fi

	pyznapinstall

}

##--------
logFunc
date
update_date_time(){
	##Update time to correct out of date virtualbox clock when using snapshots for testing.
	timedatectl

	manual_set(){
		timedatectl set-ntp off
		sleep 1
		timedatectl set-time "2021-01-01 00:00:00"
	}
	#manual_set

	sync_ntp(){

		if systemctl is-active systemd-timesyncd
		then
			systemctl restart systemd-timesyncd.service
			systemctl status systemd-timesyncd.service
		else
			if systemctl is-active chrony
			then
				chronyc burst 4/4 #Requests up to 4 good measurements (and up to 4 total attempts) from all configured sources.
				sleep 5 ##Allow time for burst to complete.
				chronyc makestep #Update the system clock.
				
				##Check status
				chronyc tracking
				chronyc sources
			else true
			fi
		fi

	}
	sync_ntp
	
	timedatectl set-ntp false
	timedatectl set-ntp true
	sleep 10
	timedatectl
}
update_date_time

initialinstall(){
	
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
	
	keyboard_console_setup #Configure keyboard and console.
	systemsetupFunc_part4 #Install zfsbootmenu.
	systemsetupFunc_part5 #Config swap, tmpfs, rootpass.
	
	usersetup #Create user account and setup groups.
	logcompress #Disable log compression.
	reinstate_apt "chroot" #Reinstate non-mirror package sources in new install.
	script_copy #Copy script to new installation.
	fixfsmountorder #ZFS file system mount ordering.
	logcopy #Copy install log to new installation.
	
	#unmount_datasets #Unmount datasets.
	
	echo "Initial minimal system setup complete."
	echo "Reboot required to complete installation."
	echo "First login is ${user}:${PASSWORD-}"
	echo "Following reboot, run script with postreboot option to complete installation."
	echo "Reboot."
}

postreboot(){
	disclaimer
	connectivity_check #Check for internet connectivity.
	
	distroinstall #Upgrade the minimal system to the selected distro.
	NetworkManager_config #Adjust networking config for NetworkManager, if installed by distro.
	#pyznapinstall #Snapshot management.
	sanoid_install #Snapshot and replication management.
	extra_programs #Install extra programs.
	reinstate_apt "base" #Reinstate non-mirror package sources in new install.
	
	echo "Installation complete: ${distro_variant}."
	echo "Reboot."
}

case "${1-default}" in
	initial)
		echo "Running initial system installation. Press Enter to Continue or CTRL+C to abort."
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
	reinstall-zbm)
		echo "Re-installing zfsbootmenu. Press Enter to Continue or CTRL+C to abort."
		read -r _
		reinstall-zbm
	;;
	reinstall-pyznap)
		echo "Re-installing pyznap. Press Enter to Continue or CTRL+C to abort."
		read -r
		reinstall-pyznap
	;;
	*)
		printf "%s\n%s\n%s\n" "-----" "Usage: $0 initial | postreboot | remoteaccess | datapool | reinstall-zbm | reinstall-pyznap" "-----"
	;;
esac

date
exit 0
