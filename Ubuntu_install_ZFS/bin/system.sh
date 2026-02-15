#!/bin/bash

debootstrap_part1_Func() {
    export DEBIAN_"${install_warning_level}"
    
    cat > /etc/apt/apt.conf.d/30apt_error_on_transient <<-EOF
		APT::Update::Error-Mode "any";
	EOF
    
    identify_apt_data_sources
    apt_sources "base" "${ubuntu_original}"
    
    if [ -n "${mirror_archive}" ]; then
        apt_mirror_source
    fi
    
    cat "${apt_data_sources_loc}"
    
    trap 'printf "%s\n%s" "The script has experienced an error during the first apt update. That may have been caused by a queried server not responding in time. Try running the script again." "If the issue is the security server not responding, then comment out the security server in the \"${apt_data_sources_loc}\". Alternatively, you can uncomment the command that does this in the install script. This affects the temporary live iso only. Not the permanent installation."' ERR
    apt update
    trap - ERR

    keyboard_console_settings # Request keyboard and console settings.
    
    apt-get -yq install debootstrap software-properties-common gdisk zfs-initramfs
    if service --status-all | grep -Fq 'zfs-zed'; then
        systemctl stop zfs-zed
    fi

    clear_partition_table "root"
    partprobe
    sleep 2

    partitionsFunc
}

debootstrap_installminsys_Func() {
    ## Install minimum system
    FREE="$(df -k --output=avail "$mountpoint" | tail -n1)"
    if [ "$FREE" -lt 5242880 ]; then # 5 GB
         echo "Less than 5 GBs free!"
         exit 1
    fi
    
    debootstrap "$ubuntuver" "$mountpoint"
}

zfsbootmenu_install_config_Func() {
    zfsbootmenu_install_config_loc="/tmp/zfsbootmenu_install_config.sh"
    cat <<-EOH >"${zfsbootmenu_install_config_loc}"
		#!/bin/bash
		set -euo pipefail
		# set -x
		apt update

		compile_zbm_git() {
			apt-get install --yes bsdextrautils mbuffer
			apt-get install --yes --no-install-recommends \
				libsort-versions-perl libboolean-perl libyaml-pp-perl \
				git fzf make kexec-tools dracut-core cpio curl
			
			mkdir -p /usr/local/src/zfsbootmenu
			cd /usr/local/src/zfsbootmenu

			zbm_release="git" ## "git" for git master, "release" for latest release.
			case "${zbm_release}" in
				git) git clone https://github.com/zbm-dev/zfsbootmenu . ;;
				release)
					latest_tar="$(curl -s https://api.github.com/repos/zbm-dev/zfsbootmenu/releases/latest | grep tarball | cut -d : -f 2,3 | tr -d \" | sed 's/^[ \t]*//;s/,//')"
					curl -L "${latest_tar}" | tar -zxv --strip-components=1 -f -
				;;
				*) exit 1 ;;
			esac
			make core dracut
		}
		compile_zbm_git

		config_zbm() {
			kb_layoutcode="\$(debconf-get-selections | grep keyboard-configuration/layoutcode | awk '{print \$4}')"
			sed \
			-e 's,ManageImages:.*,ManageImages: true,' \
			-e 's@ImageDir:.*@ImageDir: /boot/efi/EFI/ubuntu@' \
			-e 's,Versions:.*,Versions: false,' \
			-e "/CommandLine/s,ro,rd.vconsole.keymap=\${kb_layoutcode} ro," \
			-i /etc/zfsbootmenu/config.yaml

			if [ "$quiet_boot" = "no" ]; then
				sed -i 's,ro quiet,ro,' /etc/zfsbootmenu/config.yaml
			fi
			
			if [ -n "$zfs_root_password" ] && [ "$zfs_root_encrypt" = "luks" ]; then
				zfsbootmenu_hook_root=/etc/zfsbootmenu/hooks
				mkdir -p \${zfsbootmenu_hook_root}/early-setup.d
				cd \${zfsbootmenu_hook_root}/early-setup.d
				curl -L -O https://raw.githubusercontent.com/agorgl/zbm-luks-unlock/master/hooks/early-setup.d/luks-unlock.sh
				chmod +x \${zfsbootmenu_hook_root}/early-setup.d/luks-unlock.sh
				cd /etc/zfsbootmenu/dracut.conf.d/
				curl -L -O https://raw.githubusercontent.com/agorgl/zbm-luks-unlock/master/dracut.conf.d/99-crypt.conf
			fi	
		}
		config_zbm

		update-initramfs -c -k all
		generate-zbm --debug
	EOH

    case "$1" in
        chroot)
            cp "${zfsbootmenu_install_config_loc}" "$mountpoint/tmp"
            chroot "$mountpoint" /bin/bash -x "/tmp/$(basename "${zfsbootmenu_install_config_loc}")"
        ;;
        base) /bin/bash "${zfsbootmenu_install_config_loc}" ;;
        *) exit 1 ;;
    esac
}

remote_zbm_access_Func() {
    modulesetup="/usr/lib/dracut/modules.d/60crypt-ssh/module-setup.sh"
    cat <<-EOH >/tmp/remote_zbm_access.sh
		#!/bin/sh
		apt update
		apt install -y dracut-network dropbear isc-dhcp-client
		git -C /tmp clone 'https://github.com/dracut-crypt-ssh/dracut-crypt-ssh.git'
		mkdir -p /usr/lib/dracut/modules.d/60crypt-ssh
		cp /tmp/dracut-crypt-ssh/modules/60crypt-ssh/* /usr/lib/dracut/modules.d/60crypt-ssh/
		rm -f /usr/lib/dracut/modules.d/60crypt-ssh/Makefile
		
		sed -i \
			-e 's,  inst "\$moddir"/helper/console_auth /bin/console_auth,  #inst "\$moddir"/helper/console_auth /bin/console_auth,' \
			-e 's,  inst "\$moddir"/helper/console_peek.sh /bin/console_peek,  #inst "\$moddir"/helper/console_peek.sh /bin/console_peek,' \
			-e 's,  inst "\$moddir"/helper/unlock /bin/unlock,  #inst "\$moddir"/helper/unlock /bin/unlock,' \
			-e 's,  inst "\$moddir"/helper/unlock-reap-success.sh /sbin/unlock-reap-success,  #inst "\$moddir"/helper/unlock-reap-success.sh /sbin/unlock-reap-success,' \
			"$modulesetup"
		
		mkdir -p /etc/cmdline.d
		case "$remoteaccess_ip_config" in
			dhcp*) echo "ip=$remoteaccess_ip_config rd.neednet=1" > /etc/cmdline.d/dracut-network.conf ;;
			static) echo "ip=$remoteaccess_ip:::$remoteaccess_netmask:::none rd.neednet=1 rd.break" > /etc/cmdline.d/dracut-network.conf ;;
			*) exit 1 ;;
		esac
		echo "send fqdn.fqdn \"$remoteaccess_hostname\";" >> /usr/lib/dracut/modules.d/35network-legacy/dhclient.conf

		cat <<-BANNER >/etc/zfsbootmenu/dracut.conf.d/banner.txt
			Welcome to the ZFSBootMenu initramfs shell. Enter "zfsbootmenu" or "zbm" to start ZFSBootMenu.
		BANNER
		chmod 755 /etc/zfsbootmenu/dracut.conf.d/banner.txt
		sed -i 's,  /sbin/dropbear -s -j -k -p \${dropbear_port} -P /tmp/dropbear.pid,  /sbin/dropbear -s -j -k -p \${dropbear_port} -P /tmp/dropbear.pid -b /etc/banner.txt,' /usr/lib/dracut/modules.d/60crypt-ssh/dropbear-start.sh
		sed -i '$ s,^},,' "$modulesetup"
		echo "  inst /etc/zfsbootmenu/dracut.conf.d/banner.txt /etc/banner.txt" >> "$modulesetup"
		echo "}" >> "$modulesetup"
		
		mkdir -p /etc/dropbear
		for keytype in rsa ecdsa ed25519; do
			ssh-keygen -t "\${keytype}" -m PEM -f "/etc/dropbear/ssh_host_\${keytype}_key" -N ""
		done
		
		sed -i '/inst "\${dropbear_acl}"/a \\  chown root:root "\${initdir}/root/.ssh/authorized_keys"' "$modulesetup"
		
		cat <<-DBEAR >/etc/zfsbootmenu/dracut.conf.d/dropbear.conf
			add_dracutmodules+=" crypt-ssh network-legacy "
			install_optional_items+=" /etc/cmdline.d/dracut-network.conf "
			dropbear_rsa_key="/etc/dropbear/ssh_host_rsa_key"
			dropbear_ecdsa_key="/etc/dropbear/ssh_host_ecdsa_key"
			dropbear_ed25519_key="/etc/dropbear/ssh_host_ed25519_key"
		DBEAR
		systemctl stop dropbear || true
		systemctl disable dropbear || true
		sed -i 's,zbm.timeout=$timeout_zbm_no_remote_access,zbm.timeout=$timeout_zbm_remote_access,' /boot/efi/EFI/ubuntu/refind_linux.conf
		generate-zbm --debug
	EOH

    case "$1" in
        chroot)
            cp /tmp/remote_zbm_access.sh "$mountpoint/tmp"
            chroot "$mountpoint" /bin/bash -x /tmp/remote_zbm_access.sh
        ;;
        base)
            if grep casper /proc/cmdline >/dev/null 2>&1; then
                echo "Live environment present. Reboot into new installation to install remoteaccess."
                exit 1
            fi
            /bin/bash /tmp/remote_zbm_access.sh
            sed -i 's,#dropbear_acl,dropbear_acl,' /etc/zfsbootmenu/dracut.conf.d/dropbear.conf
            mkdir -p "/home/$user/.ssh"
            touch "/home/$user/.ssh/authorized_keys"
            chown -R "$user":"$user" "/home/$user/.ssh"
            chmod 644 "/home/$user/.ssh/authorized_keys"
            echo "Zfsbootmenu remote access installed. Run sudo generate-zbm after adding keys."
        ;;
        *) exit 1 ;;
    esac
}

systemsetupFunc_part1() {
    chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		export DEBIAN_"${install_warning_level}"
EOCHROOT
    cp /etc/apt/apt.conf.d/30apt_error_on_transient "$mountpoint/etc/apt/apt.conf.d/"
    echo "$hostname" > "$mountpoint/etc/hostname"
    echo "127.0.1.1       $hostname" >> "$mountpoint/etc/hosts"
    
    ethernetinterface="$(basename "$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${ethprefix}*")")"
    cat > "$mountpoint/etc/netplan/01-$ethernetinterface.yaml" <<-EOF
		network:
		  version: 2
		  ethernets:
		    $ethernetinterface:
		      dhcp4: yes
	EOF
    chmod 600 "$mountpoint/etc/netplan/01-$ethernetinterface.yaml"
    mount --rbind /dev "$mountpoint/dev"
    mount --rbind /proc "$mountpoint/proc"
    mount --rbind /sys "$mountpoint/sys"

    if [ -n "${mirror_archive}" ]; then
        apt_sources "chroot" "${ubuntu_mirror}"
    else
        apt_sources "chroot" "${ubuntu_original}"
    fi

    chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		apt update
		locale-gen en_US.UTF-8 $locale
		echo 'LANG="$locale"' > /etc/default/locale
		ln -fs /usr/share/zoneinfo/"$timezone" /etc/localtime
		dpkg-reconfigure tzdata
EOCHROOT
}

systemsetupFunc_part2() {
    chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		apt update
		apt install --no-install-recommends -y linux-headers-generic linux-image-generic dkms wget nano software-properties-common
		apt install --yes zfsutils-linux zfs-zed zfs-initramfs
EOCHROOT
}

systemsetupFunc_part3() {
    identify_ubuntu_dataset_uuid
    apt install --yes dosfstools
    loop_counter=0
    while IFS= read -r diskidnum; do
        if [ "$loop_counter" -eq 0 ]; then
            esp_mount="/boot/efi"
        else
            esp_mount="/boot/efi$loop_counter"
            echo "$esp_mount" >> "$mountpoint/tmp/backup_esp_mounts.txt"
        fi
        umount -q "/dev/disk/by-id/${diskidnum}-part1" || true
        mkdosfs -F 32 -s 1 -n EFI "/dev/disk/by-id/${diskidnum}-part1"
        partprobe && sleep 2
        blkid_part1="$(blkid -s UUID -o value "/dev/disk/by-id/${diskidnum}-part1")"
        chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
			mkdir -p "${esp_mount}"
			echo "/dev/disk/by-uuid/$blkid_part1 ${esp_mount} vfat defaults 0 0" >> /etc/fstab
			mount "${esp_mount}"
EOCHROOT
        loop_counter=$((loop_counter + 1))
    done < /tmp/diskid_check_root.txt

    initial_boot_order="$(efibootmgr | grep "BootOrder" | cut -d " " -f 2)"
    chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		apt-get -yq install refind kexec-tools dpkg-dev git systemd-sysv
		sed -i 's,^timeout .*,timeout $timeout_rEFInd,' /boot/efi/EFI/refind/refind.conf
		echo REMAKE_INITRD=yes > /etc/dkms/zfs.conf
		sed -i 's,LOAD_KEXEC=false,LOAD_KEXEC=true,' /etc/default/kexec
EOCHROOT
}

systemsetupFunc_part4() {
    cp /tmp/diskid_check_root.txt "$mountpoint/tmp/"
    [ -f /tmp/luks_dmname_root.txt ] && cp /tmp/luks_dmname_root.txt "$mountpoint/tmp/"
    
    chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		if [ -n "$zfs_root_password" ]; then
			case "$zfs_root_encrypt" in
				native)
					echo "$zfs_root_password" > /etc/zfs/$RPOOL.key
					chmod 600 /etc/zfs/$RPOOL.key
					zfs change-key -o keylocation=file:///etc/zfs/$RPOOL.key -o keyformat=passphrase $RPOOL
					zfs set org.zfsbootmenu:keysource="$RPOOL/ROOT" $RPOOL
				;;
				luks)
					mkdir -p /etc/cryptsetup-keys.d/
					dd if=/dev/urandom of=/etc/cryptsetup-keys.d/$RPOOL.key bs=1024 count=4
					chmod 600 /etc/cryptsetup-keys.d/$RPOOL.key
				;;
			esac
		fi
		echo "UMASK=0077" > /etc/initramfs-tools/conf.d/umask.conf
EOCHROOT

    [ "$zfs_root_encrypt" = "luks" ] && update_crypttab_Func "chroot" "root"

    chroot "$mountpoint" /bin/bash -x <<-EOCHROOT					
		cmd="spl_hostid=\$( hostid ) ro"
		[ "$quiet_boot" = "yes" ] && cmd="\$cmd quiet"
		zfs set org.zfsbootmenu:commandline="\$cmd" "$RPOOL/ROOT"
EOCHROOT

    zfsbootmenu_install_config_Func "chroot"

    chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		cat <<-REFIND > /boot/efi/EFI/ubuntu/refind_linux.conf
			"Boot default"  "zbm.timeout=$timeout_zbm_no_remote_access ro quiet loglevel=0"
			"Boot to menu"  "zbm.show ro quiet loglevel=0"
		REFIND
		[ "$quiet_boot" = "no" ] && sed -i 's,ro quiet,ro,' /boot/efi/EFI/ubuntu/refind_linux.conf
EOCHROOT
    
    case "$topology_root" in
        single) true ;;
        *) zbm_multiple_ESP ;;
    esac

    [ "${remoteaccess_first_boot}" = "yes" ] && remote_zbm_access_Func "chroot"
}

zbm_multiple_ESP() {
    esp_sync_path="/etc/zfsbootmenu/generate-zbm.post.d/esp-sync.sh"
    chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		mkdir -p "/etc/zfsbootmenu/generate-zbm.post.d/"
		cat > "$esp_sync_path" <<-"EOT"
			#!/bin/sh
			sync_func() { rsync --delete-after -axHAWXS --info=progress2 /boot/efi/ "\$1"; }
		EOT
		while IFS= read -r esp_mount; do
			echo "sync_func \"\$esp_mount\"" >> "$esp_sync_path"
		done < /tmp/backup_esp_mounts.txt
		chmod +x "$esp_sync_path"
		apt install -y rsync
		sh "$esp_sync_path"
EOCHROOT
    
    # efibootmgr updates
    i=0
    while IFS= read -r diskidnum; do
        if [ "$i" -gt 0 ]; then
            device_name="$(readlink -f "/dev/disk/by-id/${diskidnum}")"
            efibootmgr --create --disk "${device_name}" --label "rEFInd Boot Manager Backup $i" --loader \\EFI\\refind\\refind_x64.efi
        fi
        i=$((i + 1))
    done < /tmp/diskid_check_root.txt
}

systemsetupFunc_part5() {
    chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		echo -e "root:$PASSWORD" | chpasswd -c SHA256
EOCHROOT
    
    crypttab_parameters="/dev/urandom plain,swap,cipher=aes-xts-plain64:sha256,size=512"
    case "$topology_root" in
        single)
            DISKID="$(cat /tmp/diskid_check_root.txt)"
            if [ -n "$zfs_root_password" ]; then
                chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
					apt install --yes cryptsetup
					echo "swap /dev/disk/by-id/$DISKID-part2 ${crypttab_parameters}" >> /etc/crypttab
					echo "/dev/mapper/swap none swap defaults 0 0" >> /etc/fstab
EOCHROOT
            else
                chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
					mkswap -f "/dev/disk/by-id/$DISKID-part2"
					blkid_part2="\$(blkid -s UUID -o value "/dev/disk/by-id/$DISKID-part2")"
					echo "/dev/disk/by-uuid/\$blkid_part2 none swap defaults 0 0" >> /etc/fstab
					sleep 2 && swapon -a || true
EOCHROOT
            fi
        ;;
        mirror|raidz1|raidz2|raidz3)
            # Simplified: use MDADM for RAID swap
            mdadm_level="mirror"
            [ "$topology_root" = "raidz1" ] && mdadm_level="5"
            [ "$topology_root" = "raidz2" ] && mdadm_level="6"
            [ "$topology_root" = "raidz3" ] && mdadm_level="6"
            mdadm_swap_Func "$mdadm_level" "$disks_root"
        ;;
        raid0)
            i=0
            while IFS= read -r diskidnum; do
                swap_part="swap$i"
                if [ -n "$zfs_root_password" ]; then
                    echo "${swap_part} /dev/disk/by-id/${diskidnum}-part2 ${crypttab_parameters}" >> "${mountpoint}/etc/crypttab"
                    echo "/dev/mapper/${swap_part} none swap defaults,pri=1 0 0" >> "${mountpoint}/etc/fstab"
                else
                    mkswap -f "/dev/disk/by-id/${diskidnum}-part2"
                    uuid="$(blkid -s UUID -o value "/dev/disk/by-id/${diskidnum}-part2")"
                    echo "/dev/disk/by-uuid/$uuid none swap defaults,pri=1 0 0" >> "${mountpoint}/etc/fstab"
                fi
                i=$((i + 1))
            done < /tmp/diskid_check_root.txt
        ;;
    esac
    
    chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		cp /usr/share/systemd/tmp.mount /etc/systemd/system/
		systemctl enable tmp.mount
		addgroup --system lpadmin
		addgroup --system lxd
		addgroup --system sambashare
		update-initramfs -c -k all
EOCHROOT
}

mdadm_swap_Func() {
    mdadm_level="$1"
    mdadm_devices="$2"
    mdadm_swap_loc="/tmp/multi_disc_swap.sh"
    cat > "$mdadm_swap_loc" <<-EOF
		apt install --yes mdadm
		mdadm --create /dev/md0 --metadata=1.2 --level="$mdadm_level" --raid-devices="$mdadm_devices" \\
	EOF
    while IFS= read -r diskidnum; do
        echo "/dev/disk/by-id/${diskidnum}-part2 \\" >> "$mdadm_swap_loc"
    done < /tmp/diskid_check_root.txt
    sed -i '$s,\\,,' "$mdadm_swap_loc"
    
    if [ -n "$zfs_root_password" ]; then
        cat >> "$mdadm_swap_loc" <<-EOF
			apt install --yes cryptsetup
			echo "swap /dev/md0 ${crypttab_parameters}" >> /etc/crypttab
			echo "/dev/mapper/swap none swap defaults 0 0" >> /etc/fstab
		EOF
    else
        cat >> "$mdadm_swap_loc" <<-EOF
			mkswap -f /dev/md0
			uuid="\$(blkid -s UUID -o value /dev/md0)"
			echo "/dev/disk/by-uuid/\$uuid none swap defaults 0 0" >> /etc/fstab
		EOF
    fi
    echo "mdadm --detail --scan --verbose | tee -a /etc/mdadm/mdadm.conf" >> "$mdadm_swap_loc"
    cp "$mdadm_swap_loc" "$mountpoint/tmp/"
    chroot "$mountpoint" /bin/bash -x "/tmp/$(basename "$mdadm_swap_loc")"
}

update_crypttab_Func() {
    script_env=$1
    pool=$2	
    cat <<-EOH >/tmp/update_crypttab_$pool.sh
		case "$pool" in
			root) params="luks,discard,initramfs" ;;
			data) params="luks,discard" ;;
		esac
		apt install -y cryptsetup
		i=1
		while IFS= read -r diskidnum; do
			luks_dmname="\$(sed "\${i}q;d" /tmp/luks_dmname_$pool.txt)"
			part=""
			[ "$pool" = "root" ] && part="-part3"
			uuid="\$(blkid -s UUID -o value /dev/disk/by-id/\${diskidnum}\${part})"
			echo "${zfs_root_password}" | cryptsetup -v luksAddKey /dev/disk/by-uuid/\$uuid /etc/cryptsetup-keys.d/$RPOOL.key
			echo "\$luks_dmname UUID=\$uuid /etc/cryptsetup-keys.d/$RPOOL.key \$params" >> /etc/crypttab
			i=\$((i + 1))
		done < /tmp/diskid_check_$pool.txt
		sed -i 's,#KEYFILE_PATTERN=,KEYFILE_PATTERN="/etc/cryptsetup-keys.d/*.key",' /etc/cryptsetup-initramfs/conf-hook
	EOH
    case "${script_env}" in
        chroot)
            cp /tmp/diskid_check_$pool.txt "$mountpoint/tmp"
            cp /tmp/update_crypttab_$pool.sh "$mountpoint/tmp"
            chroot "$mountpoint" /bin/bash -x "/tmp/update_crypttab_$pool.sh"
        ;;
        base) /bin/bash /tmp/update_crypttab_$pool.sh ;;
    esac
}

fixfsmountorder() {
    identify_ubuntu_dataset_uuid
    chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		mkdir -p /etc/zfs/zfs-list.cache
		touch /etc/zfs/zfs-list.cache/$RPOOL
		zed -F &
		count=0
		while [ ! -s /etc/zfs/zfs-list.cache/$RPOOL ] && [ \$count -lt 60 ]; do
			zfs set canmount=noauto "$RPOOL/ROOT/${rootzfs_full_name}"
			sleep 1
			count=\$((count + 1))
		done
		pkill -9 zed || true
		sed -Ei "s|$mountpoint/?|/|" /etc/zfs/zfs-list.cache/$RPOOL
EOCHROOT
}

keyboard_console_setup() {
    cp /tmp/kb_console_selections.conf "$mountpoint/tmp"
    chroot "$mountpoint" <<-EOCHROOT
		apt install -y debconf-utils
		debconf-set-selections < /tmp/kb_console_selections.conf
		rm -f /etc/default/keyboard
		dpkg-reconfigure -f noninteractive keyboard-configuration
		dpkg-reconfigure -f noninteractive console-setup
EOCHROOT
}

unmount_datasets() {
    mount --make-rslave "$mountpoint/dev"
    mount --make-rslave "$mountpoint/proc"
    mount --make-rslave "$mountpoint/sys"
    grep "$mountpoint" /proc/mounts | cut -f2 -d" " | sort -r | xargs umount -n || true
}

usersetup() {
	## Create user account and setup groups
	zfs create -o mountpoint=/home/"$user" "$RPOOL/home/${user}"

	chroot "$mountpoint" /bin/bash -x <<-EOCHROOT
		## gecos parameter disabled asking for finger info
		adduser --disabled-password --gecos "" "$user"
		cp -a /etc/skel/. "/home/$user"
		chown -R "$user":"$user" "/home/$user"
		usermod -a -G adm,cdrom,dip,lpadmin,lxd,plugdev,sambashare,sudo "$user"
		echo -e "$user:$PASSWORD" | chpasswd

		## Disable root login with password.
		passwd -dl root
	EOCHROOT
}

reinstall-zbm() {
    disclaimer
    connectivity_check

    if grep -q casper /proc/cmdline; then
        echo "Live environment present. Reboot into new installation to re-install ZFSBootMenu."
        exit 1
    fi

    command -v generate-zbm >/dev/null 2>&1 || { echo "generate-zbm not found. Exiting."; exit 1; }

    # Version check
    latest_v="$(curl -s https://api.github.com/repos/zbm-dev/zfsbootmenu/releases/latest | grep tag_name | cut -d : -f 2,3 | tr -d \" | sed 's/^[ \t]*//;s/,//;s/^v//')"
    installed_v="$(generate-zbm --showver 2>/dev/null || echo "Unknown")"
    
    echo "Latest ZFSBootMenu version: $latest_v"
    echo "Installed ZFSBootMenu version: $installed_v"

    if [ "$latest_v" = "$installed_v" ]; then
        read -r -p "Latest version is already installed. Re-install anyway? (y/N): " choice
        case "$choice" in
            [Yy]*) zfsbootmenu_install_config_Func "base" ;;
            *) echo "Exiting."; exit 0 ;;
        esac
    else
        zfsbootmenu_install_config_Func "base"
    fi
}
