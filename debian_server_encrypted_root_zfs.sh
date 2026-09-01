#!/bin/bash
##Installs Debian on ZFS with encrypted-root snapshot rollback at boot. 

# shellcheck disable=SC2317  # Don't warn about unreachable commands in this file

set -euo pipefail
#set -x

##Usage: <script_filename> buildenv | initial | postreboot | remoteaccess | datapool

script_path="$(readlink -f "$0")"
env_file="${script_path%.sh}.env"
env_name="${env_file##*/}"
run_mode="${1-default}"

case "$run_mode" in
	initial|postreboot|remoteaccess|datapool)
		if [ ! -f "$env_file" ]; then
			echo "Missing ${env_name} file at ${env_file}."
			echo "Run \"$0 buildenv\" to create it, then try again."
			exit 1
		fi
		# shellcheck source=/dev/null
		. "$env_file"
	;;
	*)
		true
	;;
esac

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

in_live_environment(){
	grep -qw 'boot=live' /proc/cmdline 2>/dev/null
}

env_error(){
	##Appends one problem to env_errors to report as a batch.
	env_errors="${env_errors}${env_errors:+$'\n'}  - $1"
}

onion_key_file_is_valid(){
	##Shared shape check for the two Tor v3 onion service key files, as they are carried in the env
	##file: base64 of a fixed-size file that starts with a 32-byte NUL-padded type tag.
	##$1 base64 value, $2 expected decoded size in bytes, $3 tag text.
	onion_key_check="$(mktemp)"
	onion_key_tag_ref="$(mktemp)"
	printf '%s\0\0\0' "$3" > "$onion_key_tag_ref"
	onion_key_verdict="valid"
	if ! printf '%s' "$1" | base64 -d > "$onion_key_check" 2>/dev/null \
		|| [ "$(wc -c < "$onion_key_check")" -ne "$2" ] \
		|| ! cmp -s <(head -c 32 "$onion_key_check") "$onion_key_tag_ref";
	then
		onion_key_verdict="invalid"
	fi
	rm -f "$onion_key_check" "$onion_key_tag_ref" ##Never leave decoded key material behind, valid or not.
	[ "$onion_key_verdict" = "valid" ]
}

onion_secret_key_is_valid(){
	##96 bytes: the type tag, then the 64-byte expanded ed25519 key.
	onion_key_file_is_valid "$1" 96 '== ed25519v1-secret: type0 =='
}

onion_public_key_is_valid(){
	##64 bytes: the type tag, then the 32-byte ed25519 public key.
	onion_key_file_is_valid "$1" 64 '== ed25519v1-public: type0 =='
}

onion_hostname_is_valid(){
	##A v3 address is 56 base32 characters (public key, checksum and version byte) plus ".onion".
	printf '%s' "$1" | grep -Eq '^[a-z2-7]{56}\.onion$'
}

onion_client_auth_pubkey_is_valid(){
	##"descriptor:x25519:" plus a 32-byte x25519 key in unpadded base32, i.e. 52 characters.
	printf '%s' "$1" | grep -Eq '^descriptor:x25519:[A-Z2-7]{52}$'
}

dropbear_pubkey_line_is_valid(){
	##Bare "<keytype> <key> [comment]" only -- a pasted-in "restrict"/"command=..." prefix would get
	##parsed as the key type instead, silently locking out pre-boot login.
	case "$1" in
		ssh-ed25519\ *|sk-ssh-ed25519@openssh.com\ *|ssh-rsa\ *|ecdsa-sha2-nistp256\ *|ecdsa-sha2-nistp384\ *|ecdsa-sha2-nistp521\ *|sk-ecdsa-sha2-nistp256@openssh.com\ *)
			return 0
		;;
		*)
			return 1
		;;
	esac
}

disk_ids_count_check(){
	##Checks disks_<pool>_ids has exactly as many non-blank lines as the chosen topology needs.
	pool="$1"

	topology_pointer="topology_${pool}"
	eval topology_pointer="\$${topology_pointer}"
	disks_pointer="disks_${pool}"
	eval disks_pointer="\$${disks_pointer}"
	ids_pointer="disks_${pool}_ids"
	eval ids_pointer="\$${ids_pointer}"

	case "$topology_pointer" in
		single) min_disks="1" ;;
		mirror|raid0|raidz1) min_disks="2" ;;
		raidz2) min_disks="3" ;;
		raidz3) min_disks="4" ;;
		*)
			env_error "topology_${pool}=\"${topology_pointer}\" is not recognised (single, mirror, raid0, raidz1, raidz2, or raidz3)."
			return
		;;
	esac

	if [ "$topology_pointer" = "single" ];
	then
		needed="1"
	else
		if ! [ "$disks_pointer" -ge "$min_disks" ] 2>/dev/null;
		then
			env_error "topology_${pool}=\"${topology_pointer}\" needs at least ${min_disks} disks, but disks_${pool}=\"${disks_pointer}\"."
			return
		fi
		needed="$disks_pointer"
	fi

	have="$(printf '%s\n' "$ids_pointer" | sed '/^[[:space:]]*$/d' | wc -l | tr -d '[:space:]')"
	if [ "$have" -ne "$needed" ];
	then
		env_error "disks_${pool}_ids has ${have} line(s), but topology_${pool}=\"${topology_pointer}\" with disks_${pool}=\"${disks_pointer}\" needs ${needed}. Run \"$0 buildenv\" to (re)select disks for the ${pool} pool."
	fi
}

verify_env(){
	##Checks the env file for all errors, then reports to the user
	env_errors=""

	##Every ENV_VAR_ORDER name must be present, not just non-empty
	for var_name in $ENV_VAR_ORDER;
	do
		eval "[ -z \"\${${var_name}+x}\" ]" && env_error "${var_name} is missing from ${env_name} entirely."
	done

	##Identity/root-pool fields every stage needs set at "initial", read back by every later stage.
	[ -n "${user-}" ] || env_error "user is not set."
	[ -n "${PASSWORD-}" ] || env_error "PASSWORD is not set."
	[ -n "${hostname-}" ] || env_error "hostname is not set."
	case "${hostname-}" in
		*_*) env_error "hostname=\"${hostname}\" contains an underscore, which is DNS non-compliant." ;;
	esac
	[ -n "${RPOOL-}" ] || env_error "RPOOL is not set."
	[ -n "${zbm_ref-}" ] || env_error "zbm_ref is not set."

	if [ -n "${zfs_root_password-}" ];
	then
		case "${zfs_root_encrypt-}" in
			native) true ;;
			"") env_error "zfs_root_password is set but zfs_root_encrypt is empty. Set zfs_root_encrypt to \"native\"." ;;
			*) env_error "zfs_root_encrypt=\"${zfs_root_encrypt}\" is not recognised. Use \"native\"." ;;
		esac
	fi

	if [ -n "${zfs_data_password-}" ] && [ "${zfs_data_encrypt-}" != "native" ] && [ "$run_mode" = "datapool" ];
	then
		if [ -z "${zfs_data_encrypt-}" ];
		then
			env_error "zfs_data_password is set but zfs_data_encrypt is empty. Set zfs_data_encrypt to \"native\"."
		else
			env_error "zfs_data_encrypt=\"${zfs_data_encrypt}\" is not recognised. Use \"native\"."
		fi
	fi

	if [ -n "${zfs_data_password-}" ] && [ "${zfs_data_encrypt-}" = "native" ] && [ -z "${zfs_root_password-}" ];
	then
		echo "Note: the root pool is unencrypted, so the data pool's key will be stored in plaintext at /etc/zfs/${datapool}.key on the unencrypted root filesystem. The data pool will unlock automatically at boot, but it offers little protection against someone with physical access to the disks."
	fi

	case "$run_mode" in
		initial)
			[ -n "${debianver-}" ] || env_error "debianver is not set."
			[ -n "${ethprefix-}" ] || env_error "ethprefix is not set."
			disk_ids_count_check "root"
		;;
		datapool)
			[ -n "${datapool-}" ] || env_error "datapool is not set."
			disk_ids_count_check "data"
		;;
		remoteaccess)
			[ -n "${ethprefix-}" ] || env_error "ethprefix is not set."
			if [ -z "${remoteaccess_dropbear_pubkeys-}" ];
			then
				env_error "remoteaccess_dropbear_pubkeys is not set -- without a key there, nothing could log in to unlock the pool."
			else
				while IFS= read -r dropbear_pubkey_line || [ -n "$dropbear_pubkey_line" ];
				do
					case "$dropbear_pubkey_line" in
						""|"#"*) continue ;;
						*)
							dropbear_pubkey_line_is_valid "$dropbear_pubkey_line" \
								|| env_error "remoteaccess_dropbear_pubkeys in ${env_name} has a line that isn't a bare public key: \"${dropbear_pubkey_line}\". Paste only \"<keytype> <base64key> [comment]\" per line -- restrictions like \"restrict\"/\"command=...\" aren't supported here (no-agent-forwarding is added automatically) and would otherwise be parsed as the key type, silently locking out pre-boot login."
						;;
					esac
				done <<-DROPBEARKEYS
					${remoteaccess_dropbear_pubkeys}
				DROPBEARKEYS
			fi
			case "${remoteaccess_ip_config-}" in
				dhcp | dhcp,dhcp6 | dhcp6) true ;;
				static)
					[ -n "${remoteaccess_ip-}" ] || env_error "remoteaccess_ip_config is \"static\" but remoteaccess_ip is not set."
					[ -n "${remoteaccess_netmask-}" ] || env_error "remoteaccess_ip_config is \"static\" but remoteaccess_netmask is not set."
					[ -n "${remoteaccess_gateway-}" ] || env_error "remoteaccess_ip_config is \"static\" but remoteaccess_gateway is not set."
				;;
				"") env_error "remoteaccess_ip_config is not set. Use \"dhcp\", \"dhcp,dhcp6\", \"dhcp6\" or \"static\"." ;;
				*) env_error "remoteaccess_ip_config=\"${remoteaccess_ip_config}\" is not recognised. Use \"dhcp\", \"dhcp,dhcp6\", \"dhcp6\" or \"static\"." ;;
			esac

			##Checked here rather than at boot: it lands in refind_linux.conf as zbm.timeout, where a
			##non-numeric value is only discovered by watching the machine boot.
			if ! [ "${timeout_zbm_remote_access-}" -ge 1 ] 2>/dev/null;
			then
				env_error "timeout_zbm_remote_access=\"${timeout_zbm_remote_access-}\" is not a positive whole number of seconds."
			fi

			if [ "${remoteaccess_tor-}" = "yes" ];
			then
				if [ -z "${remoteaccess_tor_client_auth_pubkey-}" ];
				then
					env_error "remoteaccess_tor is \"yes\" but remoteaccess_tor_client_auth_pubkey is not set."
				elif ! onion_client_auth_pubkey_is_valid "$remoteaccess_tor_client_auth_pubkey";
				then
					##Worth being strict: a malformed value builds cleanly and is only discovered as a
					##lockout at the boot prompt, which is exactly where you can't fix it.
					env_error "remoteaccess_tor_client_auth_pubkey in ${env_name} is not a client-auth public key. Expected \"descriptor:x25519:\" followed by the 52 base32 characters of client.pub.key (not client.prv.key) -- see README."
				fi

				##These three describe one identity. Any that are set must be well-formed; any that are
				##missing get derived (see create_hidden_service_key), so an empty one is not an error.
				if [ -n "${remoteaccess_tor_onion_secret_key-}" ] && ! onion_secret_key_is_valid "$remoteaccess_tor_onion_secret_key";
				then
					env_error "remoteaccess_tor_onion_secret_key in ${env_name} is not a valid base64-encoded Tor v3 onion service secret key (expected 96 decoded bytes with the ed25519v1-secret header -- see README)."
				fi
				if [ -n "${remoteaccess_tor_onion_public_key-}" ] && ! onion_public_key_is_valid "$remoteaccess_tor_onion_public_key";
				then
					env_error "remoteaccess_tor_onion_public_key in ${env_name} is not a valid base64-encoded Tor v3 onion service public key (expected 64 decoded bytes with the ed25519v1-public header). Clear it and run \"$0 buildenv\" to re-derive it from the secret key."
				fi
				if [ -n "${remoteaccess_tor_onion_hostname-}" ] && ! onion_hostname_is_valid "$remoteaccess_tor_onion_hostname";
				then
					env_error "remoteaccess_tor_onion_hostname=\"${remoteaccess_tor_onion_hostname}\" is not a v3 onion address (56 base32 characters followed by \".onion\"). Clear it and run \"$0 buildenv\" to re-derive it from the secret key."
				fi

				if ! [ "${remoteaccess_tor_start_delay-}" -ge 0 ] 2>/dev/null;
				then
					env_error "remoteaccess_tor_start_delay=\"${remoteaccess_tor_start_delay-}\" is not a non-negative whole number of seconds."
				elif [ "$remoteaccess_tor_start_delay" -ge "$timeout_zbm_remote_access" ] && [ -z "${zfs_root_password-}" ];
				then
					##An encrypted root waits at its passphrase prompt regardless of the timeout, so only unencrypted matters here.
					echo "Note: remoteaccess_tor_start_delay (${remoteaccess_tor_start_delay}s) is >= timeout_zbm_remote_access (${timeout_zbm_remote_access}s), and the root pool is unencrypted -- on an unattended boot, the default environment auto-boots at the timeout before tor ever starts. Tor will only come up here if something (a connected dropbear session, physical console interaction) is holding the boot at the ZFSBootMenu prompt past that point. Increase timeout_zbm_remote_access if tor should also be reachable on an unattended boot."
				fi
			fi
		;;
	esac

	if [ -n "$env_errors" ];
	then
		echo "Env file problems in ${env_name}:"
		printf '%s\n' "$env_errors"
		echo "Run \"$0 buildenv\" to fix these, then try again."
		exit 1
	fi
}

live_debian_check(){
	##Check for Debian live environment
	if in_live_environment;
	then
		echo "Live environment present."
	else
		echo "Live environment test failed. Run script from a Debian Live 'standard' (cli-only) environment, booted with boot=live."
		exit 1
	fi

	if dpkg-query -W -f='${Status}' live-boot 2>/dev/null | grep -q "install ok installed";
	then
		echo "live-boot package check passed."
	else
		echo "live-boot package check failed. Run script from a Debian Live environment."
		exit 1
	fi

	live_debian_version="$( . /etc/os-release && echo "${VERSION_CODENAME}" )"
	if [ "$(echo "${live_debian_version}" | tr '[:upper:]' '[:lower:]')" = "$(echo "${debianver}" | tr '[:upper:]' '[:lower:]')" ];
	then
		echo "Live environment version test passed."
	else
		echo "Live environment version test failed."
		echo "The live environment version does not match the Debian version to be installed. Re-run script from a live environment which matches the version to be installed. This is to avoid zfs version conflicts."
		exit 1
	fi
}

update_date_time(){
	if ! timeout 5 timedatectl >/dev/null 2>&1;
	then
		echo "timedatectl is not reachable (no working D-Bus system bus in this environment). Skipping clock sync; system clock left as-is."
		return 0
	fi

	timedatectl

	manual_set(){
		timedatectl set-ntp off
		sleep 1
		timedatectl set-time "2026-01-01 00:00:00"
	}
	#manual_set

	sync_ntp(){

		if systemctl is-active systemd-timesyncd
		then
			systemctl restart systemd-timesyncd.service || true
			systemctl status systemd-timesyncd.service || true
		else
			if systemctl is-active chrony
			then
				chronyc burst 4/4 || true #Requests up to 4 good measurements
				sleep 5
				chronyc makestep || true #Update the system clock.

				chronyc tracking || true
				chronyc sources || true
			else true
			fi
		fi

	}
	sync_ntp

	if [ "$(timedatectl show -p CanNTP --value)" = "yes" ]
	then
		timedatectl set-ntp false || true
		timedatectl set-ntp true || true
		sleep 10
	else
		echo "No NTP service available (timedatectl reports NTP unsupported). Skipping NTP toggle; system clock left as-is."
	fi
	timedatectl || true
}

keyboard_console_settings(){
	kb_console_settings=/tmp/kb_console_selections.conf

	apt install -y debconf-utils

	echo "keyboard-configuration keyboard-configuration/layoutcode string ${keyboard_layoutcode}" | debconf-set-selections

	export DEBIAN_PRIORITY=high
	export DEBIAN_FRONTEND=noninteractive
	dpkg-reconfigure keyboard-configuration
	dpkg-reconfigure console-setup
	export DEBIAN_"${install_warning_level}"

	debconf-get-selections | grep keyboard-configuration | tee "${kb_console_settings}"
	debconf-get-selections | grep console-setup | tee -a "${kb_console_settings}"
}

topology_min_disk_check(){
	##Check that number of disks meets minimum number for selected topology.
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
	# Log everything we do.
	mkdir -p "$log_loc"
	touch "$log_loc"/"$install_log"
	chmod 600 "$log_loc"/"$install_log"
	exec > >(tee -a "$log_loc"/"$install_log") 2>&1
}

disclaimer(){
	echo "***WARNING*** This script could wipe out all your data, or worse! I am not responsible for your decisions. Press Enter to Continue or CTRL+C to abort."
	read -r _
}

connectivity_check(){
	test_site=deb.debian.org
	if curl -sSf --max-time 10 -o /dev/null "https://${test_site}"
	then
		echo "Internet connectivity test passed."
	else
		echo "No internet connectivity available. Please check connectivity."
		exit 1
	fi
}

prompt_stale_reference(){
	stale_label="$1"
	stale_link="$2"
	echo "Review before deciding: $stale_link"
	while true;
	do
		read -r -p "Pinned ${stale_label} is behind upstream. [C]ontinue with the pin, [u]pdate to the latest for this run only, or [e]xit? [C/u/e] " stale_reply
		case "$(printf '%s' "${stale_reply:-c}" | tr '[:upper:]' '[:lower:]')" in
			c) stale_choice="continue"; break ;;
			u) stale_choice="update"; break ;;
			e) stale_choice="exit"; break ;;
			*) echo "Please enter c, u, or e." ;;
		esac
	done
}

check_pinned_upstream_versions(){
	##Only an actual stale pin prompts the user, not connectivity issues.
	echo "Checking whether zbm_ref and zbm_builder_image are still the latest published upstream versions..."

	latest_zbm_ref="$(curl -sSf --max-time 10 "https://api.github.com/repos/zbm-dev/zfsbootmenu/releases/latest" 2>/dev/null | grep -m1 '"tag_name"' | cut -d'"' -f4)" || true
	if [ -n "$latest_zbm_ref" ];
	then
		if [ "$latest_zbm_ref" != "$zbm_ref" ];
		then
			echo "NOTICE: zbm_ref is pinned to \"$zbm_ref\" in ${env_name}, but the latest zfsbootmenu release is \"$latest_zbm_ref\"."
			prompt_stale_reference "zbm_ref (\"$zbm_ref\")" "https://github.com/zbm-dev/zfsbootmenu/releases/tag/${latest_zbm_ref}"
			case "$stale_choice" in
			update)
				zbm_ref="$latest_zbm_ref"
				zbm_raw_url="https://raw.githubusercontent.com/zbm-dev/zfsbootmenu/${zbm_ref}"
				echo "Using zbm_ref=\"$zbm_ref\" for this run. Update zbm_ref in ${env_name} afterward to make this permanent."
			;;
			exit)
				echo "Exiting at user request. Review the release notes, then update zbm_ref and re-run."
				exit 1
			;;
			continue)
				echo "Continuing with zbm_ref=\"$zbm_ref\"."
			;;
			esac
		else
			echo "zbm_ref (\"$zbm_ref\") is the latest zfsbootmenu release."
		fi
	else
		echo "Could not reach the GitHub API to check for a newer zfsbootmenu release. Continuing with zbm_ref=\"$zbm_ref\"."
	fi

	if [ -n "$zbm_builder_image" ];
	then
		image_repo="${zbm_builder_image%:*}"
		pinned_tag="${zbm_builder_image##*:}"
		ghcr_path="${image_repo#ghcr.io/}"

        ## Skip check on "latest" or "development"
		if printf '%s' "$pinned_tag" | grep -Eq '^[0-9]{8}$';
		then
			ghcr_token="$(curl -sSf --max-time 10 "https://ghcr.io/token?scope=repository:${ghcr_path}:pull&service=ghcr.io" 2>/dev/null | grep -o '"token":"[^"]*"' | cut -d'"' -f4)" || true
			if [ -n "$ghcr_token" ];
			then
				latest_dated_tag="$(curl -sSf --max-time 10 -H "Authorization: Bearer $ghcr_token" "https://ghcr.io/v2/${ghcr_path}/tags/list" 2>/dev/null | grep -o '"[0-9]\{8\}"' | tr -d '"' | sort -n | tail -1)" || true
				if [ -n "$latest_dated_tag" ];
				then
					if [ "$latest_dated_tag" != "$pinned_tag" ];
					then
						echo "NOTICE: zbm_builder_image is pinned to tag \"$pinned_tag\" in ${env_name}, but a newer dated build \"$latest_dated_tag\" is available at ${image_repo}. Only pin a tag alongside a matching zbm_ref bump -- the dated tag published for the zfsbootmenu release actually in use, not just whatever is newest."
						prompt_stale_reference "zbm_builder_image tag (\"$pinned_tag\")" "https://github.com/orgs/zbm-dev/packages/container/package/zbm-builder"
						case "$stale_choice" in
						update)
							zbm_builder_image="${image_repo}:${latest_dated_tag}"
							echo "Using zbm_builder_image=\"$zbm_builder_image\" for this run. Update zbm_builder_image in ${env_name} afterward to make this permanent."
						;;
						exit)
							echo "Exiting at user request. Review the available tags, then update zbm_builder_image and re-run."
							exit 1
						;;
						continue)
							echo "Continuing with zbm_builder_image=\"$zbm_builder_image\"."
						;;
						esac
					else
						echo "zbm_builder_image tag (\"$pinned_tag\") is the latest dated build."
					fi
				else
					echo "Could not list tags for ${image_repo} to check for a newer build. Continuing with zbm_builder_image=\"$zbm_builder_image\"."
				fi
			else
				echo "Could not reach ghcr.io to check for a newer zbm-builder image. Continuing with zbm_builder_image=\"$zbm_builder_image\"."
			fi
		fi
	else
		echo "zbm_builder_image is unset in ${env_name} -- the ZFSBootMenu build container will float on upstream's \"latest\" tag."
	fi
}

getdiskID(){
	##The env file may have been written on different hardware at a different time, so recheck
	pool="$1"
	diskidnum="$2"
	total_discs="$3"

	preset_ids_pointer="disks_${pool}_ids"
	eval preset_ids_pointer="\$${preset_ids_pointer}"

	##One /dev/disk/by-id name per line
	DISKID="$(printf '%s\n' "$preset_ids_pointer" | sed -n "${diskidnum}p" | tr -d '[:space:]')"
	if [ -z "$DISKID" ];
	then
		echo "disks_${pool}_ids in ${env_name} has no line $diskidnum (need $total_discs for the $pool pool). Run \"$0 buildenv\" to (re)select disks for the ${pool} pool."
		exit 1
	fi
	echo "Using preset Disk ID for disk $diskidnum of $total_discs on $pool pool: '$DISKID'"

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

	disk_in_use_check "$DISKID"

	printf "%s\n" "$DISKID" >> /tmp/diskid_check_"${pool}".txt
}

disk_in_use_check(){
	##Refuse a disk that the running system is currently using.
	diskid_inuse="$1"
	diskpath_inuse="$(readlink -f /dev/disk/by-id/"${diskid_inuse}")"
	inuse_reason=""

	##Kernel names of the disk itself and of every partition on it.
	disk_knames="$(lsblk -nro NAME "$diskpath_inuse" 2>/dev/null || true)"

	##$pool ("root"/"data") is set by the caller (getdiskID()/wizard_select_disk_id()). A disk that's
	##already a vdev of *that* pool is an expected match when re-confirming a disk already assigned to
	##it (e.g. re-running buildenv/datapool on the installed system, well after the pool was created) --
	##not a sign it would be wiped by mistake. A disk belonging to any other imported pool still refuses.
	target_poolname=""
	case "${pool-}" in
		root) target_poolname="${RPOOL-}" ;;
		data) target_poolname="${datapool-}" ;;
	esac
	own_pool_vdevs=""
	if [ -n "$target_poolname" ];
	then
		own_pool_vdevs="$(zpool status -LP "$target_poolname" 2>/dev/null || true)"
	fi

	zpool_vdevs="$(zpool status -LP 2>/dev/null || true)"

	mounted_kname="$(lsblk -nro NAME,MOUNTPOINT "$diskpath_inuse" 2>/dev/null | awk 'NF > 1 {print $1; exit}' || true)"
	if [ -n "$mounted_kname" ];
	then
		inuse_reason="/dev/${mounted_kname} is mounted or in use as swap"
	fi

	for kname_inuse in $disk_knames;
	do
		if [ -n "$inuse_reason" ];
		then
			break
		fi

		if printf '%s\n' "$own_pool_vdevs" | grep -qw "/dev/${kname_inuse}";
		then
			continue
		fi

		if [ -n "$(find /sys/class/block/"${kname_inuse}"/holders -maxdepth 1 -mindepth 1 2>/dev/null || true)" ];
		then
			inuse_reason="/dev/${kname_inuse} is in use by device-mapper or md (open LUKS container, LVM PV, or raid member)"
			break
		fi

		if printf '%s\n' "$zpool_vdevs" | grep -qw "/dev/${kname_inuse}";
		then
			inuse_reason="/dev/${kname_inuse} is a vdev of a currently imported zpool"
			break
		fi
	done

	if [ -z "$inuse_reason" ];
	then
		return 0
	fi

	if in_live_environment;
	then
		echo "WARNING: ${inuse_reason}."
		echo "In the live environment this is usually leftover state from an earlier attempt of this script, which will be cleared before the disk is partitioned. Continuing."
		return 0
	fi

	echo "Refusing to use disk ${diskid_inuse}: ${inuse_reason}."
	echo "This script is not running in the live environment, so that disk belongs to the running system -- it would be wiped by the partitioning step. Select a disk that is not in use. Exiting."
	exit 1
}

getdiskID_pool(){
	pool="$1"

	topology_min_disk_check "$pool"

	echo "Carefully enter the ID of the disk(s) YOU WANT TO DESTROY in the next step to ensure no data is accidentally lost."

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

wizard_select_disk_id(){
	pool="$1"
	diskidnum="$2"
	total_discs="$3"
	existing_default="$4"

	diskidmenu_loc="/tmp/diskidmenu.txt"
	ls -la /dev/disk/by-id | awk '{ print $9, $11 }' | sed -e '1,3d' | grep -v "part\|CD-ROM" > "$diskidmenu_loc"

	echo "Disk $diskidnum of $total_discs on the $pool pool:"
	nl "$diskidmenu_loc"
	count="$(wc -l "$diskidmenu_loc" | cut -f 1 -d' ')"

	while true;
	do
		if [ -n "$existing_default" ];
		then
			read -r -p "Select option [keep current: ${existing_default}]: " n || { echo "No input available (stdin closed). Aborting disk selection."; exit 1; }
		else
			read -r -p "Select option: " n || { echo "No input available (stdin closed). Aborting disk selection."; exit 1; }
		fi

		if [ -z "$n" ] && [ -n "$existing_default" ];
		then
			DISKID="$existing_default"
		elif [ "$n" -eq "$n" ] 2>/dev/null && [ "$n" -gt 0 ] && [ "$n" -le "$count" ];
		then
			DISKID="$(sed -n "${n}p" "$diskidmenu_loc" | awk '{ print $1 }')"
		else
			echo "Enter a listed option number$( [ -n "$existing_default" ] && printf '%s' ", or press Enter to keep the current value" )."
			continue
		fi

		if [ -z "$(find /dev/disk/by-id -maxdepth 1 -mindepth 1 -name "$DISKID")" ];
		then
			echo "Disk ID '$DISKID' not found under /dev/disk/by-id. Try again."
			continue
		fi

		if grep -qxF "$DISKID" /tmp/diskid_check_"${pool}".txt 2>/dev/null;
		then
			echo "Disk ID '$DISKID' has already been selected for the $pool pool in this session. Choose a different one."
			continue
		fi

		##Compare only against the OTHER pool's recorded ids, not this pool's own -- disks_${pool}_ids
		##still holds the list from before this wizard loop started (it's only overwritten once the
		##whole loop finishes), so re-confirming a disk already recorded for this same pool would
		##otherwise self-match here and be wrongly rejected as a cross-pool conflict.
		other_pool_ids=""
		case "$pool" in
			root) other_pool_ids="${disks_data_ids-}" ;;
			data) other_pool_ids="${disks_root_ids-}" ;;
		esac
		if printf '%s\n' "$other_pool_ids" | grep -qxF "$DISKID";
		then
			echo "Disk ID '$DISKID' is already assigned to the other pool (root or data). Choose a different one."
			continue
		fi

		disk_in_use_check "$DISKID"
		break
	done

	printf "%s\n" "$DISKID" >> /tmp/diskid_check_"${pool}".txt
	printf "%s\n\n" "Disk $diskidnum of $total_discs on $pool pool: '$DISKID'"
}

wizard_select_disk_ids(){
	pool="$1"

	topology_min_disk_check "$pool" ##Sets topology_pool_pointer / disks_pointer for $pool via eval.

	existing_ids_pointer="disks_${pool}_ids"
	eval existing_ids_pointer="\$${existing_ids_pointer}"

	true > /tmp/diskid_check_"${pool}".txt
	collected=""
	total_discs="1"
	if [ "$topology_pool_pointer" != "single" ];
	then
		total_discs="$disks_pointer"
	fi

	diskidnum="1"
	while [ "$diskidnum" -le "$total_discs" ];
	do
		existing_default="$(printf '%s\n' "$existing_ids_pointer" | sed -n "${diskidnum}p" | tr -d '[:space:]')"
		wizard_select_disk_id "$pool" "$diskidnum" "$total_discs" "$existing_default"
		collected="${collected}${collected:+$'\n'}${DISKID}"
		diskidnum=$(( diskidnum + 1 ))
	done

	if [ "$pool" = "root" ];
	then
		# shellcheck disable=SC2034 #disks_root_ids read indirectly via eval in getdiskID()/write_env_file()
		disks_root_ids="$collected"
	else
		# shellcheck disable=SC2034 #disks_data_ids read indirectly via eval in getdiskID()/write_env_file()
		disks_data_ids="$collected"
	fi
}

cleanup_prior_attempt(){
	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop udisks2.service 2>/dev/null || true
		systemctl mask udisks2.service 2>/dev/null || true
	fi

	swapoff -a 2>/dev/null || true

	if [ -d "$mountpoint" ]; then
		echo "Checking for mounts left by a previous partial run of this script..."

		mount | awk -v mp="${mountpoint}/boot/efi" '$3 == mp || index($3, mp"/") == 1 || index($3, mp) == 1 {print $3}' | sort -r | while read -r m;
		do
			umount "$m" 2>/dev/null || true
		done

		umount -R "$mountpoint"/dev 2>/dev/null || true
		umount -R "$mountpoint"/proc 2>/dev/null || true
		umount -R "$mountpoint"/sys 2>/dev/null || true
		umount -l "$mountpoint"/dev/pts 2>/dev/null || true
		umount -l "$mountpoint"/sys/fs/cgroup 2>/dev/null || true
		umount -l "$mountpoint"/proc/sys/fs/binfmt_misc 2>/dev/null || true
		umount "$mountpoint"/run 2>/dev/null || true
	fi

	if zpool list -H -o name 2>/dev/null | grep -qx "$RPOOL"; then
		echo "Pool ${RPOOL} is still imported from a previous run -- exporting it..."

		zpool export "$RPOOL" 2>/dev/null || true
		command -v udevadm >/dev/null 2>&1 && udevadm settle --timeout=10 2>/dev/null || true

		if zpool list -H -o name 2>/dev/null | grep -qx "$RPOOL"; then
			zpool export -f "$RPOOL" 2>/dev/null || true
			command -v udevadm >/dev/null 2>&1 && udevadm settle --timeout=10 2>/dev/null || true
		fi

		if zpool list -H -o name 2>/dev/null | grep -qx "$RPOOL"; then
			echo "Pool ${RPOOL} is still imported and cannot be exported -- reboot the live environment and re-run this script." >&2
			exit 1
		fi
	fi
}

clear_partition_table(){
	pool="$1" #root or data

	if in_live_environment;
	then
		if command -v dmsetup >/dev/null 2>&1; then
			dmsetup remove_all --force --noudevsync 2>/dev/null || true
		fi

		if command -v mdadm >/dev/null 2>&1; then
			mdadm --stop --scan 2>/dev/null || true
		fi

		command -v udevadm >/dev/null 2>&1 && udevadm settle --timeout=10 2>/dev/null || true
	fi

	while IFS= read -r diskidnum;
	do
		diskpath="/dev/disk/by-id/${diskidnum}"
		echo "Clearing partition table on disk ${diskidnum}."

		wipefs_wait_count=0
		while ! wipefs -a "$diskpath" 2>/tmp/wipefs_err.txt; ##Clear residual LVM/filesystem/RAID signatures, not just the GPT header.
		do
			wipefs_wait_count=$((wipefs_wait_count + 1))
			if [ "$wipefs_wait_count" -gt 10 ]; then
				cat /tmp/wipefs_err.txt >&2
				echo "wipefs on ${diskpath} kept failing after 10 retries. Check what else has it open (fuser -vm ${diskpath})."
				exit 1
			fi
			cat /tmp/wipefs_err.txt >&2
			sleep 1
			command -v udevadm >/dev/null 2>&1 && udevadm settle --timeout=5 2>/dev/null || true
		done

		sgdisk --zap-all "$diskpath"
	done < /tmp/diskid_check_"${pool}".txt
}

identify_debian_dataset_uuid(){
	rootzfs_full_name=0
	rootzfs_full_name="$(zfs list -o name | awk '/ROOT\/debian/{print $1;exit}'|sed -e 's,^.*/,,')"
}

ipv6_apt_live_iso_fix(){

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
		sysctl -p /etc/sysctl.conf
	}

	if [ "$ipv6_apt_fix_live_iso" = "yes" ]; then
		prefer_ipv4
		#dis_ipv6
	else
		true
	fi

}

identify_apt_data_sources(){

	if [ -f /etc/apt/sources.list.d/debian.sources ];
	then
		apt_data_sources_loc="/etc/apt/sources.list.d/debian.sources"
	else
		apt_data_sources_loc="/etc/apt/sources.list"
	fi

}

apt_sources(){
	script_env="$1" ##chroot, base
	source_archive="$2"

	cat > /tmp/apt_sources.sh <<-EOF
		#!/bin/sh
		if [ -f /etc/apt/sources.list.d/debian.sources ];
		then
			apt_data_sources_loc="/etc/apt/sources.list.d/debian.sources"
			cp "\${apt_data_sources_loc}" "\${apt_data_sources_loc}".orig 2>/dev/null || true

			cat > "\${apt_data_sources_loc}" <<-EOLIST
				Types: deb
				URIs: ${source_archive}
				Suites: ${debianver} ${debianver}-updates ${debianver}-backports
				Components: main contrib non-free non-free-firmware
				Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

				Types: deb
				URIs: ${debian_security_original}
				Suites: ${debianver}-security
				Components: main contrib non-free non-free-firmware
				Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
			EOLIST
		else
			apt_data_sources_loc="/etc/apt/sources.list"
			cp "\${apt_data_sources_loc}" "\${apt_data_sources_loc}".orig 2>/dev/null || true

			cat > "\${apt_data_sources_loc}" <<-EOLIST
				deb ${source_archive} ${debianver} main contrib non-free non-free-firmware
				#deb-src ${source_archive} ${debianver} main contrib non-free non-free-firmware

				deb ${source_archive} ${debianver}-updates main contrib non-free non-free-firmware
				#deb-src ${source_archive} ${debianver}-updates main contrib non-free non-free-firmware

				deb ${source_archive} ${debianver}-backports main contrib non-free non-free-firmware
				#deb-src ${source_archive} ${debianver}-backports main contrib non-free non-free-firmware

				deb ${debian_security_original} ${debianver}-security main contrib non-free non-free-firmware
				#deb-src ${debian_security_original} ${debianver}-security main contrib non-free non-free-firmware
			EOLIST
		fi
	EOF

	case "${script_env}" in
	chroot)
		cp /tmp/apt_sources.sh "$mountpoint"/tmp
		chroot "$mountpoint" /bin/bash -ex /tmp/apt_sources.sh
	;;
	base)
		/bin/bash -e /tmp/apt_sources.sh
	;;
	*)
		exit 1
	;;
	esac

}

reinstate_apt(){
	script_env="$1" ##chroot, base

	cat > /tmp/reinstate_apt.sh <<-EOF
		#!/bin/sh
		if [ -f /etc/apt/apt.conf.d/30apt_error_on_transient ];
		then
			mv /etc/apt/apt.conf.d/30apt_error_on_transient /tmp ##Remove apt update error on transient in new install.
		else true
		fi
	EOF

	case "${script_env}" in
	chroot)
		cp /tmp/reinstate_apt.sh "$mountpoint"/tmp
		chroot "$mountpoint" /bin/bash -ex /tmp/reinstate_apt.sh
	;;
	base)
		/bin/bash -e /tmp/reinstate_apt.sh
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
		chmod 600 "$mountpoint""$log_loc"/"$install_log"
		echo "Log file copied into new installation at ${log_loc}."
	else
		echo "No mountpoint dir present. Install log not copied."
	fi
}

script_copy(){
	cp "$script_path" "$mountpoint"/home/"${user}"/
	env_new_install_loc=/home/"${user}"/"${env_name}"
	cp "$env_file" "$mountpoint""$env_new_install_loc"
	script_new_install_loc=/home/"${user}"/"$(basename "$script_path")"

	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
		chown "${user}":"${user}" "$script_new_install_loc" "$env_new_install_loc"
		chmod +x "$script_new_install_loc"
		chmod 600 "$env_new_install_loc"
	EOCHROOT

	if [ -f "$mountpoint""$script_new_install_loc" ] && [ -f "$mountpoint""$env_new_install_loc" ];
	then
		echo "Install script and ${env_name} copied to ${user} home directory in new installation."
	else
		echo "Error copying install script or ${env_name} to new installation."
	fi
}

create_zpool_Func(){

	pool=$1 ##root, data

	datapool_native_keyloc=""

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

		if [ -n "$zfs_data_password" ];
		then
			datapool_native_keyloc="/etc/zfs/$datapool.key"
			printf '%s' "$zfs_data_password" > "$datapool_native_keyloc"
			chmod 600 "$datapool_native_keyloc"
			keylocation="file://$datapool_native_keyloc"
		else
			keylocation="prompt"
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
		##mountpoint=/ doesn't make $RPOOL itself a bogus ZFSBootMenu menu entry: nothing is ever written to
		##the pool root, so it can never have the /boot ZFSBootMenu also requires to list a boot environment.
		echo "-O mountpoint=/ -R $mountpoint \\" >> "$zpool_create_temp"
	;;
	data)
		echo "-O mountpoint=$datapoolmount \\" >> "$zpool_create_temp"
	;;
	esac


	add_zpool_disks(){
		while IFS= read -r diskidnum;
		do
			echo "/dev/disk/by-id/${diskidnum}${zpool_partition} \\" >> "$zpool_create_temp"
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

debootstrap_part1_Func(){
	export DEBIAN_"${install_warning_level}"

	cat > /etc/apt/apt.conf.d/30apt_error_on_transient <<-EOF
		APT::Update::Error-Mode "any";
	EOF

	identify_apt_data_sources

	apt_sources "base" "${debian_archive_selected}"

	cat "${apt_data_sources_loc}"

	trap 'printf "%s\n%s" "The script has experienced an error during the first apt update. That may have been caused by a queried server not responding in time. Try running the script again." "If the issue is the security server not responding, then comment out the security server in the "${apt_data_sources_loc}". This affects the temporary live environment only. Not the permanent installation."' ERR
	apt update
	trap - ERR	##Resets the trap to doing nothing when the script experiences an error. The script will still exit on error if "set -e" is set.

	keyboard_console_settings

	ssh_Func(){
		apt install --yes openssh-server
		service sshd start
		ip addr show scope global | grep inet
	}

	zfs_live_env_setup(){
		live_kernel_release="$(uname -r)"
		live_kernel_headers="linux-headers-${live_kernel_release}"

		echo "Checking that headers for the live kernel (${live_kernel_release}) are available..."
		if ! headers_probe="$(LC_ALL=C apt-get install --simulate "$live_kernel_headers" 2>&1)";
		then
			echo "Cannot install ${live_kernel_headers}, which is required to build the zfs module for the running live kernel."
			echo "apt reported:"
			printf '%s\n' "$headers_probe" | tail -n 5
			echo
			echo "This usually means the Debian Live ISO in use predates the current ${debianver} point release: its kernel ABI has since been replaced in the archive, so the matching headers package no longer exists there."
			echo "ZFS must be built against the exact kernel that is running, so this cannot be worked around from inside the script."
			echo "Download the current Debian ${debianver} Live 'standard' (cli-only) ISO and re-run from that. No disks have been modified."
			exit 1
		fi

		apt-get -yq install "$live_kernel_headers" build-essential dpkg-dev zfsutils-linux zfs-dkms

		echo "Waiting for the zfs DKMS module to finish building against the live kernel..."
		dkms_wait_count=0
		while true;
		do
			dkms_status_output="$(dkms status 2>/dev/null || true)"
			dkms_kernel_lines="$(printf '%s\n' "$dkms_status_output" | grep -F "$live_kernel_release" || true)"
			if printf '%s\n' "$dkms_kernel_lines" | grep -Eq "^zfs[/,].*: installed";
			then
				break
			fi

			dkms_wait_count=$((dkms_wait_count + 1))
			if [ "$dkms_wait_count" -gt 180 ]; then
				echo "Timed out waiting for the zfs DKMS module to build for kernel ${live_kernel_release}."
				echo "Current dkms status:"
				printf '%s\n' "$dkms_status_output"
				echo "Check /var/lib/dkms/zfs/*/build/make.log for the build failure."
				exit 1
			fi
			sleep 2
		done

		depmod -a

		modprobe_wait_count=0
		while ! modprobe zfs 2>/dev/null;
		do
			modprobe_wait_count=$((modprobe_wait_count + 1))
			if [ "$modprobe_wait_count" -gt 10 ]; then
				break
			fi
			sleep 1
			depmod -a
		done

		lsmod_output="$(lsmod)"
		if printf '%s\n' "$lsmod_output" | grep -q "^zfs ";
		then
			echo "zfs kernel module loaded in the live environment."
		else
			echo "zfs kernel module failed to load. Check 'dmesg' and the dkms build logs. Exiting."
			exit 1
		fi
	}
	zfs_live_env_setup

	apt-get -yq install debootstrap gdisk
	if service --status-all | grep -Fq 'zfs-zed'; then
		systemctl stop zfs-zed
	fi

	clear_partition_table "root"
	partprobe || true ##partprobe re-scans every block device on the system, not just this one; a warning/error on an
	                   ##unrelated device (e.g. an optical drive) shouldn't abort the install under set -e.
	sleep 2

	partitionsFunc(){

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

		root_hex_code="BF00" ##Solaris root; same partition type whether the ZFS pool is native-encrypted or not.

		while IFS= read -r diskidnum;
		do
			echo "Creating partitions on disk ${diskidnum}."
			sgdisk -n1:1M:+"${EFI_boot_size}"M -t1:EF00 /dev/disk/by-id/"${diskidnum}"

			##bug with swap on zfs zvol so use swap on partition:
			##https://github.com/zfsonlinux/zfs/issues/7734
			sgdisk -n2:0:+"${swap_size}"M -t2:"${swap_hex_code}" /dev/disk/by-id/"${diskidnum}"

			sgdisk     -n3:0:0      -t3:"${root_hex_code}" /dev/disk/by-id/"${diskidnum}"

		done < /tmp/diskid_check_root.txt
		partprobe || true ##See note above: don't let an unrelated device abort the install under set -e.
		sleep 2
	}
	partitionsFunc
}

debootstrap_createzfspools_Func(){

	create_zpool_Func root

	mountpointsFunc(){

		partprobe || true
		sleep 2

		zfs create -o canmount=off -o mountpoint=none "$RPOOL"/ROOT

		rootzfs_full_name="debian.$(date +%Y.%m.%d)"
		zfs create -o canmount=noauto -o mountpoint=/ "$RPOOL"/ROOT/"$rootzfs_full_name"
		zfs mount "$RPOOL"/ROOT/"$rootzfs_full_name"
		zpool set bootfs="$RPOOL"/ROOT/"$rootzfs_full_name" "$RPOOL"

		zfs create	"$RPOOL"/srv 						##server webserver content
		zfs create -o canmount=off	"$RPOOL"/usr
		zfs create	"$RPOOL"/usr/local					##locally compiled software
		zfs create -o canmount=off "$RPOOL"/var
		zfs create -o canmount=off "$RPOOL"/var/lib
		zfs create	"$RPOOL"/var/games					##game files
		zfs create	"$RPOOL"/var/log 					##log files
		zfs create	"$RPOOL"/var/mail 					##local mails
		zfs create	"$RPOOL"/var/spool					##printing tasks
		zfs create	"$RPOOL"/var/www					##server webserver content

		zfs create "$RPOOL"/home
		zfs create -o mountpoint=/root "$RPOOL"/home/root
		chmod 700 "$mountpoint"/root

		zfs create -o com.sun:auto-snapshot=false "$RPOOL"/var/cache
		zfs create -o com.sun:auto-snapshot=false "$RPOOL"/var/tmp
		chmod 1777 "$mountpoint"/var/tmp
		zfs create -o com.sun:auto-snapshot=false "$RPOOL"/var/lib/docker ##Docker manages its own datasets & snapshots

		mkdir "$mountpoint"/run
		mount -t tmpfs tmpfs "$mountpoint"/run
		mkdir "$mountpoint"/run/lock

	}
	mountpointsFunc
}

debootstrap_installminsys_Func(){
	FREE="$(df -k --output=avail "$mountpoint" | tail -n1)"
	if [ "$FREE" -lt 5242880 ]; then ##5242880k = 5 GiB. Matches the message below.
		 echo "Less than 5 GBs free!"
		 exit 1
	fi

	debootstrap --components=main,contrib,non-free,non-free-firmware "$debianver" "$mountpoint" "$debian_archive_selected"
}

zfsbootmenu_install_config_container_Func(){
	zfsbootmenu_install_config_loc="/tmp/zfsbootmenu_install_config.sh"
	zbmbuilddir="$mountpoint"/etc/zfsbootmenu
	cat <<-EOH >"${zfsbootmenu_install_config_loc}"
		##https://github.com/zbm-dev/zfsbootmenu/blob/v3.1.0/releng/docker/README.md
		##https://discourse.practicalzfs.com/t/how-to-enable-remote-access-ssh-to-zfsbootmenu/1498/9

		apt-get install -y podman
		apt-get install -y curl

		mkdir -p "$zbmbuilddir"
		curl -L -o "$zbmbuilddir"/config.yaml "$zbm_raw_url"/etc/zbm-builder/config.yaml

		##configure zfsbootmenu
		config_zbm(){

			kb_layoutcode="\$(debconf-get-selections | grep keyboard-configuration/layoutcode | awk '{print \$4}')"

			##Update configuration file
			sed \\
			-e "/CommandLine/s,ro,rd.vconsole.keymap=\${kb_layoutcode} ro," \\
			-i "$zbmbuilddir"/config.yaml

			if [ "$quiet_boot" = "no" ]; then
				sed -i 's,ro quiet,ro,' "$zbmbuilddir"/config.yaml
			fi

		}
		config_zbm

		##Generate ZFSBootMenu images at output dir
		cat >> "$zbmbuilddir"/zbm-builder.conf <<EOF
			RUNTIME_ARGS+=( -v $mountpoint/boot/efi/EFI/debian:/output )
			BUILD_ARGS+=( -o /output )
		EOF

		##Enable host network stack in podman so network available when running in root.
		echo "RUNTIME_ARGS+=( --net=host )" >> "$zbmbuilddir"/zbm-builder.conf

		##Pin the build container image if zbm_builder_image is set in .env, instead of floating on
		##zbm-builder.sh's own default of upstream's ":latest" tag. zbm-builder.sh sources this conf file
		##after setting that default, so setting BUILD_IMG here overrides it. This same conf file persists
		##into the finished system and is read by every later rebuild; repin_zbm_builder_image_Func keeps
		##it in sync with .env from then on, so a later change to zbm_builder_image isn't stuck here.
		if [ -n "$zbm_builder_image" ];
		then
			echo "BUILD_IMG=\"$zbm_builder_image\"" >> "$zbmbuilddir"/zbm-builder.conf
		fi

		##https://github.com/zbm-dev/zfsbootmenu/blob/v3.1.0/zbm-builder.sh
		curl -L -o "$zbmbuilddir"/zbm-builder.sh "$zbm_raw_url"/zbm-builder.sh
		chmod 755 "$zbmbuilddir"/zbm-builder.sh
		chmod +x "$zbmbuilddir"/zbm-builder.sh

		##Live environment not large enough to decompress image. De-compress on disk.
		##https://docs.podman.io/en/stable/markdown/podman.1.html
		mkdir -p "$zbmbuilddir"/containers
		mkdir -p "$zbmbuilddir"/run
		cp "$zbmbuilddir"/zbm-builder.sh "$zbmbuilddir"/zbm-builder_sh.bak
		sed -i 's,exec "\${PODMAN}",exec "\${PODMAN}" --root '"$zbmbuilddir"'/containers --runroot '"$zbmbuilddir"'/run,' "$zbmbuilddir"/zbm-builder.sh
		if cmp -s "$zbmbuilddir"/zbm-builder_sh.bak "$zbmbuilddir"/zbm-builder.sh; then
			echo "Patch failed: $zbmbuilddir/zbm-builder.sh no longer contains the pattern this script expects to patch (exec \\\${PODMAN}) -- upstream zbm-builder.sh may have changed format. Aborting rather than build with a container store that was never redirected off the live environment's tmpfs."
			exit 1
		fi

		mkdir -p "$mountpoint"/boot/efi/EFI/debian/

		/bin/bash "$zbmbuilddir"/zbm-builder.sh -b "$zbmbuilddir"

	EOH

	/bin/bash "${zfsbootmenu_install_config_loc}"

	rm -rf "$zbmbuilddir"/containers 2>/dev/null || true
	rm -rf "$zbmbuilddir"/run 2>/dev/null || true

	sed -i 's,'"$mountpoint"',,g' "$zbmbuilddir"/zbm-builder.conf
	mv "$zbmbuilddir"/zbm-builder_sh.bak "$zbmbuilddir"/zbm-builder.sh

}

create_hidden_service_key(){
	##Works out the Tor onion service identity and leaves it in remoteaccess_tor_onion_secret_key,
	##remoteaccess_tor_onion_public_key and remoteaccess_tor_onion_hostname for the caller to store in
	##${env_name}. $1, when non-empty, is an existing base64 secret key to derive the rest from (which
	##pins the .onion address); otherwise a new identity is generated.
	##Tor computes all three files locally in a couple of seconds -- nothing is published and no
	##circuits are needed -- so the daemon runs only long enough to write them out, then is killed.
	onion_seed_key="${1-}"

	tor_installed_here="no"
	if ! command -v tor >/dev/null 2>&1;
	then
		echo "The tor package is not installed, and tor is what turns an onion service key into its .onion address."
		echo "It would be run once, locally, purely to write the key files out: nothing is published, and no traffic is carried."
		read -r -p "Install the tor package now? [y/N]: " install_tor_reply
		case "$(printf '%s' "${install_tor_reply:-n}" | tr '[:upper:]' '[:lower:]')" in
			y|yes)
				apt-get install --yes tor
				tor_installed_here="yes"
			;;
			*)
				echo "Declined -- tor not installed, so the onion service identity can't be worked out here."
				return 1
			;;
		esac
	fi

	##Debian's tor package ships an AppArmor profile that confines /usr/bin/tor to writing under
	##/var/lib/tor, so the throwaway directories have to live there: from anywhere else (/tmp,
	##/etc/zfsbootmenu) tor is denied and never writes the key files at all.
	onion_genkey_dir=/var/lib/tor/zbm-onion-genkey
	onion_genkey_hs_dir="$onion_genkey_dir"/hidden_service
	rm -rf "$onion_genkey_dir"
	mkdir -p "$onion_genkey_hs_dir"
	chmod 700 "$onion_genkey_dir" "$onion_genkey_hs_dir"

	if [ -n "$onion_seed_key" ];
	then
		echo "Working out the onion service address from the secret key already in ${env_name}..."
		printf '%s' "$onion_seed_key" | base64 -d > "$onion_genkey_hs_dir"/hs_ed25519_secret_key
		chmod 600 "$onion_genkey_hs_dir"/hs_ed25519_secret_key
	else
		echo "Generating a new onion service identity key..."
	fi

	onion_genkey_conf="$onion_genkey_dir"/torrc
	cat > "$onion_genkey_conf" <<-EOF
		DataDirectory $onion_genkey_dir/data
		HiddenServiceDir $onion_genkey_hs_dir
		HiddenServiceVersion 3
		HiddenServicePort 22 127.0.0.1:222
		SocksPort 0
	EOF

	##When hs_ed25519_secret_key is already in place tor reports "Found secret key but not
	##hs_ed25519_public_key. Regenerating." and derives the matching public key and hostname from it,
	##instead of generating a new keypair -- which is what makes a pinned .onion address possible.
	tor -f "$onion_genkey_conf" --RunAsDaemon 0 &
	onion_genkey_pid=$!

	##All three files are waited on, not just the hostname: they are what gets installed into the
	##ZFSBootMenu image, so a partially written service directory has to fail here, loudly, rather
	##than at boot where the only log lives in a tmpfs that disappears.
	onion_genkey_waited=0
	onion_genkey_failed=""
	while [ ! -s "$onion_genkey_hs_dir"/hostname ] \
		|| [ ! -s "$onion_genkey_hs_dir"/hs_ed25519_public_key ] \
		|| [ ! -s "$onion_genkey_hs_dir"/hs_ed25519_secret_key ];
	do
		if ! kill -0 "$onion_genkey_pid" 2>/dev/null;
		then
			echo "tor exited before writing the onion service key files -- check for errors above."
			onion_genkey_failed="yes"
			break
		fi
		if [ "$onion_genkey_waited" -ge 30 ];
		then
			echo "Timed out waiting for tor to write the onion service key files."
			onion_genkey_failed="yes"
			break
		fi
		sleep 1
		onion_genkey_waited=$((onion_genkey_waited + 1))
	done

	kill "$onion_genkey_pid" 2>/dev/null || true
	wait "$onion_genkey_pid" 2>/dev/null || true

	if [ -z "$onion_genkey_failed" ];
	then
		remoteaccess_tor_onion_secret_key="$(base64 -w0 < "$onion_genkey_hs_dir"/hs_ed25519_secret_key)"
		remoteaccess_tor_onion_public_key="$(base64 -w0 < "$onion_genkey_hs_dir"/hs_ed25519_public_key)"
		remoteaccess_tor_onion_hostname="$(cat "$onion_genkey_hs_dir"/hostname)"
	fi

	rm -rf "$onion_genkey_dir" ##Holds the secret key in the clear; the env file is where it belongs.

	if [ "$tor_installed_here" = "yes" ];
	then
		echo "tor was installed only to do the above, and is not needed to run the boot environment (the copy inside the ZFSBootMenu image is built separately, in a container)."
		read -r -p "Remove the tor package again? [Y/n]: " remove_tor_reply
		case "$(printf '%s' "${remove_tor_reply:-y}" | tr '[:upper:]' '[:lower:]')" in
			n|no)
				echo "Leaving tor installed. Note that Debian's package also leaves a tor daemon enabled and running."
			;;
			*)
				apt-get purge --yes tor
				apt-get autoremove --purge --yes
				echo "tor removed."
			;;
		esac
	fi

	if [ -n "$onion_genkey_failed" ];
	then
		return 1
	fi

	echo "Onion service address: ${remoteaccess_tor_onion_hostname}"
}

repin_zbm_builder_image_Func(){
	##BUILD_IMG is written into zbm-builder.conf once, at "initial", and zbm-builder.sh sources that
	##file verbatim on every later rebuild -- so without this, updating zbm_builder_image in ${env_name}
	##(by hand or via check_pinned_upstream_versions' "update" prompt) never actually reaches a build.
	zbm_conf=/etc/zfsbootmenu/zbm-builder.conf
	[ -f "$zbm_conf" ] || return 0

	current_pin="$(sed -n 's/^BUILD_IMG="\(.*\)"$/\1/p' "$zbm_conf")"
	[ "$current_pin" = "$zbm_builder_image" ] && return 0

	if [ -n "$zbm_builder_image" ];
	then
		if [ -n "$current_pin" ];
		then
			sed -i 's#^BUILD_IMG=.*#BUILD_IMG="'"$zbm_builder_image"'"#' "$zbm_conf"
		else
			echo "BUILD_IMG=\"$zbm_builder_image\"" >> "$zbm_conf"
		fi
		echo "Re-pinned the build container image in ${zbm_conf} to \"$zbm_builder_image\" (was \"${current_pin:-none, floating on latest}\")."
	else
		sed -i '/^BUILD_IMG=/d' "$zbm_conf"
		echo "Cleared the build container image pin in ${zbm_conf} -- it will float on upstream's latest tag."
	fi
}

remote_zbm_access_container_Func(){

	repin_zbm_builder_image_Func

	ethernetinterface_matches="$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${ethprefix}*" -printf '%f\n')"
	ethernetinterface_matchcount="$(printf '%s\n' "$ethernetinterface_matches" | grep -c . || true)"
	if [ "$ethernetinterface_matchcount" -eq 0 ];
	then
		echo "No ethernet interface found matching ethprefix=\"${ethprefix}\" in /sys/class/net."
		exit 1
	fi
	if [ "$ethernetinterface_matchcount" -gt 1 ];
	then
		echo "ethprefix=\"${ethprefix}\" matches more than one interface: $(printf '%s ' "$ethernetinterface_matches")."
		echo "Set ethprefix in ${env_name} to the full name of the interface you want to use instead of a shared prefix."
		exit 1
	fi
	ethernetinterface="$ethernetinterface_matches"

	##Both checked up front, before an onion identity is generated or any file is written: this stage
	##rebuilds what "initial" produced, and it builds a boot environment whose only way in is a key
	##from remoteaccess_dropbear_pubkeys.
	if [ ! -f /etc/zfsbootmenu/config.yaml ];
	then
		echo "/etc/zfsbootmenu/config.yaml is missing, so there is no ZFSBootMenu build to add remote access to. Run this from a system installed by this script's \"initial\" stage."
		exit 1
	fi

	##Deliberately separate from the admin user's own authorized_keys, so an openssh key isn't
	##automatically also a pre-boot unlock key. Agent forwarding is on in dropbear by default and unused
	##here, hence the "no-agent-forwarding" prefix.
	mkdir -p /etc/zfsbootmenu
	{
		while IFS= read -r pubkey_line || [ -n "$pubkey_line" ];
		do
			case "$pubkey_line" in
			""|"#"*)
				continue
			;;
			*)
				printf 'no-agent-forwarding %s\n' "$pubkey_line"
			;;
			esac
		done <<-KEYS
			$remoteaccess_dropbear_pubkeys
		KEYS
	} > /etc/zfsbootmenu/dropbear-authorized-keys
	chmod 600 /etc/zfsbootmenu/dropbear-authorized-keys

	setup_tor_hidden_service_Func(){
		tor_dir=/etc/zfsbootmenu/tor
		hs_dir="$tor_dir"/hidden_service

		##${env_name} is the source of truth for the onion identity: "buildenv" is where it gets
		##generated, because that is where tor can be installed and removed again without it being a
		##side effect of a boot image rebuild. Anything missing from there is derived here instead, so
		##a first run that was never through the wizard still works.
		if [ -z "${remoteaccess_tor_onion_secret_key-}" ] \
			|| [ -z "${remoteaccess_tor_onion_public_key-}" ] \
			|| [ -z "${remoteaccess_tor_onion_hostname-}" ];
		then
			##Only the identity itself is worth warning about below. Deriving the public key and address
			##again from a secret key that is already in the env file loses nothing.
			if [ -z "${remoteaccess_tor_onion_secret_key-}" ];
			then
				onion_identity_unsaved="yes"
			fi
			echo "The onion service identity is not fully recorded in ${env_name}."
			if ! create_hidden_service_key "${remoteaccess_tor_onion_secret_key-}";
			then
				echo "Run \"$0 buildenv\" to generate and record the onion service identity, then run this stage again."
				exit 1
			fi
		fi

		if [ -f "$hs_dir"/hs_ed25519_secret_key ];
		then
			existing_onion_key="$(base64 -w0 < "$hs_dir"/hs_ed25519_secret_key)"
			if [ "$existing_onion_key" != "$remoteaccess_tor_onion_secret_key" ];
			then
				echo "Warning: ${hs_dir} already holds a different onion service identity to the one in ${env_name}."
				echo "  installed on this machine: $(cat "$hs_dir"/hostname 2>/dev/null || echo "unknown")"
				echo "  in ${env_name}:            ${remoteaccess_tor_onion_hostname}"
				echo "Continuing replaces the installed identity with the one in ${env_name}, so the address you connect to changes and the old one stops working. Press Enter to Continue or CTRL+C to abort."
				read -r _
			fi
		fi

		##Written out from ${env_name} on every run, so the installed service and the env file can't
		##drift apart, and so no tor binary is needed on the server to rebuild the image.
		mkdir -p "$hs_dir"/authorized_clients
		chmod 700 "$tor_dir" "$hs_dir"
		printf '%s' "$remoteaccess_tor_onion_secret_key" | base64 -d > "$hs_dir"/hs_ed25519_secret_key
		chmod 600 "$hs_dir"/hs_ed25519_secret_key
		printf '%s' "$remoteaccess_tor_onion_public_key" | base64 -d > "$hs_dir"/hs_ed25519_public_key
		printf '%s\n' "$remoteaccess_tor_onion_hostname" > "$hs_dir"/hostname
		printf '%s\n' "$remoteaccess_tor_client_auth_pubkey" > "$hs_dir"/authorized_clients/client.auth
		chmod 600 "$hs_dir"/authorized_clients/client.auth

		if [ -n "${onion_identity_unsaved-}" ];
		then
			##Deliberately not printing the key itself -- this function's stdout is logged verbatim to
			##${log_loc}/${install_log} by logFunc, and that log persists (gets copied into the new
			##install, may get backed up) far more readily than the key was ever meant to.
			echo "This identity only exists on this machine so far, so it would not survive a full reinstall (fresh ESP)."
			echo "Run \"$0 buildenv\" to record it in ${env_name} -- it adopts the identity already installed at ${hs_dir}."
		fi
	}
	if [ "$remoteaccess_tor" = "yes" ];
	then
		setup_tor_hidden_service_Func
	fi

	cat <<-EOH >/tmp/remote_zbm_access.sh
		#!/bin/sh
		##Prepares /etc/zfsbootmenu for a remote-access build, then hands over to the rebuild wrapper.
		##https://github.com/zbm-dev/zfsbootmenu/blob/${zbm_ref}/contrib/remote-ssh-build.sh
		set -eu

		zbmbuilddir=/etc/zfsbootmenu

		##Test for config file
		if [ -f "\$zbmbuilddir"/config.yaml ];
		then
			echo "Zfsbootmenu container build config file found. Proceeding."
		else
			echo "Zfsbootmenu container build config file missing. Exiting."
			exit 1
		fi

		setup_network(){
			##Network settings for ssh access during boot.
			mkdir -p "\$zbmbuilddir"/cmdline.d

			##Dracut network options: https://github.com/dracutdevs/dracut/blob/master/modules.d/35network-legacy/ifup.sh
			case "$remoteaccess_ip_config" in
			dhcp | dhcp,dhcp6 | dhcp6)
				##dracut's short form is ip=<interface>:<autoconf>, and parse-ip-opts.sh splits the
				##autoconf field on commas, so "dhcp,dhcp6" stays one ip= argument. The interface is
				##named for the same reason as in the static case below: left off, dracut brings up
				##whichever NIC it happens to find first, which is not necessarily the one ethprefix
				##points at. (It also refuses more than one ip= line for the same interface, so v4 and
				##v6 have to be asked for together like this rather than on two lines.)
				echo "ip=$ethernetinterface:$remoteaccess_ip_config rd.neednet=1" > "\$zbmbuilddir"/cmdline.d/dracut-network.conf
			;;
			static)
				##dracut ip= field order is client-IP:peer:gateway-IP:netmask:hostname:interface:autoconf.
				##Leaving gateway-IP blank only works if the SSH client is on the same L2 segment as this NIC;
				##leaving interface blank lets dracut's network-legacy module guess which NIC to configure,
				##which silently picks the wrong one on multi-NIC hardware -- both are filled in below instead.
				echo "ip=$remoteaccess_ip::$remoteaccess_gateway:$remoteaccess_netmask::$ethernetinterface:none rd.neednet=1" > "\$zbmbuilddir"/cmdline.d/dracut-network.conf
			;;
			*)
				echo "Remote access IP option not recognised."
				exit 1
			;;
			esac

		}
		setup_network

		add_welcome_message(){
			mkdir -p "\$zbmbuilddir"/rc.d

			cat > "\$zbmbuilddir"/rc.d/20-dropbear-banner.sh <<-EOT
				#!/bin/sh
				cat > /etc/dropbear-banner.txt <<-EOF
					=======================================
					ZFSBootMenu Remote Access Environment
					=======================================
					Welcome to the ZFSBootMenu initramfs shell. Enter "zfsbootmenu" or "zbm" to start ZFSBootMenu.
				EOF
				sed -i '/dropbear .* -P \/tmp\/dropbear.pid/ s/$/ -b \/etc\/dropbear-banner.txt/' /usr/lib/dracut/modules.d/60crypt-ssh/dropbear-start.sh
			EOT
			chmod +x "\$zbmbuilddir"/rc.d/20-dropbear-banner.sh

			mkdir -p "\$zbmbuilddir"/dracut.conf.d
			cat > "\$zbmbuilddir"/dracut.conf.d/20-dropbear-banner.conf<<-EOP
					install_items+=" /etc/dropbear-banner.txt "
			EOP
		}
		add_welcome_message

		restrict_dropbear_host_keytypes(){
			##Host keys become part of the image, which lives on unencrypted /boot -- ed25519 only,
			##instead of dracut-crypt-ssh's rsa/ecdsa/ed25519 default.
			mkdir -p "\$zbmbuilddir"/dracut.conf.d
			cat > "\$zbmbuilddir"/dracut.conf.d/40-dropbear-keytypes.conf <<-EOR
					dropbear_keytypes=ed25519
			EOR
		}
		restrict_dropbear_host_keytypes

		add_tor_module(){
			mkdir -p "\$zbmbuilddir"/rc.d

			##This writes a new dracut module (70tor) into the builder container, rather than patching an
			##existing one -- dropbear only needs to bind and listen, so crypt-ssh hooks pre-udev; tor needs
			##actual outbound connectivity, so it has to start once the network module reports the interface
			##is up (initqueue/online), a different hook point.
			cat > "\$zbmbuilddir"/rc.d/70-tor-module.sh <<-'TORHOOK'
				#!/bin/sh
				mkdir -p /usr/lib/dracut/modules.d/70tor

				cat > /usr/lib/dracut/modules.d/70tor/module-setup.sh <<-'MODSETUP'
					#!/bin/bash

					check() {
						require_binaries tor || return 1
						return 0
					}

					depends() {
						echo network
						return 0
					}

					install() {
						local tor_bin
						if tor_bin="\$(command -v tor 2>/dev/null)"; then
							inst "\${tor_bin}" /sbin/tor
						else
							derror "Unable to locate tor executable"
							return 1
						fi

						inst_dir /etc/tor
						inst_dir /var/lib/tor/hidden_service/authorized_clients
						inst /build/tor/hidden_service/hs_ed25519_secret_key /var/lib/tor/hidden_service/hs_ed25519_secret_key
						inst /build/tor/hidden_service/hs_ed25519_public_key /var/lib/tor/hidden_service/hs_ed25519_public_key
						inst /build/tor/hidden_service/hostname /var/lib/tor/hidden_service/hostname
						inst /build/tor/hidden_service/authorized_clients/client.auth /var/lib/tor/hidden_service/authorized_clients/client.auth

						chmod 700 "\${initdir}"/var/lib/tor
						chmod 700 "\${initdir}"/var/lib/tor/hidden_service
						chmod 600 "\${initdir}"/var/lib/tor/hidden_service/hs_ed25519_secret_key

						cat > "\${initdir}"/etc/tor/torrc <<-'TORRC'
							DataDirectory /var/lib/tor
							HiddenServiceDir /var/lib/tor/hidden_service
							HiddenServiceVersion 3
							HiddenServicePort 22 127.0.0.1:222
							Log notice file /tmp/tor-onion.log
							SocksPort 0
						TORRC

						inst_hook initqueue/online 30 "\$moddir/tor-start.sh"
					}
				MODSETUP
				chmod +x /usr/lib/dracut/modules.d/70tor/module-setup.sh

				cat > /usr/lib/dracut/modules.d/70tor/tor-start.sh <<-'STARTHOOK'
					#!/bin/sh
					[ -e /tmp/tor-onion-started ] && exit 0
					: > /tmp/tor-onion-started
					##HiddenServicePort forwards to 127.0.0.1:222 (dropbear) and, without SocksPort explicitly
					##disabled above, tor also binds 127.0.0.1:9050 by default -- both need loopback up, which
					##this minimal initramfs doesn't bring up on its own the way a full OS does.
					ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null || true
					##Backgrounded so this hook returns immediately rather than stalling dracut's boot on the wait.
					(
						sleep $remoteaccess_tor_start_delay
						if [ -x /sbin/tor ];
						then
							echo "\$(date): tor binary found, starting after ${remoteaccess_tor_start_delay}s delay." >> /tmp/tor-onion-hook.log
							/sbin/tor -f /etc/tor/torrc --RunAsDaemon 1 >> /tmp/tor-onion-hook.log 2>&1
							echo "\$(date): tor start command exited with status \$?." >> /tmp/tor-onion-hook.log
						else
							echo "\$(date): /sbin/tor not found or not executable -- the 70tor dracut module did not install it correctly." >> /tmp/tor-onion-hook.log
						fi
					) &
				STARTHOOK
				chmod +x /usr/lib/dracut/modules.d/70tor/tor-start.sh
			TORHOOK
			chmod +x "\$zbmbuilddir"/rc.d/70-tor-module.sh

			mkdir -p "\$zbmbuilddir"/dracut.conf.d
			cat > "\$zbmbuilddir"/dracut.conf.d/30-tor-module.conf <<-EOQ
					add_dracutmodules+=" tor "
			EOQ
		}
		if [ "$remoteaccess_tor" = "yes" ]; then
			add_tor_module
		fi

		##Fetched, not patched: everything this install needs on top of upstream's script is expressed
		##through the interfaces it already offers, and lives in rebuild-zbm-remote.sh below. -f so an
		##error page can't be saved as a shell script and then executed.
		curl -sSfL -o "\$zbmbuilddir"/remote-ssh-build.sh "$zbm_raw_url"/contrib/remote-ssh-build.sh
		chmod +x "\$zbmbuilddir"/remote-ssh-build.sh

		##https://github.com/zbm-dev/zfsbootmenu/blob/${zbm_ref}/zbm-builder.sh
		curl -sSfL -o "\$zbmbuilddir"/zbm-builder.sh "$zbm_raw_url"/zbm-builder.sh
		chmod 755 "\$zbmbuilddir"/zbm-builder.sh
		chmod +x "\$zbmbuilddir"/zbm-builder.sh

		/bin/sh "\$zbmbuilddir"/rebuild-zbm-remote.sh
	EOH

	##Persistent rebuild wrapper: the image has to be rebuilt after every change to
	##remoteaccess_dropbear_pubkeys, and after kernel/zfs updates, so the settings this stage chose have
	##to outlive it somewhere. Upstream's script is driven entirely through documented inputs -- BUILD_DIR and
	##ZBM_BUILDER from the environment, dropbear/authorized_keys placed in the build dir, and packages
	##passed through after "--" -- rather than by sed-patching a file that gets re-fetched each run.
	if [ "$remoteaccess_tor" = "yes" ];
	then
		##Adds tor to the same builder invocation dropbear/dracut-crypt-ssh already use, so everything
		##is produced in one rebuild pass instead of two.
		zbm_builder_passthrough=" -- -p tor"
	else
		zbm_builder_passthrough=""
	fi

	cat <<-EOW >/etc/zfsbootmenu/rebuild-zbm-remote.sh
		#!/bin/sh
		##Rebuilds the ZFSBootMenu remote access image. Re-run after changing
		##remoteaccess_dropbear_pubkeys (via "$0 remoteaccess"), and after kernel or zfs updates.
		set -eu

		zbmbuilddir=/etc/zfsbootmenu

		##Upstream's remote-ssh-build.sh reads both of these from the environment.
		BUILD_DIR="\$zbmbuilddir"
		ZBM_BUILDER="\$zbmbuilddir"/zbm-builder.sh
		export BUILD_DIR ZBM_BUILDER

		##Written by the "remoteaccess" stage from remoteaccess_dropbear_pubkeys in ${env_name} --
		##deliberately not the admin user's own authorized_keys.
		admin_keys="\$zbmbuilddir"/dropbear-authorized-keys
		if [ ! -s "\$admin_keys" ];
		then
			echo "\$admin_keys is missing or empty -- nothing would be able to log in to the boot environment, so there is no point building it."
			echo "Set remoteaccess_dropbear_pubkeys in ${env_name} and run \"$0 remoteaccess\" again, then run this script again."
			exit 1
		fi
		mkdir -p "\$zbmbuilddir"/dropbear
		cp "\$admin_keys" "\$zbmbuilddir"/dropbear/authorized_keys

		apt-get install -y podman

		cd "\$zbmbuilddir"
		/bin/bash "\$zbmbuilddir"/remote-ssh-build.sh$zbm_builder_passthrough

		##dropbear/tor aren't version-pinned like zbm_ref/zbm_builder_image -- xbps-query records what Void's
		##rolling repo actually installed, for check-zbm-updates.sh to diff against later. Best-effort.
		{
			podman run --rm --entrypoint xbps-query "${zbm_builder_image:-ghcr.io/void-linux/void-glibc-full}" -M -R --property=pkgver dropbear
			podman run --rm --entrypoint xbps-query "${zbm_builder_image:-ghcr.io/void-linux/void-glibc-full}" -M -R --property=pkgver tor
		} > "\$zbmbuilddir"/last-build-versions.txt 2>/tmp/zbm-version-capture.log \\
			|| echo "Warning: could not record dropbear/tor versions for the update checker -- see /tmp/zbm-version-capture.log."
	EOW
	chmod +x /etc/zfsbootmenu/rebuild-zbm-remote.sh

	/bin/bash /tmp/remote_zbm_access.sh

	cat <<-EOU >/etc/zfsbootmenu/check-zbm-updates.sh
		#!/bin/sh
		##Non-interactive counterpart to check_pinned_upstream_versions(), plus a dropbear/tor version
		##diff against last-build-versions.txt. Run daily by zbm-check-updates.timer.
		set -eu

		zbm_ref="$zbm_ref"
		zbm_builder_image="$zbm_builder_image"
		remoteaccess_tor="$remoteaccess_tor"
		env_name="$env_name"
		statusfile=/var/lib/zfsbootmenu/update-check-status
		last_build_versions=/etc/zfsbootmenu/last-build-versions.txt

		mkdir -p "\$(dirname "\$statusfile")"

		stale=""

		latest_zbm_ref="\$(curl -sSf --max-time 10 "https://api.github.com/repos/zbm-dev/zfsbootmenu/releases/latest" 2>/dev/null | grep -m1 '"tag_name"' | cut -d'"' -f4)" || true
		if [ -n "\$latest_zbm_ref" ] && [ "\$latest_zbm_ref" != "\$zbm_ref" ];
		then
			stale="\${stale}zfsbootmenu release: pinned \"\$zbm_ref\" in \${env_name}, latest is \"\$latest_zbm_ref\" -- update zbm_ref (buildenv) and re-run remoteaccess -- https://github.com/zbm-dev/zfsbootmenu/releases/tag/\${latest_zbm_ref}
		"
		fi

		if [ -n "\$zbm_builder_image" ];
		then
			image_repo="\${zbm_builder_image%:*}"
			pinned_tag="\${zbm_builder_image##*:}"
			ghcr_path="\${image_repo#ghcr.io/}"
			if printf '%s' "\$pinned_tag" | grep -Eq '^[0-9]{8}\$';
			then
				ghcr_token="\$(curl -sSf --max-time 10 "https://ghcr.io/token?scope=repository:\${ghcr_path}:pull&service=ghcr.io" 2>/dev/null | grep -o '"token":"[^"]*"' | cut -d'"' -f4)" || true
				if [ -n "\$ghcr_token" ];
				then
					latest_dated_tag="\$(curl -sSf --max-time 10 -H "Authorization: Bearer \$ghcr_token" "https://ghcr.io/v2/\${ghcr_path}/tags/list" 2>/dev/null | grep -o '"[0-9]\{8\}"' | tr -d '"' | sort -n | tail -1)" || true
					if [ -n "\$latest_dated_tag" ] && [ "\$latest_dated_tag" != "\$pinned_tag" ];
					then
						stale="\${stale}zbm-builder image: pinned tag \"\$pinned_tag\" in \${env_name}, latest is \"\$latest_dated_tag\" -- update zbm_builder_image (buildenv) and re-run remoteaccess -- https://github.com/orgs/zbm-dev/packages/container/package/zbm-builder
		"
					fi
				fi
			fi
		fi

		query_image="\${zbm_builder_image:-ghcr.io/void-linux/void-glibc-full}"
		current_dropbear="\$(podman run --rm --entrypoint xbps-query "\$query_image" -M -R --property=pkgver dropbear 2>/dev/null)" || current_dropbear=""
		current_tor="\$(podman run --rm --entrypoint xbps-query "\$query_image" -M -R --property=pkgver tor 2>/dev/null)" || current_tor=""

		if [ -f "\$last_build_versions" ];
		then
			last_dropbear="\$(grep '^dropbear-' "\$last_build_versions" 2>/dev/null || true)"
			last_tor="\$(grep '^tor-' "\$last_build_versions" 2>/dev/null || true)"

			if [ -n "\$current_dropbear" ] && [ -n "\$last_dropbear" ] && [ "\$current_dropbear" != "\$last_dropbear" ];
			then
				stale="\${stale}dropbear: last build used \"\$last_dropbear\", Void currently has \"\$current_dropbear\" -- rebuild with /etc/zfsbootmenu/rebuild-zbm-remote.sh to pick it up
		"
			fi

			if [ "\$remoteaccess_tor" = "yes" ] && [ -n "\$current_tor" ] && [ -n "\$last_tor" ] && [ "\$current_tor" != "\$last_tor" ];
			then
				stale="\${stale}tor: last build used \"\$last_tor\", Void currently has \"\$current_tor\" -- rebuild with /etc/zfsbootmenu/rebuild-zbm-remote.sh to pick it up
		"
			fi
		fi

		printf '%s' "\$stale" > "\$statusfile"
	EOU
	chmod +x /etc/zfsbootmenu/check-zbm-updates.sh

	cat <<-'EOSV' >/etc/systemd/system/zbm-check-updates.service
		[Unit]
		Description=Check for zfsbootmenu/tor/dropbear updates not yet baked into the remote-access image
		After=network-online.target
		Wants=network-online.target

		[Service]
		Type=oneshot
		ExecStart=/etc/zfsbootmenu/check-zbm-updates.sh
	EOSV

	cat <<-'EOTM' >/etc/systemd/system/zbm-check-updates.timer
		[Unit]
		Description=Daily check for zfsbootmenu/tor/dropbear updates not yet baked into the remote-access image

		[Timer]
		OnCalendar=daily
		Persistent=true

		[Install]
		WantedBy=timers.target
	EOTM

	cat <<-'EOMOTD' >/etc/update-motd.d/85-zbm-updates
		#!/bin/sh
		statusfile=/var/lib/zfsbootmenu/update-check-status
		if [ -s "$statusfile" ];
		then
			echo "ZFSBootMenu remote-access image may be out of date:"
			sed 's/^/  /' "$statusfile"
		fi
	EOMOTD
	chmod +x /etc/update-motd.d/85-zbm-updates

	systemctl daemon-reload
	systemctl enable --now zbm-check-updates.timer

	##Remote unlock is only reachable while ZFSBootMenu is still on screen, so the countdown that is
	##fine for an unattended local boot is too short to connect within -- over Tor, the client alone
	##needs tens of seconds to bootstrap before it can even reach the service.
	refind_conf=/boot/efi/EFI/debian/refind_linux.conf
	if [ -f "$refind_conf" ];
	then
		##Rewriting just the timeout value keeps this idempotent across re-runs.
		sed -i '/"Boot default"/ s/zbm.timeout=[0-9]*/zbm.timeout='"$timeout_zbm_remote_access"'/' "$refind_conf"
		echo "ZFSBootMenu boot timeout raised to ${timeout_zbm_remote_access}s in ${refind_conf}, to leave time to connect before it boots the default environment."
		if [ -f /etc/zfsbootmenu/generate-zbm.post.d/esp-sync.sh ];
		then
			echo "Note: backup ESPs keep the old timeout until they are next synced (/etc/zfsbootmenu/generate-zbm.post.d/esp-sync.sh)."
		fi
	else
		echo "Warning: ${refind_conf} not found, so the ZFSBootMenu timeout was left as it is. If it is short, ZFSBootMenu may boot the default environment before you can connect."
	fi

	echo "Zfsbootmenu remote access installed. Connect as root on port 222 during boot: \"ssh root@{IP_ADDRESS or FQDN of zfsbootmenu} -p 222\""
	echo "The keys in remoteaccess_dropbear_pubkeys (${env_name}) are the ones that will work; to add more, update it there (\"$0 buildenv\") and re-run \"$0 remoteaccess\"."

	if [ "$remoteaccess_tor" = "yes" ];
	then
		echo "Tor onion service also installed. Onion address: \"$remoteaccess_tor_onion_hostname\""
		echo "Connect from a client holding the matching onion-auth private key, e.g.: \"torify ssh root@$remoteaccess_tor_onion_hostname -p 22\""
		echo "The client needs remoteaccess_tor_client_auth_pubkey's matching private key installed as ClientOnionAuthDir on its own end -- see README."
	fi

}

systemsetupFunc_part1(){

	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
		export DEBIAN_"${install_warning_level}"
	EOCHROOT

	cp /etc/apt/apt.conf.d/30apt_error_on_transient "$mountpoint"/etc/apt/apt.conf.d/

	echo "$hostname" > "$mountpoint"/etc/hostname
	echo "127.0.1.1       $hostname" >> "$mountpoint"/etc/hosts


	ethernetinterface_matches="$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${ethprefix}*" -printf '%f\n')"
	ethernetinterface_matchcount="$(printf '%s\n' "$ethernetinterface_matches" | grep -c . || true)"
	if [ "$ethernetinterface_matchcount" -eq 0 ];
	then
		echo "No ethernet interface found matching ethprefix=\"${ethprefix}\" in /sys/class/net."
		echo "Available interfaces: $(find /sys/class/net -maxdepth 1 -mindepth 1 -printf '%f ')"
		exit 1
	fi
	if [ "$ethernetinterface_matchcount" -gt 1 ];
	then
		echo "ethprefix=\"${ethprefix}\" matches more than one interface: $(printf '%s ' "$ethernetinterface_matches")."
		echo "Set ethprefix in ${env_name} to the full name of the interface you want to use instead of a shared prefix."
		exit 1
	fi
	ethernetinterface="$ethernetinterface_matches"
	echo "$ethernetinterface"

	mkdir -p "$mountpoint"/etc/systemd/network
	cat > "$mountpoint"/etc/systemd/network/10-"$ethernetinterface".network <<-EOF
		[Match]
		Name=$ethernetinterface

		[Network]
		DHCP=yes
	EOF
	chmod 644 "$mountpoint"/etc/systemd/network/10-"$ethernetinterface".network

	mount --make-private --rbind /dev  "$mountpoint"/dev
	mount --make-private --rbind /proc "$mountpoint"/proc
	mount --make-private --rbind /sys  "$mountpoint"/sys

	apt_sources "chroot" "${debian_archive_selected}"

	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
		##4.5 configure basic system
		apt update

		apt install -y locales tzdata systemd-resolved systemd-timesyncd

		#dpkg-reconfigure locales
		sed -i "s/^# *\($locale UTF-8\)/\1/" /etc/locale.gen || echo "$locale UTF-8" >> /etc/locale.gen
		locale-gen
		echo "LANG=$locale" > /etc/default/locale

		##set timezone
		ln -fs /usr/share/zoneinfo/"$timezone" /etc/localtime
		dpkg-reconfigure tzdata

		##Enable systemd-networkd/-resolved for the network config written above.
		systemctl enable systemd-networkd
		systemctl enable systemd-resolved
		rm -f /etc/resolv.conf
		ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

	EOCHROOT
}

systemsetupFunc_part2(){
	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
		##install zfs
		apt update

		apt install --no-install-recommends -y linux-image-amd64 linux-headers-amd64

		apt install --yes --no-install-recommends dkms wget nano build-essential

		apt install --yes zfsutils-linux zfs-dkms zfs-zed

		apt install --yes zfs-initramfs

		##Stable hostid, so both initramfs builds below embed the same value instead of each guessing one.
		zgenhostid -f

		echo "Waiting for the zfs DKMS module to build against the installed kernel..."
		dkms_wait_count=0
		while ! dkms status | grep -Eq "^zfs[/,].*: installed"; do
			dkms_wait_count=\$((dkms_wait_count + 1))
			if [ "\$dkms_wait_count" -gt 180 ]; then
				echo "Timed out waiting for the zfs DKMS module to build. Check 'dkms status' and /var/lib/dkms/zfs/*/build/make.log."
				exit 1
			fi
			sleep 2
		done

	EOCHROOT
}

systemsetupFunc_part3(){
	identify_debian_dataset_uuid

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
		partprobe || true ##See note in debootstrap_part1_Func: don't let an unrelated device abort under set -e.
		sleep 2
		blkid_part1=""
		blkid_part1="$(blkid -s UUID -o value /dev/disk/by-id/"${diskidnum}"-part1)"
		echo "$blkid_part1" >> /tmp/esp_partition_list_uuid.txt

		chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
			mkdir -p "${esp_mount}"

			##fstab entry. "nofail" so a missing or failed ESP does not drop the machine into an emergency
			##shell at boot: on a multi-disk topology every disk gets its own ESP, and losing one of them
			##must not cost the whole (otherwise perfectly bootable) system. That matters more than usual
			##here because this is a headless server -- an emergency shell needs console or IPMI access to
			##clear, while the system would otherwise have come up fine on the remaining disks.
			echo /dev/disk/by-uuid/"$blkid_part1" \
				"${esp_mount}" vfat \
				defaults,nofail \
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

	done < /tmp/diskid_check_root.txt

	apt-get -yq install efibootmgr

	efibootmgr_wait_count=0
	initial_boot_order=""
	while [ -z "$initial_boot_order" ];
	do
		initial_boot_order="$(efibootmgr 2>/dev/null | grep "BootOrder" | cut -d " " -f 2)" || true ##Just a liveness probe for EFI variable services here -- update_boot_manager() re-reads the live BootOrder itself when it actually needs it, rather than reusing this early snapshot.
		if [ -n "$initial_boot_order" ]; then
			break
		fi
		efibootmgr_wait_count=$((efibootmgr_wait_count + 1))
		if [ "$efibootmgr_wait_count" -gt 5 ]; then
			echo "efibootmgr could not read the firmware's BootOrder after ${efibootmgr_wait_count} attempts."
			echo "This usually means UEFI variable services are wedged (often from heavy NVRAM churn after repeated install attempts on this hardware)."
			echo "Try a full power-off/power-on cycle (not just a warm reboot) before running the script again."
			exit 1
		fi
		sleep 5
	done

	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
		apt-get -yq install refind kexec-tools
		apt install --yes dpkg-dev git systemd-sysv

		sed -i 's,^timeout .*,timeout $timeout_rEFInd,' /boot/efi/EFI/refind/refind.conf

		echo 'default_selection "EFI/debian"' >> /boot/efi/EFI/refind/refind.conf

		echo REMAKE_INITRD=yes > /etc/dkms/zfs.conf
		sed -i 's,LOAD_KEXEC=false,LOAD_KEXEC=true,' /etc/default/kexec
	EOCHROOT

}

systemsetupFunc_part4(){

	cp /tmp/diskid_check_root.txt "$mountpoint"/tmp/

	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
		encrypt_config(){
			if [ "$root_encryption_enabled" = "yes" ]; ##Flag, not the passphrase: this block runs under "bash -x".
			then
				set +x
				printf '%s' "$zfs_root_password" > /etc/zfs/$RPOOL.key
				set -x
				chmod 000 /etc/zfs/$RPOOL.key
				zfs change-key -o keylocation=file:///etc/zfs/$RPOOL.key -o keyformat=passphrase $RPOOL

				cat > /etc/initramfs-tools/hooks/zfs-root-key <<-'EOH'
					#!/bin/sh
					PREREQ=""
					prereqs() { echo "\$PREREQ"; }
					case "\$1" in
						prereqs) prereqs; exit 0 ;;
					esac
					. /usr/share/initramfs-tools/hook-functions

					copy_file config /etc/zfs/$RPOOL.key
					ret=\$?
					if [ "\$ret" -gt 1 ]; then
						echo "zfs-root-key: failed to copy /etc/zfs/$RPOOL.key into initramfs (copy_file returned \$ret)" >&2
						exit 1
					fi
					exit 0
				EOH
				chmod +x /etc/initramfs-tools/hooks/zfs-root-key

				zfs set org.zfsbootmenu:keysource="$RPOOL/ROOT/$rootzfs_full_name" $RPOOL
			else
				true
			fi

			echo "UMASK=0077" > /etc/initramfs-tools/conf.d/umask.conf ##Set access rights for initramfs images generated by mkinitramfs.

		}
		encrypt_config
	EOCHROOT

	##No spl_hostid= here: ZFSBootMenu passes through the hostid it actually imported with by default, and
	##strips any spl_hostid it finds in this commandline override first -- hand-setting it here was a no-op.
	##Import policy is also left at upstream's forgiving "hostid" default rather than "strict", a deliberate
	##choice: this is a headless/remote box, and refusing to auto-boot on any mismatch is a worse failure mode
	##than silently importing now that the hostid is actually stable. Add zbm.import_policy=strict below to
	##change that.
	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
			if [ "$quiet_boot" = "yes" ]; then
				zfs set org.zfsbootmenu:commandline="ro quiet" "$RPOOL"/ROOT
			else
				zfs set org.zfsbootmenu:commandline="ro" "$RPOOL"/ROOT
			fi
	EOCHROOT

	zfsbootmenu_install_config_container_Func

	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
		##Update refind_linux.conf
		config_refind(){
			##zfsbootmenu command-line parameters:
			##https://github.com/zbm-dev/zfsbootmenu/blob/master/pod/zfsbootmenu.7.pod
			cat <<-EOF > /boot/efi/EFI/debian/refind_linux.conf
				"Boot default"  "zbm.timeout=$timeout_zbm_no_remote_access ro quiet loglevel=0"
				"Boot to menu"  "zbm.show ro quiet loglevel=0"
			EOF

			if [ "$quiet_boot" = "no" ]; then
				sed -i 's,ro quiet,ro,' /boot/efi/EFI/debian/refind_linux.conf
			fi
		}
		config_refind
	EOCHROOT

	zbm_multiple_ESP(){
		esp_sync_path="/etc/zfsbootmenu/generate-zbm.post.d/esp-sync.sh"
		chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
			mkdir -p "/etc/zfsbootmenu/generate-zbm.post.d/"

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
			apt install --yes rsync
			sh "$esp_sync_path" ##Sync main ESP to backup ESPs.

		EOCHROOT

		update_boot_manager(){
			loop_counter="$(mktemp)"
			echo 0 > "$loop_counter" ##Assign starting counter value.
			backup_esp_hexes_file="/tmp/backup_esp_hexes.txt"
			true > "$backup_esp_hexes_file" ##Boot numbers firmware actually assigned to each backup entry, in creation order.
			while IFS= read -r diskidnum;
			do
				i="$(cat "$loop_counter")"
				echo "$i"
				if [ "$i" -eq 0 ];
				then
					true
				else
					device_name="$(readlink -f /dev/disk/by-id/"${diskidnum}")"

					existing_backup_hexes="$(efibootmgr | grep -w "rEFInd Boot Manager Backup $i" | cut -d " " -f 1 | sed 's,Boot,,' | sed 's,*,,')"
					if [ -n "$existing_backup_hexes" ]; then
						printf '%s\n' "$existing_backup_hexes" | while read -r existing_hex;
						do
							efibootmgr -b "$existing_hex" -B || true ##Already gone is a success state here, not a failure.
						done
					fi

					efibootmgr --create --disk "${device_name}" --label "rEFInd Boot Manager Backup $i" --loader \\EFI\\refind\\refind_x64.efi

					efibootmgr | grep -w "rEFInd Boot Manager Backup $i" | cut -d " " -f 1 | sed 's,Boot,,' | sed 's,*,,' >> "$backup_esp_hexes_file"
				fi
				i=$((i + 1)) ##Increment counter.
				echo "$i" > "$loop_counter"
			done < /tmp/diskid_check_root.txt

			stale_esp_hexes="$(efibootmgr | grep -v "Backup" | grep -w "rEFInd Boot Manager" | cut -d " " -f 1 | sed 's,Boot,,' | sed 's,*,,')"
			if [ -n "$stale_esp_hexes" ]; then
				printf '%s\n' "$stale_esp_hexes" | while read -r stale_hex;
				do
					efibootmgr -b "$stale_hex" -B || true ##Already gone is a success state here, not a failure.
				done
			fi

			primary_diskidnum="$(head -n1 /tmp/diskid_check_root.txt)"
			primary_device_name="$(readlink -f /dev/disk/by-id/"${primary_diskidnum}")"
			efibootmgr --create --disk "${primary_device_name}" --label "rEFInd Boot Manager" --loader \\EFI\\refind\\refind_x64.efi
			primary_esp_hex="$(efibootmgr | grep -v "Backup" | grep -w "rEFInd Boot Manager" | cut -d " " -f 1 | sed 's,Boot,,' | sed 's,*,,')"

			current_boot_order="$(efibootmgr | grep "BootOrder" | cut -d " " -f 2)"
			revised_boot_order="${primary_esp_hex}"
			while IFS= read -r backup_hex;
			do
				[ -n "$backup_hex" ] || continue
				revised_boot_order="${revised_boot_order},${backup_hex}"
			done < "$backup_esp_hexes_file"
			old_ifs="$IFS"
			IFS=','
			for order_hex in $current_boot_order;
			do
				IFS="$old_ifs"
				case ",${revised_boot_order}," in
					*",${order_hex},"*) continue ;;
				esac
				revised_boot_order="${revised_boot_order},${order_hex}"
				IFS=','
			done
			IFS="$old_ifs"

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

}

systemsetupFunc_part5(){

	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
		set +x
		printf '%s\n' "root:$PASSWORD" | chpasswd -c SHA256
		set -x
	EOCHROOT

	crypttab_parameters="/dev/urandom plain,swap,cipher=aes-xts-plain64:sha256,size=512"

	mdadm_swap_Func(){
		mdadm_swap_loc="/tmp/multi_disc_swap.sh"
		mdadm_level="$1" ##ZFS raidz = MDADM raid5, raidz2 = raid6. MDADM does not have raid7, so no triple parity equivalent to raidz3.
		mdadm_devices="$2" ##Number of disks.

		cat > "$mdadm_swap_loc" <<-EOF
			##Swap setup for mirror or raidz topology.
			apt install --yes mdadm
		EOF

		while IFS= read -r diskidnum;
		do
			cat >> "$mdadm_swap_loc" <<-EOF
				mdadm --stop --scan || true
				wipefs -a /dev/disk/by-id/${diskidnum}-part2 || true
			EOF
		done < /tmp/diskid_check_root.txt

		cat >> "$mdadm_swap_loc" <<-EOF
			##Set MDADM level and number of disks.
			mdadm --create /dev/md0 --metadata=1.2 \\
			--level="$mdadm_level" \\
			--raid-devices="$mdadm_devices" \\
			--bitmap=none \\
			--verbose \\
		EOF

		while IFS= read -r diskidnum;
		do
			echo "/dev/disk/by-id/${diskidnum}-part2 \\" >> "$mdadm_swap_loc"
		done < /tmp/diskid_check_root.txt

		sed -i '$s,\\,,' "$mdadm_swap_loc" ##Remove escape characters needed for last line of EOF code block.

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

		cat >> "$mdadm_swap_loc" <<-EOF
			mdadm --detail --scan --prefer=by-id --verbose | tee -a /etc/mdadm/mdadm.conf
		EOF

		cat >> "$mdadm_swap_loc" <<-EOF
			cat /proc/mdstat
			mdadm --detail /dev/md0
		EOF

		cp "$mdadm_swap_loc" "$mountpoint"/tmp/
		chroot "$mountpoint" /bin/bash -ex "$mdadm_swap_loc"
	}

	case "$topology_root" in
		single)
			if [ -n "$zfs_root_password" ];
			then
				DISKID="$(cat /tmp/diskid_check_root.txt)"
				chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
					apt install --yes cryptsetup
					echo swap /dev/disk/by-id/"$DISKID"-part2 ${crypttab_parameters} >> /etc/crypttab
					echo /dev/mapper/swap none swap defaults 0 0 >> /etc/fstab
				EOCHROOT
			else
				blkid_part2=""
				DISKID="$(cat /tmp/diskid_check_root.txt)"
				chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
					mkswap -f /dev/disk/by-id/"$DISKID"-part2
					blkid_part2="\$(blkid -s UUID -o value /dev/disk/by-id/$DISKID-part2)"
					echo /dev/disk/by-uuid/\${blkid_part2} none swap defaults 0 0 >> /etc/fstab
					sleep 2
					##Activating swap inside the chroot is a convenience, not a requirement -- the fstab entry
					##written above is what matters at boot. Don't let it abort the install under "set -e".
					swapon -a || echo "swapon -a failed in the chroot. The fstab entry is written; swap will be activated on first boot."
				EOCHROOT
			fi
		;;

		mirror)
			mdadm_swap_Func "mirror" "$disks_root"
		;;

		raid0)
			loop_counter="$(mktemp)"
			echo 0 > "$loop_counter" ##Assign starting counter value.
			while IFS= read -r diskidnum;
			do
				i="$(cat "$loop_counter")"
				echo "$i"
				swap_part_num="swap$i"

				if [ -n "$zfs_root_password" ];
				then
					echo "${swap_part_num}" /dev/disk/by-id/"${diskidnum}"-part2 "${crypttab_parameters}" >> "${mountpoint}"/etc/crypttab
					echo /dev/mapper/"${swap_part_num}" none swap defaults,pri=1 0 0 >> "${mountpoint}"/etc/fstab

				else
					mkswap -f /dev/disk/by-id/"${diskidnum}"-part2
					blkid_part2=""
					blkid_part2="$(blkid -s UUID -o value /dev/disk/by-id/"${diskidnum}"-part2)"
					echo /dev/disk/by-uuid/"${blkid_part2}" none swap defaults,pri=1 0 0 >> "${mountpoint}"/etc/fstab
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

	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
		systemctl enable tmp.mount || echo "tmp.mount unit not found; leaving /tmp as-is (unexpected on modern systemd)."

		echo RESUME=none > /etc/initramfs-tools/conf.d/resume
	EOCHROOT

	if [ -n "$zfs_arc_max_mb" ] || [ -n "$zfs_arc_min_mb" ];
	then
		: > "$mountpoint"/etc/modprobe.d/zfs.conf
		[ -n "$zfs_arc_max_mb" ] && echo "options zfs zfs_arc_max=$(( zfs_arc_max_mb * 1024 * 1024 ))" >> "$mountpoint"/etc/modprobe.d/zfs.conf
		[ -n "$zfs_arc_min_mb" ] && echo "options zfs zfs_arc_min=$(( zfs_arc_min_mb * 1024 * 1024 ))" >> "$mountpoint"/etc/modprobe.d/zfs.conf
	fi

	chroot "$mountpoint" /bin/bash -ex <<-"EOCHROOT"

		##Refresh initrd files

		ls /usr/lib/modules

		update-initramfs -u -k all

	EOCHROOT

}

usersetup(){
	zfs create -o mountpoint=/home/"$user" "$RPOOL"/home/"${user}"

	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT

		apt install --yes sudo

		apt install --yes openssh-server
		systemctl enable ssh

		apt install --yes curl ca-certificates

		adduser --disabled-password --gecos "" "$user"
		cp -a /etc/skel/. /home/"$user"
		chown -R "$user":"$user" /home/"$user"
		for admin_group in adm cdrom dip plugdev sudo;
		do
			if getent group "\$admin_group" >/dev/null;
			then
				usermod -a -G "\$admin_group" "$user"
			else
				echo "Group \$admin_group does not exist in the new installation. Skipping it."
			fi
		done
		set +x
		printf '%s\n' "$user:$PASSWORD" | chpasswd
		set -x

		mkdir -p /home/"$user"/.ssh
		touch /home/"$user"/.ssh/authorized_keys
		chmod 700 /home/"$user"/.ssh
		chmod 600 /home/"$user"/.ssh/authorized_keys
		chown -R "$user":"$user" /home/"$user"/.ssh

		passwd -dl root

	EOCHROOT

	if [ -n "$admin_ssh_pubkeys" ];
	then
		key_count=0
		: > "$mountpoint"/home/"$user"/.ssh/authorized_keys
		while IFS= read -r admin_ssh_pubkey_line;
		do
			if [ -n "$admin_ssh_pubkey_line" ];
			then
				echo "$admin_ssh_pubkey_line" >> "$mountpoint"/home/"$user"/.ssh/authorized_keys
				key_count=$((key_count + 1))
			else true
			fi
		done <<-EOKEYS
			$admin_ssh_pubkeys
		EOKEYS
		chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
			chown "$user":"$user" /home/"$user"/.ssh/authorized_keys
			chmod 600 /home/"$user"/.ssh/authorized_keys
		EOCHROOT
		echo "$key_count SSH public key(s) from admin_ssh_pubkeys installed into /home/$user/.ssh/authorized_keys."
	else
		echo "No admin_ssh_pubkeys set. Add your SSH public key(s) to ${mountpoint}/home/${user}/.ssh/authorized_keys before rebooting, or you will need console/IPMI access to log in."
	fi
}

distroinstall(){

	export DEBIAN_"${install_warning_level}"

	apt update

	apt dist-upgrade --yes

	apt install -y tasksel
	tasksel install standard

	apt install --yes openssh-server
	systemctl enable --now ssh

}

sanoid_install(){
	##snapshot and replication management
	##https://github.com/jimsalterjrs/sanoid
	apt update
	apt install -y sanoid

	mkdir -p /etc/sanoid
	cat > /etc/sanoid/sanoid.conf <<-EOF
		[$RPOOL/ROOT]
			use_template = production
			recursive = yes
			process_children_only = yes #Do not snapshot the parent dataset $RPOOL/ROOT. The OS root dataset is a child dataset of $RPOOL/ROOT.

		##Persistent, non-OS data. Not touched by ZFSBootMenu rollback (that only reverts \$RPOOL/ROOT), so it
		##gets its own, less sub-hourly-heavy retention -- protecting against accidental deletion over weeks
		##and months matters more here than fine-grained undo of the last few minutes.
		[$RPOOL/home]
			use_template = data
			recursive = yes #Covers every user's home directory and $RPOOL/home/root.

		[$RPOOL/srv]
			use_template = data

		[$RPOOL/usr/local]
			use_template = data

		[$RPOOL/var/log]
			use_template = data

		[$RPOOL/var/mail]
			use_template = data

		[$RPOOL/var/spool]
			use_template = data

		[$RPOOL/var/www]
			use_template = data

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

		[template_data]
			##No sub-hourly/hourly-heavy retention -- this template is for data, not for undoing the last
			##few minutes of an apt run. One hourly per day, then a month of dailies, then longer tails.
			hourly = 24
			daily = 30
			weekly = 8
			monthly = 12
			yearly = 0

			autosnap = yes
			autoprune = yes

	EOF

	pre-apt-snapshot(){
		pre_apt_prefix="pre-apt"

		cat > /etc/apt/apt.conf.d/80-zfs-snapshot <<-EOF

			DPkg::Pre-Invoke { "echo 'Creating ZFS snapshot.'; ts=${pre_apt_prefix}_\$(date +%F_%H:%M:%S); zfs snapshot -r $RPOOL/ROOT@\${ts} || true"; };

		EOF

		cat > /usr/local/bin/apt-snapshot-prune.sh <<-EOF
			#!/bin/sh
			##Prune the ZFS snapshots taken by the apt hook in /etc/apt/apt.conf.d/80-zfs-snapshot once they
			##are older than 7 days. They are created outside sanoid's control, so sanoid's own retention
			##policy in /etc/sanoid/sanoid.conf never expires them.

			prefix="${pre_apt_prefix}"
			snapshot_root="$RPOOL/ROOT"
			max_age_seconds=\$(( 7 * 24 * 3600 ))
			now="\$(date +%s)"

			##Search the dataset the hook actually snapshots. This used to substitute the output of
			##"zpool list" at install time, which froze the pool list as it stood on the day of the install --
			##a data pool added later was never searched, and a pool removed later made the command fail.
			zfs list -H -p -o name,creation -t snapshot -r "\$snapshot_root" |
			while read -r snapshot_name snapshot_creation;
			do
				##Match the prefix in the snapshot part of the name only. A bare "grep pre-apt" also matched
				##it anywhere in a dataset path, so a dataset that happened to contain that string would have
				##had its unrelated snapshots destroyed.
				case "\$snapshot_name" in
					*@"\$prefix"_*) ;;
					*) continue ;;
				esac

				age=\$(( now - snapshot_creation ))
				if [ "\$age" -gt "\$max_age_seconds" ];
				then
					echo "Destroying old \$prefix snapshot: \$snapshot_name (age \$(( age / 86400 )) days)"
					zfs destroy "\$snapshot_name" || echo "Could not destroy \$snapshot_name." >&2
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
			#Set lowest system priority. Note: systemd unit files have no inline comments -- a trailing
			#"##..." on these two lines made systemd log "Failed to parse nice priority" and ignore both
			#settings, so the prune ran at normal priority and competed with real work for disk IO.
			Nice=19
			#Only run when the disk is idle.
			IOSchedulingClass=3
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

		systemctl daemon-reload

		systemctl enable apt-snapshot-prune.timer

		systemctl start apt-snapshot-prune.timer || echo "Could not start apt-snapshot-prune.timer now. It is enabled and will start on the next boot."
		systemctl status apt-snapshot-prune.timer --no-pager || true

	}
	pre-apt-snapshot

	/usr/sbin/sanoid --take-snapshots --verbose ##Take ZFS snapshots and perform cleanup as per config file.

	systemctl enable --now sanoid.timer

}

logcompress(){
	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT

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

	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT

		apt install -y debconf-utils keyboard-configuration console-setup
		cat "${kb_console_settings}"
		debconf-set-selections < "${kb_console_settings}"

		rm -f /etc/default/keyboard

		dpkg-reconfigure -f noninteractive keyboard-configuration
		dpkg-reconfigure -f noninteractive console-setup

	EOCHROOT
}

fixfsmountorder(){

	identify_debian_dataset_uuid

	chroot "$mountpoint" /bin/bash -ex <<-EOCHROOT
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
		zed_wait_count=0
		while [ ! -s /etc/zfs/zfs-list.cache/$RPOOL ]
		do
			zed_wait_count=\$((zed_wait_count + 1))
			if [ "\$zed_wait_count" -gt 180 ]; then
				echo "Timed out waiting for zed to populate /etc/zfs/zfs-list.cache/$RPOOL. Check that zfs-zed/zed is installed and working."
				exit 1
			fi
			zfs set canmount=noauto $RPOOL/ROOT/${rootzfs_full_name}
			sleep 1
		done
		cat /etc/zfs/zfs-list.cache/$RPOOL

		##Stop zed. "-x" for an exact process-name match: the old "zed*" was an extended regular expression,
		##not a glob, so it meant "ze" followed by any number of "d" -- it would have matched a process
		##called "ze" and would not have matched anything the glob was intended to catch.
		##"|| true" because pkill exits 1 when it matched nothing, which is a normal outcome here (zed may
		##already have exited) and must not abort the chroot now that it runs under "set -e".
		pkill -9 -x zed || true
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

export_pool_for_reboot(){
	echo "Unmounting the new installation and exporting ${RPOOL} before reboot..."

	mount --make-rslave "$mountpoint"/dev 2>/dev/null || true
	mount --make-rslave "$mountpoint"/proc 2>/dev/null || true
	mount --make-rslave "$mountpoint"/sys 2>/dev/null || true

	umount -l "$mountpoint"/proc/sys/fs/binfmt_misc 2>/dev/null || true
	umount -l "$mountpoint"/sys/fs/cgroup 2>/dev/null || true
	umount -l "$mountpoint"/dev/pts 2>/dev/null || true
	umount -R "$mountpoint"/dev 2>/dev/null || true
	umount -R "$mountpoint"/proc 2>/dev/null || true
	umount -R "$mountpoint"/sys 2>/dev/null || true

	mount | awk -v mp="${mountpoint}/boot/efi" '$3 == mp || index($3, mp"/") == 1 || index($3, mp) == 1 {print $3}' | sort -r | while read -r esp_mounted;
	do
		umount "$esp_mounted" 2>/dev/null || true
	done

	umount "$mountpoint"/run 2>/dev/null || true

	command -v udevadm >/dev/null 2>&1 && udevadm settle --timeout=10 2>/dev/null || true

	if zpool export "$RPOOL" 2>/dev/null;
	then
		echo "${RPOOL} exported cleanly. The new system will import it normally on first boot."
	else
		echo "Could not export ${RPOOL} -- something still has a file open under ${mountpoint}."
		echo "This is not fatal: the installation is complete, and ZFSBootMenu will import the pool at boot regardless (it may report that the pool was last used by another system)."
		echo "To export it by hand before rebooting: fuser -vm ${mountpoint} , then zpool export ${RPOOL}"
	fi
}

setupremoteaccess(){
	verify_env

	##Checked before anything else: this stage writes to the installed system's /etc/zfsbootmenu and
	##rebuilds the image on its ESP, none of which the live environment has -- and anything it did
	##generate there (an onion service identity, say) would be lost at the next reboot.
	if in_live_environment;
	then
		echo "Live environment present. Reboot into the new installation and run this option there."
		exit 1
	fi

	zbm_raw_url="https://raw.githubusercontent.com/zbm-dev/zfsbootmenu/${zbm_ref}"

	if [ -d /etc/zfsbootmenu/dropbear ];
	then
		##Re-running is how settings get changed after the fact -- enabling Tor later, rotating the
		##onion client-auth key, switching to a static IP -- so this is a note, not a refusal. The
		##existing dropbear host keys in that directory are left alone (upstream's script only creates
		##the ones that are missing), so clients don't see a changed host key.
		echo "Remote access already appears to be installed (/etc/zfsbootmenu/dropbear exists). Re-running to apply the current settings in ${env_name}; the existing dropbear host keys are kept."
	fi

	disclaimer
	check_pinned_upstream_versions
	update_date_time
	remote_zbm_access_container_Func
}

createdatapool(){
	verify_env
	disclaimer
	update_date_time

	if [ "$(zpool status "$datapool")" ];
	then
		echo "Warning: $datapool already exists. Are you use you want to wipe the drive and destroy $datapool? Press Enter to Continue or CTRL+C to abort."
		read -r _

		##Still imported at this point (that's how the check above found it), and clear_partition_table's
		##wipefs will fail as "busy" against a disk an imported pool is still holding -- export first, same
		##retry/force pattern as cleanup_prior_attempt() uses for $RPOOL.
		echo "Exporting $datapool so its disk(s) can be wiped..."
		zpool export "$datapool" 2>/dev/null || true
		command -v udevadm >/dev/null 2>&1 && udevadm settle --timeout=10 2>/dev/null || true

		if zpool list -H -o name 2>/dev/null | grep -qx "$datapool";
		then
			zpool export -f "$datapool" 2>/dev/null || true
			command -v udevadm >/dev/null 2>&1 && udevadm settle --timeout=10 2>/dev/null || true
		fi

		if zpool list -H -o name 2>/dev/null | grep -qx "$datapool";
		then
			echo "Pool ${datapool} is still imported and cannot be exported -- check what has it open (e.g. fuser -vm ${datapoolmount}) and retry." >&2
			exit 1
		fi
	else
		echo "$datapool pre-existance check passed."
	fi

	if [ -n "$zfs_data_password" ];
	then
		echo "Warning: Encryption selected. A dedicated keyfile will be stored at /etc/zfs/$datapool.key on the root filesystem to auto unlock the data pool at boot -- it's only readable once the root pool has already been unlocked, so only the root pool will prompt. Press Enter to Continue or CTRL+C to abort."
		read -r _
	else true
	fi

	getdiskID_pool "data"

	clear_partition_table "data"
	partprobe || true ##See note in debootstrap_part1_Func: don't let an unrelated device abort under set -e.
	sleep 2

	if [ -d "$datapoolmount" ]; then
		echo "Data pool mount point exists."
	else
		mkdir -p "$datapoolmount"
		chown "$user":"$user" "$datapoolmount"
		echo "Data pool mount point created."
	fi
	echo "$datapoolmount"

	touch /etc/zfs/zfs-list.cache/"$datapool"

	create_zpool_Func "data"

	if [ -n "$datapool_native_keyloc" ];
	then
		identify_debian_dataset_uuid
		zfs set org.zfsbootmenu:keysource="$RPOOL/ROOT/$rootzfs_full_name" "$datapool"
	fi

	cat /etc/zfs/zfs-list.cache/"$datapool"
	zed_wait_count=0
	while [ ! -s /etc/zfs/zfs-list.cache/"$datapool" ]
	do
		zed_wait_count=$((zed_wait_count + 1))
		if [ "$zed_wait_count" -gt 180 ]; then
			echo "Timed out waiting for zed to populate /etc/zfs/zfs-list.cache/$datapool. Check that zfs-zed/zed is installed and working."
			exit 1
		fi
		zfs set canmount=on "$datapool"
		sleep 1
	done
	cat /etc/zfs/zfs-list.cache/"$datapool"

	chown -R "$user":"$user" "$datapoolmount"

	if [ -f /etc/sanoid/sanoid.conf ];
	then
		if grep -qF "[$datapool]" /etc/sanoid/sanoid.conf;
		then
			echo "$datapool already has a snapshot policy in /etc/sanoid/sanoid.conf, leaving it as-is."
		else
			##Appended, not regenerated -- sanoid_install() only runs once, during postreboot, so
			##regenerating the whole file here would silently discard any policy edits made since then.
			cat >> /etc/sanoid/sanoid.conf <<-EOF

				[$datapool]
					use_template = data
					recursive = yes

			EOF
			echo "Added $datapool to /etc/sanoid/sanoid.conf, using the same 'data' retention template as home/srv/etc (see sanoid_install)."
			/usr/sbin/sanoid --take-snapshots --verbose ##Take an initial snapshot now rather than waiting for the next sanoid.timer tick.
		fi
	else
		echo "Warning: /etc/sanoid/sanoid.conf not found -- sanoid isn't installed yet (that normally happens during \"postreboot\"). $datapool will not be snapshotted automatically until you run postreboot, or add a [$datapool] section to /etc/sanoid/sanoid.conf by hand."
	fi

	zpool status
	zfs list

}

case "$run_mode" in
	initial|postreboot|remoteaccess|datapool)
		logFunc
	;;
esac
date

initialinstall(){
	verify_env

	debian_archive_selected="${mirror_archive_url:-$debian_original}"

	zbm_raw_url="https://raw.githubusercontent.com/zbm-dev/zfsbootmenu/${zbm_ref}"

	if [ -n "$zfs_root_password" ];
	then
		root_encryption_enabled="yes"
	else
		root_encryption_enabled="no"
	fi

	disclaimer
	live_debian_check
	connectivity_check
	check_pinned_upstream_versions
	cleanup_prior_attempt
	getdiskID_pool "root"
	ipv6_apt_live_iso_fix
	update_date_time

	debootstrap_part1_Func
	debootstrap_createzfspools_Func
	debootstrap_installminsys_Func
	systemsetupFunc_part1 #Basic system configuration.
	systemsetupFunc_part2 #Install zfs.
	systemsetupFunc_part3 #Format EFI partition.

	keyboard_console_setup #Configure keyboard and console.
	systemsetupFunc_part4 #Install zfsbootmenu.
	systemsetupFunc_part5 #Config swap, tmpfs, rootpass.

	usersetup #Create user account, groups, and SSH access.
	logcompress #Disable log compression.
	reinstate_apt "chroot" #Reinstate non-mirror package sources in new install.
	script_copy #Copy script to new installation.
	fixfsmountorder #ZFS file system mount ordering.
	logcopy #Copy install log to new installation.

	export_pool_for_reboot #Unmount the new installation and export the pool so first boot imports it cleanly.

	echo "Initial minimal system setup complete."
	echo "Reboot required to complete installation."
	echo "First login is user \"${user}\", with the password set in PASSWORD in ${env_file}."
	echo "Following reboot, run script with postreboot option to complete installation."
	echo "Reboot."
}

postreboot(){
	verify_env
	disclaimer
	connectivity_check
	update_date_time

	distroinstall #Upgrade the minimal system to a full standard server (openssh-server already active since "initial").
	sanoid_install #Snapshot and replication management.
	reinstate_apt "base" #Reinstate non-mirror package sources in new install.

	echo "Installation complete."
	echo "SSH is enabled. Connect as ${user}@<host-ip> using your configured SSH key."
	echo "Reboot."
}

prompt_var(){
	var_name="$1"
	description="$2"
	current_value="$(eval "printf '%s' \"\${${var_name}-}\"")"
	echo "$description"
	##Prefilled and editable, not just shown -- Enter alone resubmits it unchanged, but backspacing it away
	##and pressing Enter explicitly clears the variable, which a bare "keep unless non-empty" read can't do.
	# shellcheck disable=SC2034 #new_input used indirectly via eval below
	read -r -e -i "$current_value" -p "${var_name}: " new_input
	eval "${var_name}=\$new_input"
}

prompt_topology_var(){
	var_name="$1"
	description="$2"
	while true;
	do
		prompt_var "$var_name" "$description"
		current_value="$(eval "printf '%s' \"\${${var_name}-}\"")"
		case "$current_value" in
			single|mirror|raid0|raidz1|raidz2|raidz3) break ;;
			*) echo "\"${current_value}\" is not a recognised topology. Use single, mirror, raid0, raidz1, raidz2, or raidz3." ;;
		esac
	done
}

prompt_disk_count_var(){
	var_name="$1"
	description="$2"
	pool="$3"

	topology_value_pointer="topology_${pool}"
	eval topology_value_pointer="\$${topology_value_pointer}"

	case "$topology_value_pointer" in
		single) min_disks="1" ;;
		mirror|raid0|raidz1) min_disks="2" ;;
		raidz2) min_disks="3" ;;
		raidz3) min_disks="4" ;;
		*) min_disks="1" ;; ##Unreachable: prompt_topology_var() already validated topology_${pool}.
	esac

	while true;
	do
		prompt_var "$var_name" "$description"
		current_value="$(eval "printf '%s' \"\${${var_name}-}\"")"
		if ! [ "$current_value" -eq "$current_value" ] 2>/dev/null || [ "$current_value" -lt "$min_disks" ];
		then
			echo "\"${current_value}\" is not a valid disk count -- topology_${pool}=\"${topology_value_pointer}\" needs at least ${min_disks}."
			continue
		fi
		break
	done
}

prompt_multiline_var(){
	var_name="$1"
	description="$2"
	current_value="$(eval "printf '%s' \"\${${var_name}-}\"")"

	echo "$description"
	if [ -n "$current_value" ];
	then
		echo "Current value:"
		printf '%s\n' "$current_value" | sed 's/^/  /'
	fi
	echo "Enter one per line; an empty line finishes. Just press Enter (no lines at all) to keep the current value, or enter a single \"-\" to clear it."

	got_a_line=""
	new_value=""
	while IFS= read -r line_in;
	do
		[ -z "$line_in" ] && break
		if [ -z "$got_a_line" ] && [ "$line_in" = "-" ];
		then
			new_value=""
			got_a_line="clear"
			break
		fi
		new_value="${new_value}${new_value:+$'\n'}${line_in}"
		got_a_line="yes"
	done

	if [ -n "$got_a_line" ];
	then
		eval "${var_name}=\$new_value"
	fi
}

ENV_VAR_ORDER="debianver user PASSWORD hostname admin_ssh_pubkeys zfs_root_password zfs_root_encrypt locale
timezone keyboard_layoutcode zfs_rpool_ashift mirror_archive_url RPOOL topology_root disks_root disks_root_ids
EFI_boot_size swap_size zfs_arc_max_mb zfs_arc_min_mb datapool topology_data disks_data disks_data_ids zfs_data_password zfs_data_encrypt
datapoolmount zfs_dpool_ashift zfs_compression mountpoint timeout_rEFInd timeout_zbm_no_remote_access
timeout_zbm_remote_access zbm_ref zbm_builder_image quiet_boot ethprefix install_log log_loc ipv6_apt_fix_live_iso
remoteaccess_ip_config remoteaccess_ip remoteaccess_netmask remoteaccess_gateway remoteaccess_dropbear_pubkeys remoteaccess_tor
remoteaccess_tor_client_auth_pubkey remoteaccess_tor_start_delay remoteaccess_tor_onion_secret_key remoteaccess_tor_onion_public_key
remoteaccess_tor_onion_hostname debian_original debian_security_original install_warning_level"

write_env_file(){
	tmp_env_file="$(mktemp "${env_file}.XXXXXX")"

	{
		for var_name in $ENV_VAR_ORDER;
		do
			eval "printf '%s=%q\n' \"$var_name\" \"\${${var_name}-}\""
		done
	} > "$tmp_env_file"

	# shellcheck disable=SC1090 #tmp_env_file is a freshly-generated mktemp path, not a fixed source to lint
	if ! ( set +u; . "$tmp_env_file" ) >/dev/null 2>&1;
	then
		echo "Generated ${env_name} failed to parse -- not replacing the existing file. Left for inspection at ${tmp_env_file}."
		exit 1
	fi

	mv "$tmp_env_file" "$env_file"
	chmod 600 "$env_file"
	echo "Wrote ${env_file}."
}

buildenv(){
	debianver="trixie" #Debian release to install. "trixie" (13), "bookworm" (12).
	user="testuser" #Username for new install.
	PASSWORD="testuser" #Password for user in new install.
	hostname="debian" #Name to identify the main system on the network. An underscore is DNS non-compliant.
	admin_ssh_pubkeys="" #Optional. Paste one or more SSH public keys here (e.g. "ssh-ed25519 AAAA...C3NzaC1lZDI1NTE5 user@host"),
		#one per line, to have them pre-installed into the new user's authorized_keys, so SSH works immediately after
		#first boot. Only used for logging into the running OS -- see remoteaccess_dropbear_pubkeys below for the
		#separate, pre-boot disk-unlock key set. For more than one key, use a quoted multi-line value, e.g.:
		#admin_ssh_pubkeys="ssh-ed25519 AAAA...key1 user@laptop
		#ssh-ed25519 AAAA...key2 user@phone"
		#Leave "" to add keys manually to /home/$user/.ssh/authorized_keys before rebooting instead.
	zfs_root_password="testtest" #Password for encrypted root pool. Minimum 8 characters. "" for no password encrypted protection. Unlocking root pool also unlocks data pool, unless the root pool has no password protection, then a separate data pool password can be set below. This passphrase is stored in a keyfile at /etc/zfs/$RPOOL.key baked into the target kernel's own initramfs -- that keyfile lives only inside the encrypted root pool, never in ZFSBootMenu's own image on the unencrypted ESP, so ZFSBootMenu still can't reach it and still prompts for this passphrase at every boot (locally, or over SSH if the "remoteaccess" step is set up -- see README). The target OS's own boot stage auto-unlocks silently from that keyfile instead of prompting a second time.
	zfs_root_encrypt="native" #Encryption type. "native" (native zfs encryption) is the only supported value. Required if there is a root pool password, otherwise ignored.
	locale="en_GB.UTF-8" #New install language setting.
	timezone="Europe/London" #New install timezone setting.
	keyboard_layoutcode="gb" #Keyboard layout for the live environment and new install (debconf keyboard-configuration/layoutcode). "gb" for UK, "us" for US, etc. Applied non-interactively -- no dialog pauses the install.
	zfs_rpool_ashift="12" #Drive setting for zfs pool. ashift=9 means 512B sectors (used by all ancient drives), ashift=12 means 4KiB sectors (used by most modern hard drives), and ashift=13 means 8KiB sectors (used by some modern SSDs).
	mirror_archive_url="" #"" to use the default Debian archive (deb.debian.org, which is already geo-DNS routed to a nearby
		#mirror, so no speed-test is needed the way the upstream Ubuntu script does one). Set to a full base URL, e.g.
		#"http://ftp.uk.debian.org/debian", to hardcode a specific mirror instead. Debian's security suite is always
		#fetched from debian_security_original below, regardless of this setting, since third-party mirrors don't carry it.
	RPOOL="rpool" #Root pool name.
	topology_root="single" #"single", "mirror", "raid0", "raidz1", "raidz2", or "raidz3" topology on root pool.
	disks_root="1" #Number of disks in array for root pool. Not used with single topology.
	# shellcheck disable=SC2034 #disks_root_ids used indirectly via eval in getdiskID()
	disks_root_ids="" #Required (checked by "initial"): /dev/disk/by-id name(s) for the root pool -- one per line, using
		#the same multi-line quoting pattern as admin_ssh_pubkeys above, in the order you want them added to the pool,
		#e.g. for a mirror:
		#disks_root_ids="ata-VBOX_HARDDISK_VBXXXXXXXX-XXXXXXXX
		#ata-VBOX_HARDDISK_VBYYYYYYYY-YYYYYYYY"
		#Must supply exactly as many lines as disks_root needs (1 for "single", disks_root's value otherwise). Run
		#"ls -la /dev/disk/by-id" in the live environment first to find the exact names for your hardware -- they're
		#rarely known ahead of time and differ per machine. Each ID is validated at "initial" time (must exist, must
		#not already be in use, must not be duplicated within the pool) -- but there is no interactive picker here;
		#that only exists in "buildenv" (which is the easier way to fill this in -- it lists /dev/disk/by-id for you).
	EFI_boot_size="512" #EFI boot loader partition size in mebibytes (MiB).
	swap_size="8192" #Swap partition size in mebibytes (MiB). Size of swap will be larger than defined here with Raidz topologies.
	zfs_arc_max_mb="15360"
	zfs_arc_min_mb="4096"
	datapool="datapool" #Non-root drive data pool name.
	topology_data="single" #"single", "mirror", "raid0", "raidz1", "raidz2", or "raidz3" topology on data pool.
	# shellcheck disable=SC2034 #disks_data used indirectly via eval in topology_min_disk_check()
	disks_data="1" #Number of disks in array for data pool. Not used with single topology.
	# shellcheck disable=SC2034 #disks_data_ids used indirectly via eval in getdiskID()
	disks_data_ids="" #Same as disks_root_ids above, but for the data pool -- required only once you actually run
		#"datapool" (verify_env doesn't check it for "initial"/"postreboot"/"remoteaccess"). Must supply exactly as
		#many lines as disks_data needs (1 for "single", disks_data's value otherwise).
	zfs_data_password="testtest" #Password for the data pool. Minimum 8 characters. "" for no password protection. This passphrase is stored in a keyfile at /etc/zfs/$datapool.key on the root filesystem (readable only once root is already unlocked), so the data pool auto-unlocks after root and only the root pool prompts at boot.
	zfs_data_encrypt="native" #Encryption type. "native" (native zfs encryption) is the only supported value. Required if there is a data pool password, otherwise ignored.
	datapoolmount="/mnt/$datapool" #Non-root drive data pool mount point in new install.
	zfs_dpool_ashift="12" #See notes for rpool ashift. If ashift is set too low, a significant read/write penalty is incurred. Virtually no penalty if set higher.
	zfs_compression="zstd" #"lz4" is the zfs default; "zstd" may offer better compression at a cost of higher cpu usage.
	mountpoint="/mnt/deb_server" #Mountpoint in live environment.
	timeout_rEFInd="3" #Timeout in seconds for rEFInd boot screen until default choice selected.
	timeout_zbm_no_remote_access="3" #Timeout in seconds for zfsbootmenu when no remote access enabled.
	timeout_zbm_remote_access="90" #Timeout in seconds for zfsbootmenu once the "remoteaccess" option has been run. Replaces
		#timeout_zbm_no_remote_access in refind_linux.conf at that point: the countdown is the whole window in which a remote
		#session can reach zfsbootmenu before it boots the default environment, and connecting over Tor alone costs the client
		#tens of seconds of bootstrapping. Only the countdown to an automatic boot -- an encrypted root still waits at its
		#passphrase prompt indefinitely, and this is also what makes remote snapshot rollback possible rather than just unlock.
	zbm_ref="v3.1.0" #Git tag of the zfsbootmenu release to build against (https://github.com/zbm-dev/zfsbootmenu/releases). Every fetch of zfsbootmenu source in this script derives its URL from this one value, so bumping it here is the only change needed to move to a newer release.
	zbm_builder_image="ghcr.io/zbm-dev/zbm-builder:20260101" #Container image used to build the ZFSBootMenu EFI executable (see zfsbootmenu_install_config_container_Func). Pinned to a dated tag rather than floating on upstream's ":latest", for the same reproducibility reason zbm_ref is pinned above -- pick the dated tag that was published alongside the zbm_ref release in use (check the release's "published_at" date against the tags at https://github.com/orgs/zbm-dev/packages/container/package/zbm-builder). Set to "" to fall back to upstream's floating ":latest" tag instead. Changing this after "initial" takes effect the next time "remoteaccess" is run (repin_zbm_builder_image_Func updates the persisted pin in /etc/zfsbootmenu/zbm-builder.conf).
	quiet_boot="yes" #Set to "no" to show boot sequence.
	ethprefix="e" #Prefix used to match the ethernet interface name under /sys/class/net (e.g. "eno1", "enp3s0", "eth0") to set up networking in the new install. Must match exactly one interface -- on multi-NIC servers, "e" alone will usually match more than one, so use the full interface name of the port you want.
	install_log="debian_setup_zfs_root.log" #Installation log filename.
	log_loc="/var/log" #Installation log location.
	ipv6_apt_fix_live_iso="no" #Try setting to "yes" if apt-get is slow in the Debian live environment. Doesn't affect ipv6 functionality in the new install.
	remoteaccess_ip_config="dhcp" #"dhcp", "dhcp,dhcp6", "dhcp6", or "static". Automatic (dhcp) or static IP assignment for zfsbootmenu remote access.
	remoteaccess_ip="192.168.0.222" #Remote access static IP address to connect to ZFSBootMenu. Not used for automatic IP configuration.
	remoteaccess_netmask="255.255.255.0" #Remote access subnet mask. Not used for "dhcp" automatic IP configuration.
	remoteaccess_gateway="192.168.0.1" #Remote access default gateway. Not used for "dhcp" automatic IP configuration. Set it to your LAN's real gateway (check with "ip route | grep default" on the box) -- required to reach zfsbootmenu from outside its own subnet, and dracut's static network setup expects it either way.
	remoteaccess_dropbear_pubkeys="" #Required (checked by "remoteaccess"): one or more SSH public keys, one per line (same
		#multi-line quoting pattern as admin_ssh_pubkeys above), authorized to unlock the pool pre-boot. Deliberately separate
		#from admin_ssh_pubkeys. Bare "<keytype> <key> [comment]" lines only -- no-agent-forwarding is added automatically,
		#and your own restrictions/options ahead of the key would break parsing.
	remoteaccess_tor="no" #Set to "yes" to also build a Tor v3 onion service into the zfsbootmenu remote access environment, alongside
		#the direct-IP dropbear access above (not instead of it). Lets you reach the pre-boot passphrase prompt over Tor
		#without port-forwarding or a known static IP. Requires remoteaccess_tor_client_auth_pubkey to be set. See README.
	remoteaccess_tor_client_auth_pubkey="" #Required if remoteaccess_tor="yes". The client's x25519 onion-service client-auth public key
		#(the "descriptor:x25519:..." line), so only a holder of the matching private key can even reach the onion service.
		#The script does not generate this keypair -- see README for the one-time generation steps, same as how
		#admin_ssh_pubkeys above is supplied rather than generated.
	remoteaccess_tor_start_delay="300" #Seconds to wait after the network comes up before starting tor in the ZFSBootMenu
		#remote access environment. Dropbear is reachable immediately either way -- tor is a fallback, not for
		#regular use, so it deliberately holds off this long before it even starts bootstrapping. See README.
	remoteaccess_tor_onion_secret_key="" #The onion service's identity: base64 of its hs_ed25519_secret_key file (96 decoded
		#bytes). Generated by "buildenv" when remoteaccess_tor="yes" (which is also where the tor package needed to work it
		#out gets installed, and offered for removal again), and written into the ZFSBootMenu image by "remoteaccess". Keeping
		#it here is what makes the .onion address survive a full reinstall with a fresh ESP, not just image rebuilds. Paste a
		#saved key in to adopt an existing address; leave "" to have a new one generated. See README.
	remoteaccess_tor_onion_public_key="" #Derived from remoteaccess_tor_onion_secret_key -- don't fill this in by hand.
		#Base64 of the matching hs_ed25519_public_key file (64 decoded bytes). "buildenv" works it out and stores it, and
		#clears it again whenever the secret key above changes.
	remoteaccess_tor_onion_hostname="" #Derived from remoteaccess_tor_onion_secret_key -- don't fill this in by hand. The
		#.onion address to connect to, stored so that the address is known without having to run tor on the server.
	debian_original="http://deb.debian.org/debian" #Default Debian archive.
	debian_security_original="http://security.debian.org/debian-security" #Debian security archive. Always a separate suite/host from the main archive; not affected by mirror_archive_url.
	install_warning_level="PRIORITY=critical" #"PRIORITY=critical", or "FRONTEND=noninteractive". Pause install to show critical messages only or do not pause (noninteractive).

	if [ -f "$env_file" ];
	then
		# shellcheck source=/dev/null
		. "$env_file"
	fi

	echo "=== ${env_name} setup wizard ==="
	echo "Every question below defaults to its current value (shown in brackets) -- press Enter to keep it."
	echo

	if [ -f "$env_file" ];
	then
		backup_file="${env_file}.bak-$(date +%Y%m%d%H%M%S)"
		cp "$env_file" "$backup_file"
		echo "Backed up existing config to ${backup_file}"
		echo
	fi

	if in_live_environment;
	then
		echo "--- Install fundamentals (only asked in the live environment -- these are fixed at \"initial\" and never revisited) ---"

		prompt_var debianver "Debian release to install. \"trixie\" (13) or \"bookworm\" (12)."
		prompt_var user "Username for the new install."
		prompt_var PASSWORD "Password for that user in the new install."
		prompt_var hostname "Name to identify the main system on the network. An underscore is DNS non-compliant."
		prompt_multiline_var admin_ssh_pubkeys "Optional. One or more SSH public keys (e.g. \"ssh-ed25519 AAAA...C3NzaC1lZDI1NTE5 user@host\") to pre-install into the new user's authorized_keys, so SSH works immediately after first boot. Leave empty to add keys manually before rebooting instead. This is for the running OS only -- see remoteaccess_dropbear_pubkeys below for the separate pre-boot disk-unlock key set."

		prompt_var zfs_root_password "Password for the encrypted root pool. Minimum 8 characters. Leave empty for no password/no encryption. Unlocking the root pool also unlocks the data pool unless the root pool has no password, in which case a separate data pool password can be set below."
		prompt_var zfs_root_encrypt "Encryption type for the root pool. \"native\" is the only supported value, and is required whenever zfs_root_password is set; leave empty only if zfs_root_password above is also empty."

		prompt_var locale "New install language setting, e.g. \"en_GB.UTF-8\"."
		prompt_var timezone "New install timezone setting, e.g. \"Europe/London\"."
		prompt_var keyboard_layoutcode "Keyboard layout for the live environment and new install (debconf keyboard-configuration/layoutcode). \"gb\" for UK, \"us\" for US, etc."

		prompt_var zfs_rpool_ashift "Root pool ashift. 9 = 512B sectors (ancient drives), 12 = 4KiB sectors (most modern hard drives), 13 = 8KiB sectors (some modern SSDs)."
		prompt_var mirror_archive_url "Leave empty to use the default Debian archive (deb.debian.org, already geo-DNS routed). Set to a full base URL, e.g. \"http://ftp.uk.debian.org/debian\", to hardcode a specific mirror instead."

		prompt_var RPOOL "Root pool name."
		prompt_topology_var topology_root "Root pool disk topology: \"single\", \"mirror\", \"raid0\", \"raidz1\", \"raidz2\", or \"raidz3\"."
		prompt_disk_count_var disks_root "Number of disks in the root pool array. Not used with \"single\" topology." root
		echo "Selecting disk(s) for the root pool -- carefully check each ID against what you actually want to destroy."
		wizard_select_disk_ids root

		prompt_var EFI_boot_size "EFI boot loader partition size in mebibytes (MiB)."
		prompt_var swap_size "Swap partition size in mebibytes (MiB). Actual swap will be larger than this with Raidz topologies."
		prompt_var zfs_arc_max_mb "ZFS ARC (cache) max size in mebibytes (MiB). Without a cap, ARC defaults to ~50% of RAM. Leave empty to use the ZFS default."
		prompt_var zfs_arc_min_mb "ZFS ARC min size in mebibytes (MiB), to stop ARC being starved under memory pressure. Leave empty to use the ZFS default."

		prompt_var mountpoint "Mountpoint used in the live environment during install, e.g. \"/mnt/deb_server\"."
		prompt_var timeout_rEFInd "Timeout in seconds for the rEFInd boot screen until the default choice is selected."
		prompt_var zbm_ref "Git tag of the zfsbootmenu release to build against (https://github.com/zbm-dev/zfsbootmenu/releases). Every zfsbootmenu source fetch in this script derives its URL from this value."
		prompt_var zbm_builder_image "Container image used to build the ZFSBootMenu EFI executable. Pinned to a dated tag for reproducibility -- pick the tag published alongside the zbm_ref release in use. Leave empty to float on upstream's \":latest\" tag instead."

		prompt_var ipv6_apt_fix_live_iso "Try \"yes\" if apt-get is slow in the Debian live environment. Doesn't affect ipv6 in the new install. Usually \"no\"."
		prompt_var debian_original "Default Debian archive URL."
		prompt_var debian_security_original "Debian security archive URL. Always separate from mirror_archive_url."
		echo
	else
		echo "Not running in the live environment (no \"boot=live\" on the kernel command line) -- skipping install-time-only settings, since those were already fixed by a previous \"initial\" run. Only the data-pool and remote-access settings below are editable here."
		echo
	fi

	echo "--- Data pool (used by the \"datapool\" option; can be set up now or later, once the drive is attached) ---"
	prompt_var datapool "Non-root drive data pool name."
	prompt_topology_var topology_data "Data pool disk topology: \"single\", \"mirror\", \"raid0\", \"raidz1\", \"raidz2\", or \"raidz3\"."
	prompt_disk_count_var disks_data "Number of disks in the data pool array. Not used with \"single\" topology." data

	if [ -n "${disks_data_ids-}" ];
	then
		echo "Current disks_data_ids:"
		printf '%s\n' "$disks_data_ids" | sed 's/^/  /'
	fi
	read -r -p "Select/reselect data pool disk(s) now? Only do this once the drive is physically attached to THIS machine -- otherwise leave this as-is and run buildenv again later, right before \"datapool\". [y/N]: " select_data_disks_now
	case "$(printf '%s' "${select_data_disks_now:-n}" | tr '[:upper:]' '[:lower:]')" in
		y|yes) wizard_select_disk_ids data ;;
		*) echo "Skipping data pool disk selection; disks_data_ids left unchanged." ;;
	esac

	prompt_var zfs_data_password "Password for the data pool. Minimum 8 characters. Leave empty for no password protection."
	prompt_var zfs_data_encrypt "Encryption type for the data pool. \"native\" is the only supported value, and is required whenever zfs_data_password is set; leave empty only if zfs_data_password above is also empty."
	prompt_var datapoolmount "Data pool mount point in the new install, e.g. \"/mnt/datapool\"."
	prompt_var zfs_dpool_ashift "Data pool ashift. Same guidance as zfs_rpool_ashift above."
	prompt_var zfs_compression "ZFS compression algorithm. \"lz4\" is the zfs default; \"zstd\" may compress better at a cost of higher CPU usage."
	echo

	echo "--- Remote access and networking (used by the \"remoteaccess\" option, and by \"initial\" for the new install's network config) ---"
	prompt_var quiet_boot "\"yes\" to hide the boot sequence, \"no\" to show it."
	prompt_var ethprefix "Prefix used to match the ethernet interface name under /sys/class/net (e.g. \"eno1\", \"enp3s0\", \"eth0\"). Must match exactly one interface -- on multi-NIC servers, a short prefix like \"e\" often matches more than one, so use the full interface name of the port you want."
	prompt_var remoteaccess_ip_config "\"dhcp\", \"dhcp,dhcp6\", \"dhcp6\", or \"static\" -- IP assignment for zfsbootmenu remote access."
	prompt_var remoteaccess_ip "Remote access static IP address. Only used when remoteaccess_ip_config is \"static\"."
	prompt_var remoteaccess_netmask "Remote access subnet mask. Only used when remoteaccess_ip_config is \"static\"."
	prompt_var remoteaccess_gateway "Remote access default gateway. Only used when remoteaccess_ip_config is \"static\" -- check with \"ip route | grep default\" on the box."
	prompt_multiline_var remoteaccess_dropbear_pubkeys "Required. One or more SSH public keys (e.g. \"ssh-ed25519 AAAA...C3NzaC1lZDI1NTE5 user@host\") authorized to log in to the pre-boot dropbear environment and unlock the pool. Deliberately separate from admin_ssh_pubkeys -- a key that can SSH into the running OS is not automatically also a key that can unlock the pool before it boots. Paste bare keys only, one per line -- no restrictions/options (e.g. \"restrict\", \"command=...\") ahead of the key, no-agent-forwarding is added automatically."
	prompt_var remoteaccess_tor "\"yes\" to also build a Tor onion service into zfsbootmenu remote access, alongside the direct-IP dropbear access above. Requires remoteaccess_tor_client_auth_pubkey. See README."

	prompt_var remoteaccess_tor_client_auth_pubkey "Client's x25519 onion-auth public key (\"descriptor:x25519:...\"). Required when remoteaccess_tor is \"yes\" -- see README for how to generate it."
	while [ -n "$remoteaccess_tor_client_auth_pubkey" ] && ! onion_client_auth_pubkey_is_valid "$remoteaccess_tor_client_auth_pubkey";
	do
		##Caught here rather than at boot: a wrong value builds without complaint and only shows up as
		##not being able to reach the onion service at all.
		echo "That isn't a client-auth public key. Expected \"descriptor:x25519:\" followed by the 52 base32 characters in client.pub.key -- note the public one, not client.prv.key. Leave it empty for now if you don't have it to hand."
		prompt_var remoteaccess_tor_client_auth_pubkey "Client's x25519 onion-auth public key (\"descriptor:x25519:...\")."
	done

	prompt_var remoteaccess_tor_start_delay "Seconds to wait after the network comes up before starting tor in the zfsbootmenu remote access environment. Dropbear is reachable immediately either way -- tor is a fallback for when direct-IP access isn't reachable, not for regular use, so it's meant to be held back."
	while ! [ "${remoteaccess_tor_start_delay-}" -ge 0 ] 2>/dev/null;
	do
		echo "That isn't a non-negative whole number of seconds."
		prompt_var remoteaccess_tor_start_delay "Seconds to wait after the network comes up before starting tor."
	done

	onion_secret_key_before="$remoteaccess_tor_onion_secret_key"
	prompt_var remoteaccess_tor_onion_secret_key "Optional. Base64 of an existing hs_ed25519_secret_key, to adopt an onion address you already have. Leave empty to have one generated below."
	while [ -n "$remoteaccess_tor_onion_secret_key" ] && ! onion_secret_key_is_valid "$remoteaccess_tor_onion_secret_key";
	do
		echo "That isn't a Tor v3 onion service secret key. Expected the base64 of an hs_ed25519_secret_key file, i.e. \"base64 -w0 /etc/zfsbootmenu/tor/hidden_service/hs_ed25519_secret_key\" from the machine it came from."
		prompt_var remoteaccess_tor_onion_secret_key "Base64 of an existing hs_ed25519_secret_key, or empty to generate a new identity."
	done
	if [ "$remoteaccess_tor_onion_secret_key" != "$onion_secret_key_before" ];
	then
		##Both are derived from the secret key, so neither can outlive a change to it.
		remoteaccess_tor_onion_public_key=""
		remoteaccess_tor_onion_hostname=""
	fi

	if [ "$remoteaccess_tor" = "yes" ];
	then
		if [ -z "$remoteaccess_tor_onion_secret_key" ] && [ -f /etc/zfsbootmenu/tor/hidden_service/hs_ed25519_secret_key ];
		then
			##This machine is already running an onion service the env file doesn't know about (an
			##older install, or a "remoteaccess" run that generated one itself). Keep its address.
			echo "Adopting the onion service identity already installed on this machine (/etc/zfsbootmenu/tor/hidden_service)."
			remoteaccess_tor_onion_secret_key="$(base64 -w0 < /etc/zfsbootmenu/tor/hidden_service/hs_ed25519_secret_key)"
			remoteaccess_tor_onion_public_key=""
			remoteaccess_tor_onion_hostname=""
		fi

		if [ -z "$remoteaccess_tor_onion_secret_key" ] || [ -z "$remoteaccess_tor_onion_public_key" ] || [ -z "$remoteaccess_tor_onion_hostname" ];
		then
			echo "The onion service identity and address aren't fully recorded in ${env_name} yet."
			read -r -p "Work them out now and store them here? [Y/n]: " generate_onion_now
			case "$(printf '%s' "${generate_onion_now:-y}" | tr '[:upper:]' '[:lower:]')" in
				n|no)
					echo "Skipped. The \"remoteaccess\" stage will do it instead, which means installing tor on the server at that point rather than here."
				;;
				*)
					if ! create_hidden_service_key "$remoteaccess_tor_onion_secret_key";
					then
						echo "Left blank -- run buildenv again to retry, or let the \"remoteaccess\" stage work it out."
					fi
				;;
			esac
		else
			echo "Onion service address: ${remoteaccess_tor_onion_hostname}"
		fi
	fi

	prompt_var timeout_zbm_no_remote_access "Timeout in seconds for zfsbootmenu when no remote access is enabled."
	prompt_var timeout_zbm_remote_access "Timeout in seconds for zfsbootmenu once remote access is installed -- the window in which you can connect before it boots the default environment. Tor clients need tens of seconds just to bootstrap, so keep this generous."
	echo

	echo "--- Logging and apt behaviour (used by every stage) ---"
	prompt_var install_log "Installation log filename."
	prompt_var log_loc "Installation log location."
	prompt_var install_warning_level "\"PRIORITY=critical\" (pause install to show critical messages only) or \"FRONTEND=noninteractive\" (do not pause)."
	echo

	env_errors=""
	if in_live_environment;
	then
		disk_ids_count_check "root"
	fi
	disk_ids_count_check "data"
	if [ -n "$env_errors" ];
	then
		echo "Note: the following isn't valid yet -- fine to leave if you're not ready (e.g. the data drive isn't attached), just run buildenv again before the stage that needs it:"
		printf '%s\n' "$env_errors"
		echo
	fi

	write_env_file
}

case "$run_mode" in
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
	buildenv)
		buildenv
	;;
	*)
		printf "%s\n%s\n%s\n" "-----" "Usage: $0 initial | postreboot | remoteaccess | datapool | buildenv" "-----"
	;;
esac

date
