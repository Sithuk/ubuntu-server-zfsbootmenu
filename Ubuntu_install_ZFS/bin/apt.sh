#!/bin/bash

ipv6_apt_live_iso_fix() {
    ## Try disabling ipv6 in the live iso if setting the preference to ipv4 doesn't work.
    
    prefer_ipv4() {
        sed -i 's,#precedence ::ffff:0:0/96  100,precedence ::ffff:0:0/96  100,' /etc/gai.conf
    }
    
    dis_ipv6() {
        cat >> /etc/sysctl.conf <<-EOF
			net.ipv6.conf.all.disable_ipv6 = 1
		EOF
        tail -n 3 /etc/sysctl.conf
        sudo sysctl -p /etc/sysctl.conf
        sudo netplan apply
    }

    if [ "$ipv6_apt_fix_live_iso" = "yes" ]; then
        prefer_ipv4
        # dis_ipv6
    fi
}

identify_apt_data_sources() {
    if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
        apt_data_sources_loc="/etc/apt/sources.list.d/ubuntu.sources"
    else
        apt_data_sources_loc="/etc/apt/sources.list"
    fi
}

apt_sources() {
    ## Initial system apt sources config
    script_env="$1" ## chroot, base
    source_archive="$2"
    
    cat > /tmp/apt_sources.sh <<-EOF
		#!/bin/sh
		if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
			apt_data_sources_loc="/etc/apt/sources.list.d/ubuntu.sources"
			cp "\${apt_data_sources_loc}" "\${apt_data_sources_loc}.orig"
			if [ "${ubuntu_original}" != "${source_archive}" ]; then
				sed -i 's,${ubuntu_original},${source_archive},g' "\${apt_data_sources_loc}"
			fi
		else
			apt_data_sources_loc="/etc/apt/sources.list"
			cp "\${apt_data_sources_loc}" "\${apt_data_sources_loc}.orig"
			
			cat > "\${apt_data_sources_loc}" <<-EOLIST
				deb ${ubuntu_original} $ubuntuver main universe restricted multiverse
				deb ${ubuntu_original} $ubuntuver-updates main universe restricted multiverse
				deb ${ubuntu_original} $ubuntuver-backports main universe restricted multiverse
				deb http://security.ubuntu.com/ubuntu $ubuntuver-security main universe restricted multiverse
			EOLIST
			
			if [ "${ubuntu_original}" != "${source_archive}" ]; then
				cp "\${apt_data_sources_loc}" "\${apt_data_sources_loc}.non-mirror"
				sed -i 's,${ubuntu_original},${source_archive},g' "\${apt_data_sources_loc}"
			fi
		fi
	EOF

    case "${script_env}" in
        chroot)
            cp /tmp/apt_sources.sh "$mountpoint/tmp"
            chroot "$mountpoint" /bin/bash -x /tmp/apt_sources.sh
        ;;
        base)
            /bin/bash /tmp/apt_sources.sh
        ;;
        *) exit 1 ;;
    esac
}

apt_mirror_source() {
    identify_apt_data_sources
    
    identify_apt_mirror() {
        ## Identify fastest mirror.
        echo "Choosing fastest up-to-date ubuntu mirror based on download speed."
        apt update
        apt install -y curl
        ubuntu_mirror=$({
            {
                curl -s http://mirrors.ubuntu.com/"${mirror_archive}".txt | shuf -n 20
            } | xargs -I {} sh -c 'echo "$(curl -m 5 -sI {}dists/$(lsb_release -c | cut -f2)-security/Contents-$(dpkg --print-architecture).gz | sed s/\\r\$//|grep Last-Modified|awk -F": " "{ print \$2 }" | LANG=C date -f- -u +%s)" "{}"' | sort -rg | awk '{ if (NR==1) TS=$1; if ($1 == TS) print $2 }'
        } | xargs -I {} sh -c 'echo "$(curl -r 0-102400 -m 5 -s -w %{speed_download} -o /dev/null {}ls-lR.gz)" {}' \
        | sort -g -r | tee /tmp/mirrors_speed.txt | head -1 | awk '{ print $2  }')
    }
    identify_apt_mirror

    if [ -z "${ubuntu_mirror}" ]; then
        echo "No mirror identified. No changes made."
    else
        if [ "${ubuntu_original}" != "${ubuntu_mirror}" ]; then
            cp "${apt_data_sources_loc}" "${apt_data_sources_loc}.non-mirror"
            sed -i "s,${ubuntu_original},${ubuntu_mirror},g" "${apt_data_sources_loc}"
            echo "Selected '${ubuntu_mirror}'."
        else
            echo "Identified mirror is already selected. No changes made."
        fi
    fi
}

reinstate_apt() {
    script_env="$1" ## chroot, base
    
    cat > /tmp/reinstate_apt.sh <<-EOF
		#!/bin/sh
		if [ -n "${mirror_archive}" ]; then
			if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
				apt_data_sources_loc="/etc/apt/sources.list.d/ubuntu.sources"
			else
				apt_data_sources_loc="/etc/apt/sources.list"
			fi
			if [ -f "\${apt_data_sources_loc}.non-mirror" ]; then
				cp "\${apt_data_sources_loc}.non-mirror" "\${apt_data_sources_loc}"
			fi
		fi
		if [ -f /etc/apt/apt.conf.d/30apt_error_on_transient ]; then
			rm /etc/apt/apt.conf.d/30apt_error_on_transient
		fi
	EOF

    case "${script_env}" in
        chroot)
            cp /tmp/reinstate_apt.sh "$mountpoint/tmp"
            chroot "$mountpoint" /bin/bash -x /tmp/reinstate_apt.sh
        ;;
        base)
            /bin/bash /tmp/reinstate_apt.sh
        ;;
        *) exit 1 ;;
    esac
}
