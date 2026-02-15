#!/bin/bash

distroinstall() {
    ## Upgrade the minimal system
    if [ -n "${mirror_archive}" ]; then
        apt_mirror_source
    fi
    export DEBIAN_"${install_warning_level}"
    apt update 
    apt dist-upgrade --yes

    if [ "$distro_variant" != "server" ]; then
        zfs create "$RPOOL/var/lib/AccountsService"
    fi

    case "$distro_variant" in
        server)   apt install --yes ubuntu-server ;;
        desktop)  apt install --yes ubuntu-desktop ;;
        kubuntu)
            echo sddm shared/default-x-display-manager select sddm | debconf-set-selections
            apt install --yes kubuntu-desktop
        ;;
        xubuntu)
            echo lightdm shared/default-x-display-manager select lightdm | debconf-set-selections
            apt install --yes xubuntu-desktop
        ;;
        budgie)
            echo lightdm shared/default-x-display-manager select lightdm | debconf-set-selections
            apt install --yes ubuntu-budgie-desktop
        ;;
        MATE)
            echo lightdm shared/default-x-display-manager select lightdm | debconf-set-selections
            apt install --yes ubuntu-mate-desktop
        ;;
        *) exit 1 ;;
    esac
}

NetworkManager_config() {
    if [ "$(dpkg-query --show --showformat='${db:Status-Status}\n' "network-manager")" = "installed" ]; then
        ethernetinterface="$(basename "$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${ethprefix}*")")"
        rm -f "/etc/netplan/01-$ethernetinterface.yaml"
        cat > /etc/netplan/01-NetworkManager.yaml <<-EOF
			network:
			  version: 2
			  renderer: NetworkManager
			  ethernets:
			    "$ethernetinterface":
			      dhcp4: true
		EOF
        chmod 600 /etc/netplan/01-NetworkManager.yaml
        systemctl stop systemd-networkd.service systemd-networkd.socket || true
        systemctl disable systemd-networkd.service systemd-networkd.socket || true
        netplan apply
    fi
}

pyznapinstall() {
    apt install -y python3-pip python3-virtualenv python3-virtualenvwrapper
    mkdir -p /opt/pyznap
    cd /opt/pyznap
    virtualenv venv
    source venv/bin/activate
    pip install setuptools pyznap
    deactivate
    ln -sf /opt/pyznap/venv/bin/pyznap /usr/local/bin/pyznap
    /opt/pyznap/venv/bin/pyznap setup
    chown root:root -R /etc/pyznap/
    
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

    cat > /etc/apt/apt.conf.d/80-zfs-snapshot <<-EOF
		DPkg::Pre-Invoke {"if [ -x /usr/local/bin/pyznap ]; then /usr/local/bin/pyznap snap; fi"};
	EOF
    pyznap snap
}

sanoid_install() {
    apt update && apt install -y sanoid 
    mkdir -p /etc/sanoid
    cat > /etc/sanoid/sanoid.conf <<-EOF
		[$RPOOL/ROOT]
			use_template = template_production
			recursive = yes
			process_children_only = yes
		
		[template_production]
			frequently = 4
			hourly = 24
			daily = 7
			weekly = 4
			monthly = 6
			yearly = 0
			autosnap = yes
			autoprune = yes
	EOF
    
    pre-apt-snapshot() {
        cat > /etc/apt/apt.conf.d/80-zfs-snapshot <<-EOF
			DPkg::Pre-Invoke { "echo 'Creating ZFS snapshot.'; ts=pre-apt_\$(date +%F_%H:%M:%S); zfs snapshot -r $RPOOL/ROOT@\${ts} && zfs destroy $RPOOL/ROOT@\${ts} || true"; };
		EOF
        cat > /usr/local/bin/apt-snapshot-prune.sh <<-"EOF"
			#!/bin/sh
			zfs list -H -p -o name,creation -t snapshot -r $(zpool list -H -o name) | grep 'pre-apt' |
			while read name creation; do
				age=$(( $(date +%s) - creation ))
				if [ $age -gt $((7 * 24 * 3600)) ]; then
					zfs destroy "$name"
				fi
			done
		EOF
        chmod +x /usr/local/bin/apt-snapshot-prune.sh
        cat > /etc/systemd/system/apt-snapshot-prune.service <<-EOF
			[Unit]
			Description=Prune old pre-apt ZFS snapshots
			[Service]
			Type=oneshot
			ExecStart=/usr/local/bin/apt-snapshot-prune.sh
			Nice=19
			IOSchedulingClass=3
		EOF
        cat > /etc/systemd/system/apt-snapshot-prune.timer <<-EOF
			[Unit]
			Description=Daily cleanup of old pre-apt ZFS snapshots
			[Timer]
			OnCalendar=daily
			Persistent=true
			[Install]
			WantedBy=timers.target
		EOF
    }
    pre-apt-snapshot
    /usr/sbin/sanoid --take-snapshots --verbose
    systemctl enable --now sanoid.timer
}

extra_programs() {
    if [ "$extra_programs" = "yes" ]; then
        apt install -yq cifs-utils openssh-server man-db tldr locate
    fi
}

reinstall-pyznap() {
    rm -f /etc/apt/apt.conf.d/80-zfs-snapshot /usr/local/bin/pyznap
    rm -rf /opt/pyznap /etc/pyznap/pyznap.conf
    pyznapinstall
}

createdatapool() {
    getdiskID_pool "data"
    clear_partition_table "data"
    partprobe && sleep 2
    mkdir -p "$datapoolmount"
    chown "$user":"$user" "$datapoolmount"
    touch "/etc/zfs/zfs-list.cache/$datapool"
    create_zpool_Func "data"
    
    count=0
    while [ ! -s "/etc/zfs/zfs-list.cache/$datapool" ] && [ $count -lt 60 ]; do
        zfs set canmount=on "$datapool"
        sleep 1
        count=$((count + 1))
    done
    ln -sf "$datapoolmount" "/home/$user/"
    chown -R "$user":"$user" "$datapoolmount" "/home/$user/$(basename "$datapoolmount")"
}
