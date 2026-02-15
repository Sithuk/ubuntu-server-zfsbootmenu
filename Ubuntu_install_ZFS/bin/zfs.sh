#!/bin/bash

identify_ubuntu_dataset_uuid() {
    rootzfs_full_name=0
    rootzfs_full_name="$(zfs list -o name | awk '/ROOT\/ubuntu/{print $1;exit}'|sed -e 's,^.*/,,')"
}

create_zpool_Func() {
    ## Create zfs pool
    pool=$1 ## root, data
    
    ## Set pool variables
    case "$pool" in
        root)
            ashift="$zfs_rpool_ashift"
            zpool_partition="-part3"
            zpool_name="$RPOOL"
            topology_pool="${topology_root}"
        ;;
        data)
            ashift="$zfs_dpool_ashift"
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

    if [ "$pool" = "root" ]; then
        echo -O canmount=off \\ >> "$zpool_create_temp"
    fi

    
    case "$pool" in
        root) echo "-O mountpoint=/ -R $mountpoint \\" >> "$zpool_create_temp" ;;
        data) echo "-O mountpoint=$datapoolmount \\" >> "$zpool_create_temp" ;;
    esac

    add_zpool_disks() {
        loop_counter="$(mktemp)"
        echo 1 > "$loop_counter"
        
        while IFS= read -r diskidnum; do
            echo "/dev/disk/by-id/${diskidnum}${zpool_partition} \\" >> "$zpool_create_temp"
        done < "/tmp/diskid_check_$pool".txt
        sed -i '$s,\\,,' "$zpool_create_temp"
    }

    case "${topology_pool}" in
        single|raid0) echo "${zpool_name} \\" >> "$zpool_create_temp"; add_zpool_disks ;;
        mirror)      echo "${zpool_name} mirror \\" >> "$zpool_create_temp"; add_zpool_disks ;;
        raidz1)      echo "${zpool_name} raidz1 \\" >> "$zpool_create_temp"; add_zpool_disks ;;
        raidz2)      echo "${zpool_name} raidz2 \\" >> "$zpool_create_temp"; add_zpool_disks ;;
        raidz3)      echo "${zpool_name} raidz3 \\" >> "$zpool_create_temp"; add_zpool_disks ;;
        *) exit 1 ;;
    esac
    
    sh "$zpool_create_temp" 
}

debootstrap_createzfspools_Func() {
    create_zpool_Func root
    mountpointsFunc
}

mountpointsFunc() {
    # Create filesystem datasets
    zfs create -o canmount=off -o mountpoint=none "$RPOOL/ROOT" 
                
    rootzfs_full_name="ubuntu.$(date +%Y.%m.%d)"
    zfs create -o canmount=noauto -o mountpoint=/ "$RPOOL/ROOT/$rootzfs_full_name"
    zfs mount "$RPOOL/ROOT/$rootzfs_full_name"
    zpool set bootfs="$RPOOL/ROOT/$rootzfs_full_name" "$RPOOL"
    
    zfs create "$RPOOL/srv"
    zfs create -o canmount=off "$RPOOL/usr"
    zfs create "$RPOOL/usr/local"
    zfs create -o canmount=off "$RPOOL/var" 
    zfs create -o canmount=off "$RPOOL/var/lib"
    zfs create "$RPOOL/var/games"
    zfs create "$RPOOL/var/log"
    zfs create "$RPOOL/var/mail"
    zfs create "$RPOOL/var/snap"
    zfs create "$RPOOL/var/spool"
    zfs create "$RPOOL/var/www"
    
    zfs create "$RPOOL/home"
    zfs create -o mountpoint=/root "$RPOOL/home/root"
    chmod 700 "$mountpoint/root"

    zfs create -o com.sun:auto-snapshot=false "$RPOOL/var/cache"
    zfs create -o com.sun:auto-snapshot=false "$RPOOL/var/tmp"
    chmod 1777 "$mountpoint/var/tmp"
    zfs create -o com.sun:auto-snapshot=false "$RPOOL/var/lib/docker"

    mkdir -p "$mountpoint/run"
    mount -t tmpfs tmpfs "$mountpoint/run"
}
