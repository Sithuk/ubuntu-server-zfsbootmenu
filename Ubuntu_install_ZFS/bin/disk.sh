#!/bin/bash

getdiskID() {
    pool="$1"
    diskidnum="$2"
    total_discs="$3"
    
    menu_read() {
        diskidmenu_loc="/tmp/diskidmenu.txt"
        ls -la /dev/disk/by-id | awk '{ print $9, $11 }' | sed -e '1,3d' | grep -v "part\|CD-ROM" > "$diskidmenu_loc"
        
        echo "Please enter Disk ID option for disk $diskidnum of $total_discs on $pool pool."
        nl "$diskidmenu_loc"
        count="$(wc -l "$diskidmenu_loc" | cut -f 1 -d' ')"
        n=""
        while true; do
            read -r -p 'Select option: ' n
            if [ -n "$n" ] && [ "$n" -eq "$n" ] 2>/dev/null && [ "$n" -gt 0 ] && [ "$n" -le "$count" ]; then
                break
            fi
        done
        DISKID="$(sed -n "${n}p" "$diskidmenu_loc" | awk '{ print $1 }')"
        printf "%s\n\n" "Option number $n selected: '$DISKID'"
    }
    menu_read
    
    ## error check
    errchk="$(find /dev/disk/by-id -maxdepth 1 -mindepth 1 -name "$DISKID")"
    if [ -z "$errchk" ]; then
        echo "Disk ID not found. Exiting."
        exit 1
    fi
        
    errchk="$(grep "$DISKID" "/tmp/diskid_check_${pool}.txt" 2>/dev/null || true)"
    if [ -n "$errchk" ]; then
        echo "Disk ID has already been entered. Exiting."
        exit 1
    fi
    
    printf "%s\n" "$DISKID" >> "/tmp/diskid_check_${pool}.txt"
}

getdiskID_pool() {
    pool="$1"

    ## Check that number of disks meets minimum number for selected topology.
    topology_min_disk_check "$pool"

    echo "Carefully enter the ID of the disk(s) YOU WANT TO DESTROY in the next step to ensure no data is accidentally lost."
    
    ## Create temp file to check for duplicated disk ID entry.
    true > "/tmp/diskid_check_${pool}.txt"

    topology_pool_pointer="topology_$pool"
    eval "topology_val=\$${topology_pool_pointer}"
    
    disks_pointer="disks_${pool}"
    eval "disks_val=\$${disks_pointer}"

    case "$topology_val" in
        single)
            echo "The $pool pool disk topology is a single disk."
            getdiskID "$pool" "1" "1"
        ;;
        mirror|raid0|raidz*)
            echo "The $pool pool disk topology is $topology_val with $disks_val disks."
            diskidnum="1"
            while [ "$diskidnum" -le "$disks_val" ]; do
                getdiskID "$pool" "$diskidnum" "$disks_val"
                diskidnum=$(( diskidnum + 1 ))
            done
        ;;
        *)
            echo "Pool topology not recognised. Check pool topology variable."
            exit 1
        ;;
    esac
}

clear_partition_table() {
    pool="$1" # root or data
    while IFS= read -r diskidnum; do
        echo "Clearing partition table on disk ${diskidnum}."
        sgdisk --zap-all "/dev/disk/by-id/$diskidnum"
    done < "/tmp/diskid_check_${pool}.txt"
}

partitionsFunc() {
    # gdisk hex codes: EF02 BIOS boot, EF00 EFI system, 8200 Linux swap, FD00 Linux RAID (or ZFS/LUKS in some cases)
    # BE00 Solaris boot, BF00 Solaris root (ZFS native/unencrypted)
    
    case "$topology_root" in
        single|mirror) swap_hex_code="8200" ;;
        raid0|raidz*)  swap_hex_code="FD00" ;;
        *)
            echo "topology_root variable not recognised."
            exit 1
        ;;
    esac
    
    root_hex_code="BF00"
    
    while IFS= read -r diskidnum; do
        echo "Creating partitions on disk ${diskidnum}."
        # Partition 1: EFI
        sgdisk -n1:1M:+"${EFI_boot_size}"M -t1:EF00 "/dev/disk/by-id/${diskidnum}"
        # Partition 2: Swap
        sgdisk -n2:0:+"${swap_size}"M -t2:"${swap_hex_code}" "/dev/disk/by-id/${diskidnum}"
        # Partition 3: Root Pool
        sgdisk -n3:0:0 -t3:"${root_hex_code}" "/dev/disk/by-id/${diskidnum}"
    done < "/tmp/diskid_check_root.txt"
    partprobe
    sleep 2
}
