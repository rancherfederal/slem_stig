#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Exiting."
    exit 1
fi

LOGFILE="stig_medium_user_input.log"

# Make a new logfile
> "$LOGFILE"

# Function to log messages
log_message() {
    local function_name=$1
    local vuln_id=$2
    local rule_id=$3
    local message=$4
    echo "$function_name: Vuln_ID: $vuln_id Rule_ID: $rule_id | $message" >> "$LOGFILE"
}

# Function to create a separate file system/partition for /var
#######################################################
#
# set the local partition= variable to meet your setup
#
#######################################################
create_var_partition() {
    local function_name="create_var_partition"
    local vuln_id="V-261279"
    local rule_id="SV-261279r996322"

    # Prompt the user for the partition to use
    read -p "Enter the partition to use for /var (e.g., /dev/vda3): " partition
    local mount_point="/var"

    if mount | grep -q "on $mount_point"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "/var is already on a separate partition."
        return
    fi

    mkfs.ext4 "$partition"
    mount "$partition" /mnt

    rsync -av /var/ /mnt/
    mv /var /var.old
    mkdir /var
    umount /mnt
    mount "$partition" "$mount_point"

    echo "$partition $mount_point ext4 defaults 0 2" | tee -a /etc/fstab

    if mount | grep -q "on $mount_point"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "/var has been moved to a separate partition."
        rm -rf /var.old
    else
        mv /var.old /var
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to move /var to a separate partition. This is a finding."
    fi
}

# Function to create a separate file system/partition for nonprivileged local interactive user home directories
#######################################################
#
# set the local partition= variable to meet your setup
#
#######################################################
create_home_partition() {
    local function_name="create_home_partition"
    local vuln_id="V-261278"
    local rule_id="SV-261278r996320"

    # Prompt the user for the partition to use
    read -p "Enter the partition to use for /home (e.g., /dev/vda3): " partition
    local mount_point="/home"

    if mount | grep -q "on $mount_point"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "/home is already on a separate partition."
        return
    fi

    mkfs.ext4 "$partition"
    mkdir -p "$mount_point"
    mount "$partition" "$mount_point"

    echo "$partition $mount_point ext4 defaults 0 2" | tee -a /etc/fstab

    if mount | grep -q "on $mount_point"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Nonprivileged local interactive user home directories have been moved to a separate partition."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to move nonprivileged local interactive user home directories to a separate partition. This is a finding."
    fi
}


# Function to migrate SLEM 5 audit data path onto a separate file system or partition
migrate_audit_data() {
    local function_name="migrate_audit_data"
    local vuln_id="V-261280"
    local rule_id="SV-261280r996324"

    # Prompt the user for the partition to use
    read -p "Enter the partition to use for /var/log/audit (e.g., /dev/sdZ1): " partition
    local mount_point="/var/log/audit"

    if mount | grep -q "on $mount_point"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Audit data path is already on a separate partition."
        return
    fi

    mkfs.ext4 "$partition"
    mount "$partition" /mnt

    rsync -av /var/log/audit/ /mnt/
    mv /var/log/audit /var/log/audit.old
    mkdir /var/log/audit
    umount /mnt
    mount "$partition" "$mount_point"

    echo "$partition $mount_point ext4 defaults 0 2" | tee -a /etc/fstab

    if mount | grep -q "on $mount_point"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Audit data path has been moved to a separate partition."
        rm -rf /var/log/audit.old
    else
        mv /var/log/audit.old /var/log/audit
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to move audit data path to a separate partition. This is a finding."
    fi
}


# Function to map users to specific SELinux roles
###############################################################
#
# Example usage: map_user_to_selinux_role "username" "sysadm_u"
#
###############################################################
map_user_to_selinux_role() {
    local function_name="map_user_to_selinux_role"
    local vuln_id="V-261371"
    local rule_id="SV-261371r996554"
    local username="$1"
    local role="$2"

    semanage login -m -s "$role" "$username"

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Mapped user $username to SELinux role $role successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to map user $username to SELinux role $role. This is a finding."
    fi
}

create_var_partition
create_home_partition 
migrate_audit_data
map_user_to_selinux_role
