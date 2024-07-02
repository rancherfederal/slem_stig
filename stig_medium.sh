#!/bin/bash

LOGFILE="stig_medium.log"

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

# Function to configure the system logon banner with the Standard Mandatory DOD Notice and Consent Banner
configure_logon_banner() {
    local function_name="configure_logon_banner"
    local vuln_id="V-261265"
    local rule_id="SV-261265r996289"

    local issue_file="/etc/issue"
    local banner_text="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

- The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

- At any time, the USG may inspect and seize data stored on this IS.

- Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

- This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

- Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

    echo "$banner_text" | sudo tee "$issue_file" > /dev/null

    local current_banner
    current_banner=$(cat "$issue_file")

    if [[ "$current_banner" == "$banner_text" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Standard Mandatory DOD Notice and Consent Banner has been configured successfully in $issue_file."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure the Standard Mandatory DOD Notice and Consent Banner in $issue_file. This is a finding."
    fi
}

# Function to restrict access to the kernel message buffer
restrict_kernel_message_buffer() {
    local function_name="restrict_kernel_message_buffer"
    local vuln_id="V-261269"
    local rule_id="SV-261269r996301"

    local sysctl_conf_file="/etc/sysctl.conf"
    local sysctl_conf_dirs=("/run/sysctl.d/" "/etc/sysctl.d/" "/usr/local/lib/sysctl.d/" "/usr/lib/sysctl.d/" "/lib/sysctl.d/")
    local kernel_param="kernel.dmesg_restrict = 1"

    if grep -q "^kernel.dmesg_restrict" "$sysctl_conf_file"; then
        sudo sed -i 's/^kernel.dmesg_restrict.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    for dir in "${sysctl_conf_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            sudo find "$dir" -type f -exec sed -i '/^kernel.dmesg_restrict/d' {} \;
        fi
    done

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n kernel.dmesg_restrict)

    if [[ "$param_value" -eq 1 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Kernel message buffer access has been restricted successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to restrict kernel message buffer access. This is a finding."
    fi
}

# Function to disable the kdump service if kernel core dumps are not required
disable_kdump_service() {
    local function_name="disable_kdump_service"
    local vuln_id="V-261270"
    local rule_id="SV-261270r996860"

    local kdump_service_status
    kdump_service_status=$(systemctl is-enabled kdump.service 2>/dev/null)

    if [[ "$kdump_service_status" == "disabled" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "kdump.service is already disabled."
    else
        sudo systemctl disable kdump.service

        kdump_service_status=$(systemctl is-enabled kdump.service 2>/dev/null)
        if [[ "$kdump_service_status" == "disabled" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "kdump.service has been disabled successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable kdump.service. This is a finding."
        fi
    fi
}

# Function to configure ASLR
configure_aslr() {
    local function_name="configure_aslr"
    local vuln_id="V-261271"
    local rule_id="SV-261271r996306"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="kernel.randomize_va_space=2"

    sudo sysctl -w kernel.randomize_va_space=2

    if grep -q "^kernel.randomize_va_space" "$sysctl_conf_file"; then
        sudo sed -i 's/^kernel.randomize_va_space.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n kernel.randomize_va_space)

    if [[ "$param_value" -eq 2 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "ASLR has been configured successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure ASLR. This is a finding."
    fi
}

# Function to configure kernel to prevent leaking of internal addresses
configure_kernel_address_leak_prevention() {
    local function_name="configure_kernel_address_leak_prevention"
    local vuln_id="V-261272"
    local rule_id="SV-261272r996309"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="kernel.kptr_restrict=1"

    sudo sysctl -w kernel.kptr_restrict=1

    if grep -q "^kernel.kptr_restrict" "$sysctl_conf_file"; then
        sudo sed -i 's/^kernel.kptr_restrict.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n kernel.kptr_restrict)

    if [[ "$param_value" -eq 1 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Kernel address leak prevention has been configured successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure kernel address leak prevention. This is a finding."
    fi
}

# Function to install applicable SLEM 5 patches and reboot
install_slem_patches() {
    local function_name="install_slem_patches"
    local vuln_id="V-261273"
    local rule_id="SV-261273r996311"

    sudo transactional-update patch

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SLEM 5 patches have been installed successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to install SLEM 5 patches. This is a finding."
    fi
}

# Function to configure SLEM 5 to remove outdated software components after an update
configure_remove_outdated_software() {
    local function_name="configure_remove_outdated_software"
    local vuln_id="V-261275"
    local rule_id="SV-261275r996314"

    local zypp_conf_file="/etc/zypp/zypp.conf"
    local config_line="solver.upgradeRemoveDroppedPackages = true"

    if grep -q "^solver.upgradeRemoveDroppedPackages" "$zypp_conf_file"; then
        sudo sed -i 's/^solver.upgradeRemoveDroppedPackages.*/'"$config_line"'/' "$zypp_conf_file"
    else
        echo "$config_line" | sudo tee -a "$zypp_conf_file"
    fi

    local config_applied
    config_applied=$(grep "^solver.upgradeRemoveDroppedPackages" "$zypp_conf_file")

    if [[ "$config_applied" == "$config_line" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured to remove outdated software components after an update in $zypp_conf_file."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure removal of outdated software components in $zypp_conf_file. This is a finding."
    fi
}

# Function to install the kbd package to allow users to lock the console
install_kbd_package() {
    local function_name="install_kbd_package"
    local vuln_id="V-261276"
    local rule_id="SV-261276r996316"

    sudo transactional-update pkg install kbd

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "kbd package has been installed successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to install kbd package. This is a finding."
    fi
}

# Function to create a separate file system/partition for /var
create_var_partition() {
    local function_name="create_var_partition"
    local vuln_id="V-261279"
    local rule_id="SV-261279r996322"

    local partition="/dev/sdY1"  # Replace with the actual partition
    local mount_point="/var"

    if mount | grep -q "on $mount_point"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "/var is already on a separate partition."
        return
    fi

    sudo mkfs.ext4 "$partition"
    sudo mount "$partition" /mnt

    sudo rsync -av /var/ /mnt/
    sudo mv /var /var.old
    sudo mkdir /var
    sudo umount /mnt
    sudo mount "$partition" "$mount_point"

    echo "$partition $mount_point ext4 defaults 0 2" | sudo tee -a /etc/fstab

    if mount | grep -q "on $mount_point"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "/var has been moved to a separate partition."
        sudo rm -rf /var.old
    else
        sudo mv /var.old /var
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to move /var to a separate partition. This is a finding."
    fi
}

# Function to create a separate file system/partition for nonprivileged local interactive user home directories
create_home_partition() {
    local function_name="create_home_partition"
    local vuln_id="V-261278"
    local rule_id="SV-261278r996320"

    local partition="/dev/sdX1"
    local mount_point="/home"

    if mount | grep -q "on $mount_point"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "/home is already on a separate partition."
        return
    fi

    sudo mkfs.ext4 "$partition"
    sudo mkdir -p "$mount_point"
    sudo mount "$partition" "$mount_point"

    echo "$partition $mount_point ext4 defaults 0 2" | sudo tee -a /etc/fstab

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

    local partition="/dev/sdZ1"  # Replace with the actual partition
    local mount_point="/var/log/audit"

    if mount | grep -q "on $mount_point"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Audit data path is already on a separate partition."
        return
    fi

    sudo mkfs.ext4 "$partition"
    sudo mount "$partition" /mnt

    sudo rsync -av /var/log/audit/ /mnt/
    sudo mv /var/log/audit /var/log/audit.old
    sudo mkdir /var/log/audit
    sudo umount /mnt
    sudo mount "$partition" "$mount_point"

    echo "$partition $mount_point ext4 defaults 0 2" | sudo tee -a /etc/fstab

    if mount | grep -q "on $mount_point"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Audit data path has been moved to a separate partition."
        sudo rm -rf /var/log/audit.old
    else
        sudo mv /var/log/audit.old /var/log/audit
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to move audit data path to a separate partition. This is a finding."
    fi
}

# Function to configure /etc/fstab to use the nosuid option for NFS file systems
configure_fstab_nosuid_nfs() {
    local function_name="configure_fstab_nosuid_nfs"
    local vuln_id="V-261281"
    local rule_id="SV-261281r996326"

    if grep -q "nfs" /etc/fstab; then
        sudo sed -i '/nfs/s/defaults/defaults,nosuid/' /etc/fstab
        sudo mount -o remount -a

        if grep -q "nfs" /etc/fstab | grep "nosuid"; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Configured /etc/fstab to use the nosuid option for NFS file systems."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure /etc/fstab to use the nosuid option for NFS file systems. This is a finding."
        fi
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "No NFS file systems found in /etc/fstab."
    fi
}

# Function to configure /etc/fstab to use the noexec option for NFS file systems
configure_fstab_noexec_nfs() {
    local function_name="configure_fstab_noexec_nfs"
    local vuln_id="V-261282"
    local rule_id="SV-261282r996328"

    if grep -q "nfs" /etc/fstab; then
        sudo sed -i '/nfs/s/defaults/defaults,noexec/' /etc/fstab
        sudo mount -o remount -a

        if grep -q "nfs" /etc/fstab | grep "noexec"; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Configured /etc/fstab to use the noexec option for NFS file systems."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure /etc/fstab to use the noexec option for NFS file systems. This is a finding."
        fi
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "No NFS file systems found in /etc/fstab."
    fi
}

# Function to configure /etc/fstab to use the nosuid option for file systems associated with removable media
configure_fstab_nosuid_removable_media() {
    local function_name="configure_fstab_nosuid_removable_media"
    local vuln_id="V-261283"
    local rule_id="SV-261283r996330"

    if grep -q "removable" /etc/fstab; then
        sudo sed -i '/removable/s/defaults/defaults,nosuid/' /etc/fstab
        sudo mount -o remount -a

        if grep -q "removable" /etc/fstab | grep "nosuid"; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Configured /etc/fstab to use the nosuid option for removable media file systems."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure /etc/fstab to use the nosuid option for removable media file systems. This is a finding."
        fi
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "No removable media file systems found in /etc/fstab."
    fi
}

# Function to configure /etc/fstab to use the nosuid option for user home directories
configure_fstab_nosuid_home() {
    local function_name="configure_fstab_nosuid_home"
    local vuln_id="V-261285"
    local rule_id="SV-261285r996838"

    if grep -q "/home" /etc/fstab; then
        sudo sed -i '/\/home/s/defaults/defaults,nosuid/' /etc/fstab
        sudo mount -o remount /home

        if grep -q "/home" /etc/fstab | grep "nosuid"; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Configured /etc/fstab to use the nosuid option for user home directories."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure /etc/fstab to use the nosuid option for user home directories. This is a finding."
        fi
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "No user home directories found in /etc/fstab."
    fi
}

# Function to disable the ability to automount devices by stopping and disabling the autofs service
disable_automount() {
    local function_name="disable_automount"
    local vuln_id="V-261286"
    local rule_id="SV-261286r996338"

    sudo systemctl stop autofs

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "autofs service stopped successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to stop autofs service. This is a finding."
        return
    fi

    sudo systemctl disable autofs

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "autofs service disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable autofs service. This is a finding."
    fi
}

# Function to configure the system commands to be protected from unauthorized access
protect_system_commands() {
    local function_name="protect_system_commands"
    local vuln_id="V-261287 & V-261288"
    local rule_id="SV-261287r996341 & SV-261288r996344"

    sudo find -L /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' \;
    sudo find -L /bin /sbin /usr/bin /usr/sbin -perm /022 -type f -exec chmod 755 '{}' \;
    
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "System commands have been protected from unauthorized access."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to protect system commands from unauthorized access. This is a finding."
    fi
}

# Function to configure the library files to be protected from unauthorized access
protect_library_files() {
    local function_name="protect_library_files"
    local vuln_id="V-261289 & V-261290"
    local rule_id="SV-261289r996347 & SV-261290r996350"

    sudo find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec chmod 755 '{}' \;

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Library files have been protected from unauthorized access."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to protect library files from unauthorized access. This is a finding."
    fi
}

# Function to change the mode of local interactive user's home directories to 750
change_home_directory_permissions() {
    local function_name="change_home_directory_permissions"
    local vuln_id="V-261291"
    local rule_id="SV-261291r996352"

    local user_home_dirs
    user_home_dirs=$(awk -F: '($3 >= 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false") {print $6}' /etc/passwd)

    for home_dir in $user_home_dirs; do
        if [[ -d "$home_dir" ]]; then
            sudo chmod 750 "$home_dir"
            local mode
            mode=$(stat -c "%a" "$home_dir")
            if [[ "$mode" == "750" ]]; then
                log_message "$function_name" "$vuln_id" "$rule_id" "Changed permissions of $home_dir to 750."
            else
                log_message "$function_name" "$vuln_id" "$rule_id" "Failed to change permissions of $home_dir to 750. This is a finding."
            fi
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Home directory $home_dir does not exist. This is a finding."
        fi
    done
}

# Function to set the mode of local initialization files to 740
set_init_file_permissions() {
    local function_name="set_init_file_permissions"
    local vuln_id="V-261292"
    local rule_id="SV-261292r996354"

    local user_home_dirs
    user_home_dirs=$(awk -F: '($3 >= 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false") {print $6}' /etc/passwd)

    for home_dir in $user_home_dirs; do
        if [[ -d "$home_dir" ]]; then
            local init_files
            init_files=$(find "$home_dir" -maxdepth 1 -name ".*" -type f)

            for init_file in $init_files; do
                sudo chmod 740 "$init_file"
                local mode
                mode=$(stat -c "%a" "$init_file")
                if [[ "$mode" == "740" ]]; then
                    log_message "$function_name" "$vuln_id" "$rule_id" "Changed permissions of $init_file to 740."
                else
                    log_message "$function_name" "$vuln_id" "$rule_id" "Failed to change permissions of $init_file to 740. This is a finding."
                fi
            done
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Home directory $home_dir does not exist. This is a finding."
        fi
    done
}

# Function to set the mode of SSH daemon public host key files to 644
set_ssh_public_key_permissions() {
    local function_name="set_ssh_public_key_permissions"
    local vuln_id="V-261293"
    local rule_id="SV-261293r996357"

    local public_key_files
    public_key_files=$(find /etc/ssh -type f -name "ssh_host*key.pub")

    for key_file in $public_key_files; do
        sudo chmod 644 "$key_file"
        local mode
        mode=$(stat -c "%a" "$key_file")
        if [[ "$mode" == "644" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Changed permissions of $key_file to 644."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to change permissions of $key_file to 644. This is a finding."
        fi
    done
}

# Function to set the mode of SSH daemon private host key files to 640
set_ssh_private_key_permissions() {
    local function_name="set_ssh_private_key_permissions"
    local vuln_id="V-261294"
    local rule_id="SV-261294r996359"

    local private_key_files
    private_key_files=$(find /etc/ssh -type f -name "ssh_host*key" ! -name "*.pub")

    for key_file in $private_key_files; do
        sudo chmod 640 "$key_file"
        local mode
        mode=$(stat -c "%a" "$key_file")
        if [[ "$mode" == "640" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Changed permissions of $key_file to 640."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to change permissions of $key_file to 640. This is a finding."
        fi
    done
}

# Function to configure the library files to be owned by root
protect_library_files_ownership() {
    local function_name="protect_library_files_ownership"
    local vuln_id="V-261295"
    local rule_id="SV-261295r996362"

    sudo transactional-update shell <<EOF
    sudo find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type f -exec chown root '{}' \;
    exit
EOF

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Library files ownership set to root successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set library files ownership to root. This is a finding."
    fi
}

# Function to configure the library files to be in the root group
protect_library_files_group() {
    local function_name="protect_library_files_group"
    local vuln_id="V-261296"
    local rule_id="SV-261296r996365"

    sudo transactional-update shell <<EOF
    sudo find /lib /lib64 /usr/lib /usr/lib64 ! -group root -type f -exec chgrp root '{}' \;
    exit
EOF

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Library files group set to root successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set library files group to root. This is a finding."
    fi
}

# Function to configure the library directories to be owned by root
protect_library_dirs_ownership() {
    local function_name="protect_library_dirs_ownership"
    local vuln_id="V-261297"
    local rule_id="SV-261297r996368"

    sudo transactional-update shell <<EOF
    sudo find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec chown root '{}' \;
    exit
EOF

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Library directories ownership set to root successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set library directories ownership to root. This is a finding."
    fi
}

# Function to configure the library directories to be in the root group
protect_library_dirs_group() {
    local function_name="protect_library_dirs_group"
    local vuln_id="V-261298"
    local rule_id="SV-261298r996371"

    sudo transactional-update shell <<EOF
    sudo find /lib /lib64 /usr/lib /usr/lib64 ! -group root -type d -exec chgrp root '{}' \;
    exit
EOF

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Library directories group set to root successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set library directories group to root. This is a finding."
    fi
}

# Function to configure the system commands to be owned by root
protect_system_commands_ownership() {
    local function_name="protect_system_commands_ownership"
    local vuln_id="V-261299 & V-261300"
    local rule_id="SV-261299r996373 & SV-261300r996375"

    sudo transactional-update shell <<EOF
    sudo find -L /bin /sbin /usr/bin /usr/sbin ! -user root -type f -exec chown root '{}' \;
    exit
EOF

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "System commands ownership set to root successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set system commands ownership to root. This is a finding."
    fi
}

# Function to configure the system commands directories to be owned by root
protect_system_commands_directory_ownership() {
    local function_name="protect_system_commands_directory_ownership"
    local vuln_id="V-261301"
    local rule_id="SV-261301r996377"

    sudo transactional-update shell <<EOF
    sudo find -L /bin /sbin /usr/bin /usr/sbin ! -user root -type d -exec chown root '{}' \;
    exit
EOF

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "System commands directories ownership set to root successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set system commands directories ownership to root. This is a finding."
    fi
}

# Function to configure the system commands directories to be in the root group
protect_system_commands_directory_group() {
    local function_name="protect_system_commands_directory_group"
    local vuln_id="V-261302"
    local rule_id="SV-261302r996380"

    sudo transactional-update shell <<EOF
    sudo find -L /bin /sbin /usr/bin /usr/sbin ! -group root -type d -exec chgrp root '{}' \;
    exit
EOF

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "System commands directories group set to root successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set system commands directories group to root. This is a finding."
    fi
}

# Function to assign a valid user to unowned files and directories
assign_valid_user_to_unowned_files() {
    local function_name="assign_valid_user_to_unowned_files"
    local vuln_id="V-261303"
    local rule_id="SV-261303r996382"

    local unowned_files
    unowned_files=$(find / -nouser)

    for file in $unowned_files; do
        sudo chown root "$file"
        local owner
        owner=$(stat -c "%U" "$file")
        if [[ "$owner" == "root" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Assigned root as owner to $file."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to assign owner to $file. This is a finding."
        fi
    done
}

# Function to assign a valid group to ungrouped files and directories
assign_valid_group_to_ungrouped_files() {
    local function_name="assign_valid_group_to_ungrouped_files"
    local vuln_id="V-261304"
    local rule_id="SV-261304r996384"

    local ungrouped_files
    ungrouped_files=$(find / -nogroup)

    for file in $ungrouped_files; do
        sudo chgrp root "$file"
        local group
        group=$(stat -c "%G" "$file")
        if [[ "$group" == "root" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Assigned root as group to $file."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to assign group to $file. This is a finding."
        fi
    done
}

# Function to change the group owner of a local interactive user's home directory
change_home_directory_group() {
    local function_name="change_home_directory_group"
    local vuln_id="V-261305"
    local rule_id="SV-261305r996387"

    local user_home_dirs
    user_home_dirs=$(awk -F: '($3 >= 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false") {print $1 ":" $6}' /etc/passwd)

    for user_home in $user_home_dirs; do
        local user
        local home_dir
        IFS=: read -r user home_dir <<< "$user_home"
        local group
        group=$(id -gn "$user")

        if [[ -d "$home_dir" ]]; then
            sudo chgrp "$group" "$home_dir"
            local current_group
            current_group=$(stat -c "%G" "$home_dir")
            if [[ "$current_group" == "$group" ]]; then
                log_message "$function_name" "$vuln_id" "$rule_id" "Changed group of $home_dir to $group."
            else
                log_message "$function_name" "$vuln_id" "$rule_id" "Failed to change group of $home_dir to $group. This is a finding."
            fi
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Home directory $home_dir does not exist. This is a finding."
        fi
    done
}

# Function to change the group of world-writable directories to root
change_group_of_world_writable_directories() {
    local function_name="change_group_of_world_writable_directories"
    local vuln_id="V-261306"
    local rule_id="SV-261306r996389"

    local world_writable_dirs
    world_writable_dirs=$(find / -type d -perm -002 2>/dev/null)

    for dir in $world_writable_dirs; do
        sudo chgrp root "$dir"
        local group
        group=$(stat -c "%G" "$dir")
        if [[ "$group" == "root" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Changed group of $dir to root."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to change group of $dir to root. This is a finding."
        fi
    done
}

# Function to set the sticky bit on world-writable directories
set_sticky_bit_on_world_writable_directories() {
    local function_name="set_sticky_bit_on_world_writable_directories"
    local vuln_id="V-261307"
    local rule_id="SV-261307r996392"

    local world_writable_dirs
    world_writable_dirs=$(find / -type d -perm -002 2>/dev/null)

    for dir in $world_writable_dirs; do
        sudo chmod 1777 "$dir"
        local mode
        mode=$(stat -c "%a" "$dir")
        if [[ "$mode" == "1777" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Set sticky bit on $dir."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set sticky bit on $dir. This is a finding."
        fi
    done
}

# Function to prevent unauthorized access to system error messages
prevent_unauthorized_access_to_error_messages() {
    local function_name="prevent_unauthorized_access_to_error_messages"
    local vuln_id="V-261308"
    local rule_id="SV-261308r996395"

    sudo sed -i '/\/var\/log\/messages/d' /etc/permissions.local
    echo "/var/log/messages root:root 640" | sudo tee -a /etc/permissions.local

    sudo chkstat --set --system

    local permissions
    permissions=$(stat -c "%a" /var/log/messages)
    local owner
    owner=$(stat -c "%U:%G" /var/log/messages)

    if [[ "$permissions" == "640" && "$owner" == "root:root" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Set permissions of /var/log/messages to root:root 640."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set permissions of /var/log/messages to root:root 640. This is a finding."
    fi
}

# Function to set permissions of log files to 640
set_log_files_permissions() {
    local function_name="set_log_files_permissions"
    local vuln_id="V-261309"
    local rule_id="SV-261309r996398"

    sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec chmod 640 '{}' \;

    local incorrect_permissions
    incorrect_permissions=$(find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f)

    if [[ -z "$incorrect_permissions" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Set permissions of all log files under /var/log to 640."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set permissions of some log files under /var/log. This is a finding."
    fi
}

# Function to configure firewalld and enable panic mode
configure_firewalld_and_panic_mode() {
    local function_name="configure_firewalld_and_panic_mode"
    local vuln_id="V-261310"
    local rule_id="SV-261310r996401"

    sudo systemctl enable firewalld.service --now

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "firewalld.service enabled and started successfully."
        sudo firewall-cmd --panic-on
        log_message "$function_name" "$vuln_id" "$rule_id" "Firewall set to panic mode."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to enable and start firewalld.service. This is a finding."
    fi
}

# Function to configure system clock to synchronize with an authoritative DOD time source
configure_clock_synchronization() {
    local function_name="configure_clock_synchronization"
    local vuln_id="V-261311"
    local rule_id="SV-261311r996404"
    
    local chrony_conf_file="/etc/chrony.conf"
    local time_source="<time_source>"  # Replace with the actual authoritative DOD time source

    if grep -q "server $time_source maxpoll 16" "$chrony_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "System clock already configured to synchronize with $time_source."
    else
        echo "server $time_source maxpoll 16" | sudo tee -a "$chrony_conf_file"
        sudo systemctl restart chronyd

        if grep -q "server $time_source maxpoll 16" "$chrony_conf_file"; then
            log_message "$function_name" "$vuln_id" "$rule_id" "System clock configured to synchronize with $time_source successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure system clock synchronization. This is a finding."
        fi
    fi
}

# Function to turn off promiscuous mode on network interfaces
turn_off_promiscuous_mode() {
    local function_name="turn_off_promiscuous_mode"
    local vuln_id="V-261312"
    local rule_id="SV-261312r996406"
    
    local network_interfaces
    network_interfaces=$(ip link show | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}')

    for interface in $network_interfaces; do
        sudo ip link set dev "$interface" promisc off
        local promisc_mode
        promisc_mode=$(ip link show "$interface" | grep -o "PROMISC")
        
        if [[ -z "$promisc_mode" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Promiscuous mode turned off for $interface."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to turn off promiscuous mode for $interface. This is a finding."
        fi
    done
}

# Function to disable IPv4 source routing
disable_ipv4_source_routing() {
    local function_name="disable_ipv4_source_routing"
    local vuln_id="V-261313"
    local rule_id="SV-261313r996409"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv4.conf.all.accept_source_route=0"

    sudo sysctl -w net.ipv4.conf.all.accept_source_route=0

    if grep -q "^net.ipv4.conf.all.accept_source_route" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv4.conf.all.accept_source_route.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv4.conf.all.accept_source_route)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv4 source routing has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv4 source routing. This is a finding."
    fi
}

# Function to disable IPv4 default source routing
disable_ipv4_default_source_routing() {
    local function_name="disable_ipv4_default_source_routing"
    local vuln_id="V-261314"
    local rule_id="SV-261314r996412"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv4.conf.default.accept_source_route=0"

    sudo sysctl -w net.ipv4.conf.default.accept_source_route=0

    if grep -q "^net.ipv4.conf.default.accept_source_route" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv4.conf.default.accept_source_route.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv4.conf.default.accept_source_route)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv4 default source routing has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv4 default source routing. This is a finding."
    fi
}

# Function to configure SLEM 5 to not accept IPv4 ICMP redirect messages
disable_ipv4_icmp_redirects_all() {
    local function_name="disable_ipv4_icmp_redirects_all"
    local vuln_id="V-261315"
    local rule_id="SV-261315r996415"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv4.conf.all.accept_redirects=0"

    sudo sysctl -w net.ipv4.conf.all.accept_redirects=0

    if grep -q "^net.ipv4.conf.all.accept_redirects" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv4.conf.all.accept_redirects.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv4.conf.all.accept_redirects)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv4 ICMP redirects acceptance has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv4 ICMP redirects acceptance. This is a finding."
    fi
}

# Function to configure SLEM 5 to not accept IPv4 ICMP redirect messages by default
disable_ipv4_icmp_redirects_default() {
    local function_name="disable_ipv4_icmp_redirects_default"
    local vuln_id="V-261316"
    local rule_id="SV-261316r996418"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv4.conf.default.accept_redirects=0"

    sudo sysctl -w net.ipv4.conf.default.accept_redirects=0

    if grep -q "^net.ipv4.conf.default.accept_redirects" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv4.conf.default.accept_redirects.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv4.conf.default.accept_redirects)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv4 ICMP redirects acceptance by default has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv4 ICMP redirects acceptance by default. This is a finding."
    fi
}

# Function to configure SLEM 5 to not allow interfaces to perform IPv4 ICMP redirects
disable_ipv4_icmp_send_redirects_all() {
    local function_name="disable_ipv4_icmp_send_redirects_all"
    local vuln_id="V-261317"
    local rule_id="SV-261317r996421"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv4.conf.all.send_redirects=0"

    sudo sysctl -w net.ipv4.conf.all.send_redirects=0

    if grep -q "^net.ipv4.conf.all.send_redirects" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv4.conf.all.send_redirects.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv4.conf.all.send_redirects)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv4 ICMP redirects sending has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv4 ICMP redirects sending. This is a finding."
    fi
}

# Function to configure SLEM 5 to not allow interfaces to perform IPv4 ICMP redirects by default
disable_ipv4_icmp_send_redirects_default() {
    local function_name="disable_ipv4_icmp_send_redirects_default"
    local vuln_id="V-261318"
    local rule_id="SV-261318r996424"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv4.conf.default.send_redirects=0"

    sudo sysctl -w net.ipv4.conf.default.send_redirects=0

    if grep -q "^net.ipv4.conf.default.send_redirects" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv4.conf.default.send_redirects.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv4.conf.default.send_redirects)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv4 ICMP redirects sending by default has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv4 ICMP redirects sending by default. This is a finding."
    fi
}

# Function to configure SLEM 5 to not perform IPv4 packet forwarding
disable_ipv4_packet_forwarding() {
    local function_name="disable_ipv4_packet_forwarding"
    local vuln_id="V-261319"
    local rule_id="SV-261319r996427"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv4.ip_forward=0"

    sudo sysctl -w net.ipv4.ip_forward=0

    if grep -q "^net.ipv4.ip_forward" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv4.ip_forward.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv4.ip_forward)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv4 packet forwarding has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv4 packet forwarding. This is a finding."
    fi
}

# Function to configure SLEM 5 to use IPv4 TCP syncookies
configure_tcp_syncookies() {
    local function_name="configure_tcp_syncookies"
    local vuln_id="V-261320"
    local rule_id="SV-261320r996861"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv4.tcp_syncookies=1"

    sudo sysctl -w net.ipv4.tcp_syncookies=1

    if grep -q "^net.ipv4.tcp_syncookies" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv4.tcp_syncookies.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv4.tcp_syncookies)

    if [[ "$param_value" -eq 1 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "TCP syncookies have been enabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to enable TCP syncookies. This is a finding."
    fi
}

# Function to configure SLEM 5 to disable IPv6 source routing
disable_ipv6_source_routing_all() {
    local function_name="disable_ipv6_source_routing_all"
    local vuln_id="V-261321"
    local rule_id="SV-261321r996433"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv6.conf.all.accept_source_route=0"

    sudo sysctl -w net.ipv6.conf.all.accept_source_route=0

    if grep -q "^net.ipv6.conf.all.accept_source_route" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv6.conf.all.accept_source_route.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv6.conf.all.accept_source_route)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv6 source routing has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv6 source routing. This is a finding."
    fi
}

# Function to configure SLEM 5 to disable IPv6 default source routing
disable_ipv6_source_routing_default() {
    local function_name="disable_ipv6_source_routing_default"
    local vuln_id="V-261322"
    local rule_id="SV-261322r996436"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv6.conf.default.accept_source_route=0"

    sudo sysctl -w net.ipv6.conf.default.accept_source_route=0

    if grep -q "^net.ipv6.conf.default.accept_source_route" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv6.conf.default.accept_source_route.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv6.conf.default.accept_source_route)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv6 default source routing has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv6 default source routing. This is a finding."
    fi
}

# Function to configure SLEM 5 to not accept IPv6 ICMP redirect messages
disable_ipv6_icmp_redirects_all() {
    local function_name="disable_ipv6_icmp_redirects_all"
    local vuln_id="V-261323"
    local rule_id="SV-261323r996439"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv6.conf.all.accept_redirects=0"

    sudo sysctl -w net.ipv6.conf.all.accept_redirects=0

    if grep -q "^net.ipv6.conf.all.accept_redirects" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv6.conf.all.accept_redirects.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv6.conf.all.accept_redirects)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv6 ICMP redirects acceptance has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv6 ICMP redirects acceptance. This is a finding."
    fi
}

# Function to configure SLEM 5 to not accept IPv6 ICMP redirect messages by default
disable_ipv6_icmp_redirects_default() {
    local function_name="disable_ipv6_icmp_redirects_default"
    local vuln_id="V-261324"
    local rule_id="SV-261324r996442"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv6.conf.default.accept_redirects=0"

    sudo sysctl -w net.ipv6.conf.default.accept_redirects=0

    if grep -q "^net.ipv6.conf.default.accept_redirects" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv6.conf.default.accept_redirects.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv6.conf.default.accept_redirects)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv6 ICMP redirects acceptance by default has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv6 ICMP redirects acceptance by default. This is a finding."
    fi
}

# Function to configure SLEM 5 to not perform IPv6 packet forwarding
disable_ipv6_packet_forwarding_all() {
    local function_name="disable_ipv6_packet_forwarding_all"
    local vuln_id="V-261325"
    local rule_id="SV-261325r996445"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv6.conf.all.forwarding=0"

    sudo sysctl -w net.ipv6.conf.all.forwarding=0

    if grep -q "^net.ipv6.conf.all.forwarding" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv6.conf.all.forwarding.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv6.conf.all.forwarding)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv6 packet forwarding has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv6 packet forwarding. This is a finding."
    fi
}

# Function to configure SLEM 5 to not perform IPv6 packet forwarding by default
disable_ipv6_packet_forwarding_default() {
    local function_name="disable_ipv6_packet_forwarding_default"
    local vuln_id="V-261326"
    local rule_id="SV-261326r996448"

    local sysctl_conf_file="/etc/sysctl.d/99-stig.conf"
    local kernel_param="net.ipv6.conf.default.forwarding=0"

    sudo sysctl -w net.ipv6.conf.default.forwarding=0

    if grep -q "^net.ipv6.conf.default.forwarding" "$sysctl_conf_file"; then
        sudo sed -i 's/^net.ipv6.conf.default.forwarding.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | sudo tee -a "$sysctl_conf_file"
    fi

    sudo sysctl --system

    local param_value
    param_value=$(sysctl -n net.ipv6.conf.default.forwarding)

    if [[ "$param_value" -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "IPv6 default packet forwarding has been disabled successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable IPv6 default packet forwarding. This is a finding."
    fi
}

# Function to configure SSH banner
configure_ssh_banner() {
    local function_name="configure_ssh_banner"
    local vuln_id="V-261329"
    local rule_id="SV-261329r996455"

    local sshd_config_file="/etc/ssh/sshd_config"
    local sshd_param="Banner /etc/issue"

    if grep -q "^Banner" "$sshd_config_file"; then
        sudo sed -i 's/^Banner.*/'"$sshd_param"'/' "$sshd_config_file"
    else
        echo "$sshd_param" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service

    if systemctl is-active --quiet sshd.service; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH banner has been configured successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure SSH banner. This is a finding."
    fi
}

# Function to configure SSH ClientAliveCountMax
configure_ssh_client_alive_count_max() {
    local function_name="configure_ssh_client_alive_count_max"
    local vuln_id="V-261331"
    local rule_id="SV-261331r996459"

    local sshd_config_file="/etc/ssh/sshd_config"
    local sshd_param="ClientAliveCountMax 1"

    if grep -q "^ClientAliveCountMax" "$sshd_config_file"; then
        sudo sed -i 's/^ClientAliveCountMax.*/'"$sshd_param"'/' "$sshd_config_file"
    else
        echo "$sshd_param" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service

    if systemctl is-active --quiet sshd.service; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH ClientAliveCountMax has been configured successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure SSH ClientAliveCountMax. This is a finding."
    fi
}

# Function to configure SSH ClientAliveInterval
configure_ssh_client_alive_interval() {
    local function_name="configure_ssh_client_alive_interval"
    local vuln_id="V-261332"
    local rule_id="SV-261332r996462"

    local sshd_config_file="/etc/ssh/sshd_config"
    local sshd_param="ClientAliveInterval 600"

    if grep -q "^ClientAliveInterval" "$sshd_config_file"; then
        sudo sed -i 's/^ClientAliveInterval.*/'"$sshd_param"'/' "$sshd_config_file"
    else
        echo "$sshd_param" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service

    if systemctl is-active --quiet sshd.service; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH ClientAliveInterval has been configured successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure SSH ClientAliveInterval. This is a finding."
    fi
}

# Function to add or modify the X11Forwarding directive in the SSH configuration
disable_ssh_x11_forwarding() {
    local function_name="disable_ssh_x11_forwarding"
    local vuln_id="V-261333"
    local rule_id="SV-261333r996464"

    local sshd_config_file="/etc/ssh/sshd_config"
    local x11_forwarding="X11Forwarding no"

    if grep -q "^X11Forwarding" "$sshd_config_file"; then
        sudo sed -i 's|^X11Forwarding.*|'"$x11_forwarding"'|' "$sshd_config_file"
    else
        echo "$x11_forwarding" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service

    if systemctl is-active sshd.service > /dev/null; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH X11Forwarding disabled and SSH service restarted successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable SSH X11Forwarding or restart SSH service. This is a finding."
    fi
}

# Function to add or modify the PermitRootLogin directive in the SSH configuration
deny_root_logon_ssh() {
    local function_name="deny_root_logon_ssh"
    local vuln_id="V-261337"
    local rule_id="SV-261337r996844"

    local sshd_config_file="/etc/ssh/sshd_config"
    local permit_root_login="PermitRootLogin no"

    if grep -q "^PermitRootLogin" "$sshd_config_file"; then
        sudo sed -i 's|^PermitRootLogin.*|'"$permit_root_login"'|' "$sshd_config_file"
    else
        echo "$permit_root_login" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service

    if systemctl is-active sshd.service > /dev/null; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH PermitRootLogin set to 'no' and SSH service restarted successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set SSH PermitRootLogin to 'no' or restart SSH service. This is a finding."
    fi
}

# Function to add or modify the LogLevel directive in the SSH configuration
verbose_ssh_logging() {
    local function_name="verbose_ssh_logging"
    local vuln_id="V-261338"
    local rule_id="SV-261338r996845"

    local sshd_config_file="/etc/ssh/sshd_config"
    local log_level="LogLevel VERBOSE"

    if grep -q "^LogLevel" "$sshd_config_file"; then
        sudo sed -i 's|^LogLevel.*|'"$log_level"'|' "$sshd_config_file"
    else
        echo "$log_level" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service

    if systemctl is-active sshd.service > /dev/null; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH LogLevel set to VERBOSE and SSH service restarted successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set SSH LogLevel to VERBOSE or restart SSH service. This is a finding."
    fi
}

# Function to add or modify the PrintLastLog directive in the SSH configuration
enable_print_last_log() {
    local function_name="enable_print_last_log"
    local vuln_id="V-261339"
    local rule_id="SV-261339r996480"

    local sshd_config_file="/etc/ssh/sshd_config"
    local print_last_log="PrintLastLog yes"

    if grep -q "^PrintLastLog" "$sshd_config_file"; then
        sudo sed -i 's|^PrintLastLog.*|'"$print_last_log"'|' "$sshd_config_file"
    else
        echo "$print_last_log" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service

    if systemctl is-active sshd.service > /dev/null; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH PrintLastLog set to yes and SSH service restarted successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set SSH PrintLastLog to yes or restart SSH service. This is a finding."
    fi
}

# Function to add or modify the IgnoreUserKnownHosts directive in the SSH configuration
disable_known_hosts_authentication() {
    local function_name="disable_known_hosts_authentication"
    local vuln_id="V-261340"
    local rule_id="SV-261340r996483"

    local sshd_config_file="/etc/ssh/sshd_config"
    local ignore_user_known_hosts="IgnoreUserKnownHosts yes"

    if grep -q "^IgnoreUserKnownHosts" "$sshd_config_file"; then
        sudo sed -i 's|^IgnoreUserKnownHosts.*|'"$ignore_user_known_hosts"'|' "$sshd_config_file"
    else
        echo "$ignore_user_known_hosts" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service

    if systemctl is-active sshd.service > /dev/null; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH IgnoreUserKnownHosts set to yes and SSH service restarted successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set SSH IgnoreUserKnownHosts to yes or restart SSH service. This is a finding."
    fi
}

# Function to add or modify the StrictModes directive in the SSH configuration
enable_strict_modes() {
    local function_name="enable_strict_modes"
    local vuln_id="V-261341"
    local rule_id="SV-261341r996486"

    local sshd_config_file="/etc/ssh/sshd_config"
    local strict_modes="StrictModes yes"

    if grep -q "^StrictModes" "$sshd_config_file"; then
        sudo sed -i 's|^StrictModes.*|'"$strict_modes"'|' "$sshd_config_file"
    else
        echo "$strict_modes" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service

    if systemctl is-active sshd.service > /dev/null; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH StrictModes set to yes and SSH service restarted successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set SSH StrictModes to yes or restart SSH service. This is a finding."
    fi
}

# Function to create a new private and public key pair with a passcode
create_ssh_key_pair_with_passphrase() {
    local function_name="create_ssh_key_pair_with_passphrase"
    local vuln_id="V-261342"
    local rule_id="SV-261342r996488"

    local key_file="/root/.ssh/id_rsa"
    local passphrase="<passphrase>"  # Replace with the actual passphrase

    sudo ssh-keygen -N "$passphrase" -f "$key_file"

    if [[ -f "${key_file}" && -f "${key_file}.pub" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "New SSH key pair created with passphrase successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to create SSH key pair with passphrase. This is a finding."
    fi
}

# Function to disable all wireless network interfaces
disable_wireless_interfaces() {
    local function_name="disable_wireless_interfaces"
    local vuln_id="V-261346"
    local rule_id="SV-261346r996496"

    local wireless_interfaces
    wireless_interfaces=$(ip link show | grep wlan | awk -F: '{print $2}' | tr -d ' ')

    for interface in $wireless_interfaces; do
        sudo wicked ifdown "$interface"

        if [[ $? -eq 0 ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Wireless interface $interface brought down successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to bring down wireless interface $interface. This is a finding."
        fi

        sudo rm "/etc/sysconfig/network/ifcfg-$interface"
        sudo rm "/etc/wicked/ifconfig/$interface.xml"

        if [[ ! -f "/etc/sysconfig/network/ifcfg-$interface" && ! -f "/etc/wicked/ifconfig/$interface.xml" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Configuration files for wireless interface $interface removed successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to remove configuration files for wireless interface $interface. This is a finding."
        fi
    done
}

# Example of calling the new function
configure_logon_banner
restrict_kernel_message_buffer
disable_kdump_service
configure_aslr
configure_kernel_address_leak_prevention
install_slem_patches
configure_remove_outdated_software
install_kbd_package
create_var_partition
create_home_partition
migrate_audit_data
configure_fstab_nosuid_nfs
configure_fstab_noexec_nfs
configure_fstab_nosuid_removable_media
configure_fstab_nosuid_home
disable_automount
protect_system_commands
protect_library_files
change_home_directory_permissions
set_init_file_permissions
set_ssh_public_key_permissions
set_ssh_private_key_permissions
protect_library_files_ownership
protect_library_files_group
protect_library_dirs_ownership
protect_library_dirs_group
protect_system_commands_ownership
protect_system_commands_directory_ownership
protect_system_commands_directory_group
assign_valid_user_to_unowned_files
assign_valid_group_to_ungrouped_files
change_home_directory_group
change_group_of_world_writable_directories
set_sticky_bit_on_world_writable_directories
prevent_unauthorized_access_to_error_messages
set_log_files_permissions
configure_firewalld_and_panic_mode
configure_clock_synchronization
turn_off_promiscuous_mode
disable_ipv4_source_routing
disable_ipv4_default_source_routing
disable_ipv4_icmp_redirects_all
disable_ipv4_icmp_redirects_default
disable_ipv4_icmp_send_redirects_all
disable_ipv4_icmp_send_redirects_default
disable_ipv4_packet_forwarding
configure_tcp_syncookies
disable_ipv6_source_routing_all
disable_ipv6_source_routing_default
disable_ipv6_icmp_redirects_all
disable_ipv6_icmp_redirects_default
disable_ipv6_packet_forwarding_all
disable_ipv6_packet_forwarding_default
configure_ssh_banner
configure_ssh_client_alive_count_max
configure_ssh_client_alive_interval
disable_ssh_x11_forwarding
deny_root_logon_ssh
verbose_ssh_logging
enable_print_last_log
disable_known_hosts_authentication
enable_strict_modes
create_ssh_key_pair_with_passphrase
disable_wireless_interfaces
