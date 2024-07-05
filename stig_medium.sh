#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Exiting."
    exit 1
fi

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

    echo "$banner_text" | tee "$issue_file" > /dev/null

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
        sed -i 's/^kernel.dmesg_restrict.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    for dir in "${sysctl_conf_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -type f -exec sed -i '/^kernel.dmesg_restrict/d' {} \;
        fi
    done

    sysctl --system

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
        systemctl disable kdump.service

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

    sysctl -w kernel.randomize_va_space=2

    if grep -q "^kernel.randomize_va_space" "$sysctl_conf_file"; then
        sed -i 's/^kernel.randomize_va_space.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w kernel.kptr_restrict=1

    if grep -q "^kernel.kptr_restrict" "$sysctl_conf_file"; then
        sed -i 's/^kernel.kptr_restrict.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    zypper patch

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
        sed -i 's/^solver.upgradeRemoveDroppedPackages.*/'"$config_line"'/' "$zypp_conf_file"
    else
        echo "$config_line" | tee -a "$zypp_conf_file"
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

    zypper in -y kbd

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

    local partition="/dev/sdZ1"  # Replace with the actual partition
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

# Function to configure /etc/fstab to use the nosuid option for NFS file systems
configure_fstab_nosuid_nfs() {
    local function_name="configure_fstab_nosuid_nfs"
    local vuln_id="V-261281"
    local rule_id="SV-261281r996326"

    if grep -q "nfs" /etc/fstab; then
        sed -i '/nfs/s/defaults/defaults,nosuid/' /etc/fstab
        mount -o remount -a

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
        sed -i '/nfs/s/defaults/defaults,noexec/' /etc/fstab
        mount -o remount -a

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
        sed -i '/removable/s/defaults/defaults,nosuid/' /etc/fstab
        mount -o remount -a

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
        sed -i '/\/home/s/defaults/defaults,nosuid/' /etc/fstab
        mount -o remount /home

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

    systemctl stop autofs

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "autofs service stopped successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to stop autofs service. This is a finding."
        return
    fi

    systemctl disable autofs

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

    find -L /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' \;
    find -L /bin /sbin /usr/bin /usr/sbin -perm /022 -type f -exec chmod 755 '{}' \;
    
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

    find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec chmod 755 '{}' \;

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
            chmod 750 "$home_dir"
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
                chmod 740 "$init_file"
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
        chmod 644 "$key_file"
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
        chmod 640 "$key_file"
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

    find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type f -exec chown root '{}' \;
    
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

    find /lib /lib64 /usr/lib /usr/lib64 ! -group root -type f -exec chgrp root '{}' \;
    
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

    find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec chown root '{}' \;

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

    find /lib /lib64 /usr/lib /usr/lib64 ! -group root -type d -exec chgrp root '{}' \;
    
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

    find -L /bin /sbin /usr/bin /usr/sbin ! -user root -type f -exec chown root '{}' \;
    
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

    find -L /bin /sbin /usr/bin /usr/sbin ! -user root -type d -exec chown root '{}' \;
    
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

    find -L /bin /sbin /usr/bin /usr/sbin ! -group root -type d -exec chgrp root '{}' \;

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
        chown root "$file"
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
        chgrp root "$file"
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
            chgrp "$group" "$home_dir"
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
        chgrp root "$dir"
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
        chmod 1777 "$dir"
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

    sed -i '/\/var\/log\/messages/d' /etc/permissions.local
    echo "/var/log/messages root:root 640" | tee -a /etc/permissions.local

    chkstat --set --system

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

    find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec chmod 640 '{}' \;

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

    systemctl enable firewalld.service --now

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "firewalld.service enabled and started successfully."
        firewall-cmd --panic-on
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
        echo "server $time_source maxpoll 16" | tee -a "$chrony_conf_file"
        systemctl restart chronyd

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
        ip link set dev "$interface" promisc off
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

    sysctl -w net.ipv4.conf.all.accept_source_route=0

    if grep -q "^net.ipv4.conf.all.accept_source_route" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv4.conf.all.accept_source_route.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv4.conf.default.accept_source_route=0

    if grep -q "^net.ipv4.conf.default.accept_source_route" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv4.conf.default.accept_source_route.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv4.conf.all.accept_redirects=0

    if grep -q "^net.ipv4.conf.all.accept_redirects" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv4.conf.all.accept_redirects.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv4.conf.default.accept_redirects=0

    if grep -q "^net.ipv4.conf.default.accept_redirects" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv4.conf.default.accept_redirects.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv4.conf.all.send_redirects=0

    if grep -q "^net.ipv4.conf.all.send_redirects" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv4.conf.all.send_redirects.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv4.conf.default.send_redirects=0

    if grep -q "^net.ipv4.conf.default.send_redirects" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv4.conf.default.send_redirects.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv4.ip_forward=0

    if grep -q "^net.ipv4.ip_forward" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv4.ip_forward.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv4.tcp_syncookies=1

    if grep -q "^net.ipv4.tcp_syncookies" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv4.tcp_syncookies.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv6.conf.all.accept_source_route=0

    if grep -q "^net.ipv6.conf.all.accept_source_route" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv6.conf.all.accept_source_route.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv6.conf.default.accept_source_route=0

    if grep -q "^net.ipv6.conf.default.accept_source_route" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv6.conf.default.accept_source_route.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv6.conf.all.accept_redirects=0

    if grep -q "^net.ipv6.conf.all.accept_redirects" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv6.conf.all.accept_redirects.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv6.conf.default.accept_redirects=0

    if grep -q "^net.ipv6.conf.default.accept_redirects" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv6.conf.default.accept_redirects.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv6.conf.all.forwarding=0

    if grep -q "^net.ipv6.conf.all.forwarding" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv6.conf.all.forwarding.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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

    sysctl -w net.ipv6.conf.default.forwarding=0

    if grep -q "^net.ipv6.conf.default.forwarding" "$sysctl_conf_file"; then
        sed -i 's/^net.ipv6.conf.default.forwarding.*/'"$kernel_param"'/' "$sysctl_conf_file"
    else
        echo "$kernel_param" | tee -a "$sysctl_conf_file"
    fi

    sysctl --system

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
        sed -i 's/^Banner.*/'"$sshd_param"'/' "$sshd_config_file"
    else
        echo "$sshd_param" | tee -a "$sshd_config_file"
    fi

    systemctl restart sshd.service

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
        sed -i 's/^ClientAliveCountMax.*/'"$sshd_param"'/' "$sshd_config_file"
    else
        echo "$sshd_param" | tee -a "$sshd_config_file"
    fi

    systemctl restart sshd.service

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
        sed -i 's/^ClientAliveInterval.*/'"$sshd_param"'/' "$sshd_config_file"
    else
        echo "$sshd_param" | tee -a "$sshd_config_file"
    fi

    systemctl restart sshd.service

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
        sed -i 's|^X11Forwarding.*|'"$x11_forwarding"'|' "$sshd_config_file"
    else
        echo "$x11_forwarding" | tee -a "$sshd_config_file"
    fi

    systemctl restart sshd.service

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
        sed -i 's|^PermitRootLogin.*|'"$permit_root_login"'|' "$sshd_config_file"
    else
        echo "$permit_root_login" | tee -a "$sshd_config_file"
    fi

    systemctl restart sshd.service

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
        sed -i 's|^LogLevel.*|'"$log_level"'|' "$sshd_config_file"
    else
        echo "$log_level" | tee -a "$sshd_config_file"
    fi

    systemctl restart sshd.service

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
        sed -i 's|^PrintLastLog.*|'"$print_last_log"'|' "$sshd_config_file"
    else
        echo "$print_last_log" | tee -a "$sshd_config_file"
    fi

    systemctl restart sshd.service

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
        sed -i 's|^IgnoreUserKnownHosts.*|'"$ignore_user_known_hosts"'|' "$sshd_config_file"
    else
        echo "$ignore_user_known_hosts" | tee -a "$sshd_config_file"
    fi

    systemctl restart sshd.service

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
        sed -i 's|^StrictModes.*|'"$strict_modes"'|' "$sshd_config_file"
    else
        echo "$strict_modes" | tee -a "$sshd_config_file"
    fi

    systemctl restart sshd.service

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

    ssh-keygen -N "$passphrase" -f "$key_file"

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
        wicked ifdown "$interface"

        if [[ $? -eq 0 ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Wireless interface $interface brought down successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to bring down wireless interface $interface. This is a finding."
        fi

        rm "/etc/sysconfig/network/ifcfg-$interface"
        rm "/etc/wicked/ifconfig/$interface.xml"

        if [[ ! -f "/etc/sysconfig/network/ifcfg-$interface" && ! -f "/etc/wicked/ifconfig/$interface.xml" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Configuration files for wireless interface $interface removed successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to remove configuration files for wireless interface $interface. This is a finding."
        fi
    done
}

# Function to prevent USB mass storage devices from automounting
prevent_usb_automount() {
    local function_name="prevent_usb_automount"
    local vuln_id="V-261347"
    local rule_id="SV-261347r996498"

    local modprobe_conf_file="/etc/modprobe.d/50-blacklist.conf"
    local blacklist_usb="blacklist usb-storage"

    if grep -q "^blacklist usb-storage" "$modprobe_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "USB mass storage automounting already prevented."
    else
        echo "$blacklist_usb" | tee -a "$modprobe_conf_file"

        if grep -q "^blacklist usb-storage" "$modprobe_conf_file"; then
            log_message "$function_name" "$vuln_id" "$rule_id" "USB mass storage automounting prevented successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to prevent USB mass storage automounting. This is a finding."
        fi
    fi
}

# Function to assign home directories to new local interactive users
assign_home_directories_new_users() {
    local function_name="assign_home_directories_new_users"
    local vuln_id="V-261348"
    local rule_id="SV-261348r996500"

    local login_defs_file="/etc/login.defs"
    local create_home="CREATE_HOME yes"

    if grep -q "^CREATE_HOME" "$login_defs_file"; then
        sed -i 's/^CREATE_HOME.*/'"$create_home"'/' "$login_defs_file"
    else
        echo "$create_home" | tee -a "$login_defs_file"
    fi

    if grep -q "^CREATE_HOME yes" "$login_defs_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Home directories will be assigned to new local interactive users."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure home directory creation for new users. This is a finding."
    fi
}

# Function to define default permissions for authenticated users
define_default_permissions() {
    local function_name="define_default_permissions"
    local vuln_id="V-261349"
    local rule_id="SV-261349r996502"

    local login_defs_file="/etc/login.defs"
    local umask_setting="UMASK 077"

    if grep -q "^UMASK" "$login_defs_file"; then
        sed -i 's/^UMASK.*/'"$umask_setting"'/' "$login_defs_file"
    else
        echo "$umask_setting" | tee -a "$login_defs_file"
    fi

    if grep -q "^UMASK 077" "$login_defs_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Default permissions for authenticated users defined successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to define default permissions for authenticated users. This is a finding."
    fi
}

# Function to enforce a delay between logon prompts
enforce_logon_delay() {
    local function_name="enforce_logon_delay"
    local vuln_id="V-261350"
    local rule_id="SV-261350r996504"

    local login_defs_file="/etc/login.defs"
    local fail_delay="FAIL_DELAY 5"

    if grep -q "^FAIL_DELAY" "$login_defs_file"; then
        sed -i 's/^FAIL_DELAY.*/'"$fail_delay"'/' "$login_defs_file"
    else
        echo "$fail_delay" | tee -a "$login_defs_file"
    fi

    if grep -q "^FAIL_DELAY 5" "$login_defs_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Delay between logon prompts enforced successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to enforce delay between logon prompts. This is a finding."
    fi
}

# Function to assign home directories to existing local interactive users
assign_home_directories_existing_users() {
    local function_name="assign_home_directories_existing_users"
    local vuln_id="V-261351"
    local rule_id="SV-261351r996506"

    local users_without_home
    users_without_home=$(awk -F: '($3 >= 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false" && !system("test -d "$6)) {print $1}' /etc/passwd)

    for user in $users_without_home; do
        local home_dir="/home/$user"
        mkdir -p "$home_dir"
        usermod -d "$home_dir" "$user"
        chown "$user:$user" "$home_dir"

        if [[ -d "$home_dir" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Home directory $home_dir assigned to user $user."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to assign home directory $home_dir to user $user. This is a finding."
        fi
    done
}

# Function to create home directories for local interactive users
create_home_directories() {
    local function_name="create_home_directories"
    local vuln_id="V-261352"
    local rule_id="SV-261352r996862"

    local users_without_home
    users_without_home=$(awk -F: '($3 >= 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false" && !system("test -d "$6)) {print $1 ":" $6 ":" $4}' /etc/passwd)

    for user_info in $users_without_home; do
        local user
        local home_dir
        local group
        IFS=: read -r user home_dir group <<< "$user_info"

        mkdir -p "$home_dir"
        chown "$user" "$home_dir"
        chgrp "$group" "$home_dir"
        chmod 0750 "$home_dir"

        if [[ -d "$home_dir" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Home directory $home_dir created for user $user."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to create home directory $home_dir for user $user. This is a finding."
        fi
    done
}

# Function to edit local interactive user initialization files to change any PATH variable statements
edit_user_init_files() {
    local function_name="edit_user_init_files"
    local vuln_id="V-261353"
    local rule_id="SV-261353r996512"

    local user_home_dirs
    user_home_dirs=$(awk -F: '($3 >= 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false") {print $6}' /etc/passwd)

    for home_dir in $user_home_dirs; do
        local init_files
        init_files=$(find "$home_dir" -maxdepth 1 -name ".*" -type f)

        for init_file in $init_files; do
            if grep -q "PATH=" "$init_file"; then
                sed -i '/PATH=/s|:[^:]*/[^:]||g' "$init_file"
                log_message "$function_name" "$vuln_id" "$rule_id" "Edited PATH variable in $init_file for user in $home_dir."
            fi
        done
    done
}

# Function to remove world-writable permissions or references in init scripts
remove_world_writable_permissions() {
    local function_name="remove_world_writable_permissions"
    local vuln_id="V-261354"
    local rule_id="SV-261354r996514"

    local user_home_dirs
    user_home_dirs=$(awk -F: '($3 >= 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false") {print $6}' /etc/passwd)

    for home_dir in $user_home_dirs; do
        local init_files
        init_files=$(find "$home_dir" -maxdepth 1 -name ".*" -type f)

        for init_file in $init_files; do
            if grep -q ":[^:]*/[^:]*" "$init_file"; then
                sed -i '/[^:]* /d' "$init_file"
                log_message "$function_name" "$vuln_id" "$rule_id" "Removed references to world-writable files in $init_file for user in $home_dir."
            fi
        done
    done
}

# Function to expire temporary accounts after 72 hours
expire_temporary_accounts() {
    local function_name="expire_temporary_accounts"
    local vuln_id="V-261355"
    local rule_id="SV-261355r996516"

    local temporary_accounts
    temporary_accounts=$(awk -F: '($3 >= 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false") {print $1}' /etc/passwd)

    for account in $temporary_accounts; do
        chage -E "$(date -d +3days +%Y-%m-%d)" "$account"

        if [[ $? -eq 0 ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Temporary account $account set to expire in 72 hours."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set expiration for temporary account $account. This is a finding."
        fi
    done
}

# Function to never automatically remove or disable emergency administrator accounts
configure_emergency_admin_accounts() {
    local function_name="configure_emergency_admin_accounts"
    local vuln_id="V-261356"
    local rule_id="SV-261356r996518"

    local emergency_accounts
    emergency_accounts=$(awk -F: '($3 >= 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false") {print $1}' /etc/passwd)

    for account in $emergency_accounts; do
        chage -I -1 -M 99999 "$account"

        if [[ $? -eq 0 ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Emergency administrator account $account configured not to expire."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure emergency administrator account $account. This is a finding."
        fi
    done
}

# Function to ensure all accounts are assigned to an active system, application, or user account
assign_accounts_to_active_entities() {
    local function_name="assign_accounts_to_active_entities"
    local vuln_id="V-261357"
    local rule_id="SV-261357r996521"

    local inactive_accounts
    inactive_accounts=$(awk -F: '($3 >= 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false") {print $1}' /etc/passwd)

    for account in $inactive_accounts; do
        userdel "$account"

        if [[ $? -eq 0 ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Inactive account $account removed successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to remove inactive account $account. This is a finding."
        fi
    done
}

# Function to disable interactive shell for noninteractive accounts
disable_interactive_shell_noninteractive_accounts() {
    local function_name="disable_interactive_shell_noninteractive_accounts"
    local vuln_id="V-261358"
    local rule_id="SV-261358r996829"

    local noninteractive_accounts
    noninteractive_accounts=$(awk -F: '($3 >= 1000 && $7 == "/bin/bash") {print $1}' /etc/passwd)

    for account in $noninteractive_accounts; do
        usermod --shell /sbin/nologin "$account"

        if [[ $? -eq 0 ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Interactive shell disabled for noninteractive account $account."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable interactive shell for noninteractive account $account. This is a finding."
        fi
    done
}

# Function to disable account identifiers after 35 days of inactivity
disable_inactive_accounts() {
    local function_name="disable_inactive_accounts"
    local vuln_id="V-261360"
    local rule_id="SV-261360r996529"

    useradd -D -f 35

    local inactive_days
    inactive_days=$(useradd -D | grep INACTIVE | awk -F= '{print $2}')

    if [[ "$inactive_days" -eq 35 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured to disable account identifiers after 35 days of inactivity successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure disabling of account identifiers after 35 days of inactivity. This is a finding."
    fi
}

# Function to ensure no duplicate UIDs for interactive users
ensure_unique_uids() {
    local function_name="ensure_unique_uids"
    local vuln_id="V-261361"
    local rule_id="SV-261361r996530"

    local duplicate_uids
    duplicate_uids=$(awk -F: '($3 >= 1000) {print $3}' /etc/passwd | sort | uniq -d)

    if [[ -n "$duplicate_uids" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Found duplicate UIDs: $duplicate_uids. Manual intervention required to resolve."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "No duplicate UIDs found for interactive users."
    fi
}

# Function to provide users with feedback on last account access
configure_pam_lastlog() {
    local function_name="configure_pam_lastlog"
    local vuln_id="V-261362"
    local rule_id="SV-261362r996533"

    local pam_login_file="/etc/pam.d/login"
    local pam_lastlog="session required pam_lastlog.so showfailed"

    if grep -q "^session.*pam_lastlog.so.*showfailed" "$pam_login_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "pam_lastlog.so is already configured in $pam_login_file."
    else
        sed -i "1s/^/$pam_lastlog\n/" "$pam_login_file"
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured pam_lastlog.so in $pam_login_file."
    fi
}

# Function to initiate session lock after 15 minutes of inactivity
configure_autologout() {
    local function_name="configure_autologout"
    local vuln_id="V-261363"
    local rule_id="SV-261363r996536"

    local autologout_file="/etc/profile.d/autologout.sh"

    echo "TMOUT=900" | tee "$autologout_file"
    echo "readonly TMOUT" | tee -a "$autologout_file"
    echo "export TMOUT" | tee -a "$autologout_file"
    chmod +x "$autologout_file"

    if [[ -f "$autologout_file" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured autologout after 15 minutes of inactivity."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure autologout. This is a finding."
    fi
}

# Function to lock account after three unsuccessful access attempts
configure_pam_tally2() {
    local function_name="configure_pam_tally2"
    local vuln_id="V-261364"
    local rule_id="SV-261364r996863"

    local common_auth_file="/etc/pam.d/common-auth"
    local common_account_file="/etc/pam.d/common-account"

    sed -i '/pam_tally2.so/d' "$common_auth_file"
    sed -i '/pam_tally2.so/d' "$common_account_file"

    echo "auth required pam_tally2.so onerr=fail silent audit deny=3" | tee -a "$common_auth_file"
    echo "account required pam_tally2.so" | tee -a "$common_account_file"

    if grep -q "pam_tally2.so" "$common_auth_file" && grep -q "pam_tally2.so" "$common_account_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured pam_tally2.so to lock accounts after three unsuccessful attempts."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure pam_tally2.so. This is a finding."
    fi
}

# Function to enforce a delay between logon prompts following a failed logon attempt
configure_logon_delay() {
    local function_name="configure_logon_delay"
    local vuln_id="V-261365"
    local rule_id="SV-261365r996541"

    local common_auth_file="/etc/pam.d/common-auth"
    local faildelay_config="auth required pam_faildelay.so delay=5000000"

    if grep -q "^auth.*pam_faildelay.so" "$common_auth_file"; then
        sed -i 's|^auth.*pam_faildelay.so.*|'"$faildelay_config"'|' "$common_auth_file"
    else
        echo "$faildelay_config" | tee -a "$common_auth_file"
    fi

    if grep -q "^auth.*pam_faildelay.so.*delay=5000000" "$common_auth_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured delay between logon prompts successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure delay between logon prompts. This is a finding."
    fi
}

# Function to configure SLEM 5 to use the default pam_tally2 tally directory while SELinux enforces a targeted policy
configure_pam_tally2_directory() {
    local function_name="configure_pam_tally2_directory"
    local vuln_id="V-261366"
    local rule_id="SV-261366r996837"

    local pam_login_file="/etc/pam.d/login"

    # Remove non-default tally directory configuration
    sed -ri 's/\s+file=\S+\s+/ /g' "$pam_login_file"

    # Update SELinux context type for the default pam_tally2 tally directory
    semanage fcontext -a -t tallylog_t "/var/log/tallylog"
    restorecon -R -v /var/log/tallylog

    # Verify SELinux context
    local selinux_context
    selinux_context=$(ls -Z /var/log/tallylog | awk '{print $3}')

    if [[ "$selinux_context" == "tallylog_t" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured default pam_tally2 tally directory successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure default pam_tally2 tally directory. This is a finding."
    fi
}

# Function to configure SLEM 5 to verify correct operation of all security functions
configure_selinux_targeted_policy() {
    local function_name="configure_selinux_targeted_policy"
    local vuln_id="V-261370"
    local rule_id="SV-261370r996551"

    local selinux_config_file="/etc/selinux/config"
    local selinux_type_config="SELINUXTYPE=targeted"

    if grep -q "^SELINUXTYPE" "$selinux_config_file"; then
        sed -i 's|^SELINUXTYPE=.*|'"$selinux_type_config"'|' "$selinux_config_file"
    else
        echo "$selinux_type_config" | tee -a "$selinux_config_file"
    fi

    if grep -q "^SELINUXTYPE=targeted" "$selinux_config_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured SELINUXTYPE to targeted successfully. A reboot is required."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure SELINUXTYPE to targeted. This is a finding."
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

# Function to define defaults in the sudoers file
configure_sudoers_defaults() {
    local function_name="configure_sudoers_defaults"
    local vuln_id="V-261372"
    local rule_id="SV-261372r996556"

    local sudoers_file="/etc/sudoers"
    local defaults="Defaults !targetpw\nDefaults !rootpw\nDefaults !runaspw"

    if ! grep -q "!targetpw" "$sudoers_file"; then
        echo -e "$defaults" | tee -a "$sudoers_file"
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured sudoers defaults."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Sudoers defaults already configured."
    fi
}

# Function to remove NOPASSWD or !authenticate from sudoers
remove_nopasswd_from_sudoers() {
    local function_name="remove_nopasswd_from_sudoers"
    local vuln_id="V-261373"
    local rule_id="SV-261373r996558"

    local sudoers_file="/etc/sudoers"
    
    sed -i '/NOPASSWD/d' "$sudoers_file"
    sed -i '/!authenticate/d' "$sudoers_file"

    if ! grep -q "NOPASSWD" "$sudoers_file" && ! grep -q "!authenticate" "$sudoers_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Removed NOPASSWD and !authenticate from sudoers."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to remove NOPASSWD or !authenticate from sudoers. This is a finding."
    fi
}

# Function to require reauthentication for command
#########################################################
#
# reauthentication with a timeout value of 5 minutes
# Example usage: require_sudo_reauthentication 5
#
#########################################################
require_sudo_reauthentication() {
    local function_name="require_sudo_reauthentication"
    local vuln_id="V-261374"
    local rule_id="SV-261374r996560"
    local timeout_value="$1"

    local sudoers_file="/etc/sudoers"
    local timeout_config="Defaults timestamp_timeout=$timeout_value"

    if grep -q "^Defaults.*timestamp_timeout" "$sudoers_file"; then
        sed -i 's/^Defaults.*timestamp_timeout.*/'"$timeout_config"'/' "$sudoers_file"
    else
        echo "$timeout_config" | tee -a "$sudoers_file"
    fi

    if grep -q "^Defaults.*timestamp_timeout=$timeout_value" "$sudoers_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured to require reauthentication with timestamp timeout of $timeout_value."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure reauthentication. This is a finding."
    fi
}

# Function to remove specific entries from the sudoers file
remove_specific_sudoers_entries() {
    local function_name="remove_specific_sudoers_entries"
    local vuln_id="V-261375"
    local rule_id="SV-261375r996562"

    local sudoers_file="/etc/sudoers"

    sed -i '/ALL\s\+ALL=(ALL)\s\+ALL/d' "$sudoers_file"
    sed -i '/ALL\s\+ALL=(ALL:ALL)\s\+ALL/d' "$sudoers_file"

    if ! grep -q 'ALL\s\+ALL=(ALL)\s\+ALL' "$sudoers_file" && ! grep -q 'ALL\s\+ALL=(ALL:ALL)\s\+ALL' "$sudoers_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Removed specified entries from sudoers."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to remove specified entries from sudoers. This is a finding."
    fi
}

# Function to configure the /etc/sudoers file to only include the /etc/sudoers.d directory
configure_sudoers_include() {
    local function_name="configure_sudoers_include"
    local vuln_id="V-261376"
    local rule_id="SV-261376r996564"

    local sudoers_file="/etc/sudoers"
    local include_dir="@includedir /etc/sudoers.d"

    if grep -q "^@includedir" "$sudoers_file"; then
        sed -i 's|^@includedir.*|'"$include_dir"'|' "$sudoers_file"
    else
        echo "$include_dir" | tee -a "$sudoers_file"
    fi

    find /etc/sudoers.d -type f -exec sed -i '/@includedir/d' {} \;

    if grep -q "^@includedir /etc/sudoers.d" "$sudoers_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured sudoers to include /etc/sudoers.d directory."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure sudoers to include /etc/sudoers.d directory. This is a finding."
    fi
}

# Function to enforce password complexity by requiring at least one uppercase character
enforce_password_complexity_uppercase() {
    local function_name="enforce_password_complexity_uppercase"
    local vuln_id="V-261377"
    local rule_id="SV-261377r996566"

    local common_password_file="/etc/pam.d/common-password"
    local ucredit_option="ucredit=-1"

    if grep -q "pam_cracklib.so" "$common_password_file"; then
        sed -i '/pam_cracklib.so/ s/$/ '"$ucredit_option"'/' "$common_password_file"
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured password complexity to require at least one uppercase character."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure password complexity for uppercase character. This is a finding."
    fi
}

# Function to enforce password complexity by requiring at least one lowercase character
enforce_password_complexity_lowercase() {
    local function_name="enforce_password_complexity_lowercase"
    local vuln_id="V-261378"
    local rule_id="SV-261378r996568"

    local common_password_file="/etc/pam.d/common-password"
    local lcredit_option="lcredit=-1"

    if grep -q "pam_cracklib.so" "$common_password_file"; then
        sed -i '/pam_cracklib.so/ s/$/ '"$lcredit_option"'/' "$common_password_file"
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured password complexity to require at least one lowercase character."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure password complexity for lowercase character. This is a finding."
    fi
}

# Function to enforce password complexity by requiring at least one numeric character
enforce_password_complexity_numeric() {
    local function_name="enforce_password_complexity_numeric"
    local vuln_id="V-261379"
    local rule_id="SV-261379r996570"

    local common_password_file="/etc/pam.d/common-password"
    local dcredit_option="dcredit=-1"

    if grep -q "pam_cracklib.so" "$common_password_file"; then
        sed -i '/pam_cracklib.so/ s/$/ '"$dcredit_option"'/' "$common_password_file"
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured password complexity to require at least one numeric character."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure password complexity for numeric character. This is a finding."
    fi
}

# Function to enforce password complexity by requiring at least one special character
enforce_password_complexity_special() {
    local function_name="enforce_password_complexity_special"
    local vuln_id="V-261380"
    local rule_id="SV-261380r996572"

    local common_password_file="/etc/pam.d/common-password"
    local ocredit_option="ocredit=-1"

    if grep -q "pam_cracklib.so" "$common_password_file"; then
        sed -i '/pam_cracklib.so/ s/$/ '"$ocredit_option"'/' "$common_password_file"
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured password complexity to require at least one special character."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure password complexity for special character. This is a finding."
    fi
}

# Function to prevent the use of dictionary words for passwords
prevent_dictionary_passwords() {
    local function_name="prevent_dictionary_passwords"
    local vuln_id="V-261381"
    local rule_id="SV-261381r996574"

    local common_password_file="/etc/pam.d/common-password"
    local cracklib_line="password requisite pam_cracklib.so"

    if grep -q "pam_cracklib.so" "$common_password_file"; then
        sed -i '/pam_cracklib.so/ s/^/#/' "$common_password_file"
    fi

    echo "$cracklib_line" | tee -a "$common_password_file"

    if grep -q "^password requisite pam_cracklib.so" "$common_password_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured to prevent the use of dictionary words for passwords."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure prevention of dictionary words for passwords. This is a finding."
    fi
}

# Function to enforce a minimum 15-character password length
enforce_min_password_length() {
    local function_name="enforce_min_password_length"
    local vuln_id="V-261382"
    local rule_id="SV-261382r996577"

    local common_password_file="/etc/pam.d/common-password"
    local minlen_option="minlen=15"

    if grep -q "pam_cracklib.so" "$common_password_file"; then
        sed -i '/pam_cracklib.so/ s/$/ '"$minlen_option"'/' "$common_password_file"
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured minimum password length to 15 characters."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure minimum password length. This is a finding."
    fi
}

# Function to require at least eight characters be changed between old and new passwords
enforce_password_change_difok() {
    local function_name="enforce_password_change_difok"
    local vuln_id="V-261383"
    local rule_id="SV-261383r996580"

    local common_password_file="/etc/pam.d/common-password"
    local difok_option="difok=8"

    if grep -q "pam_cracklib.so" "$common_password_file"; then
        sed -i '/pam_cracklib.so/ s/$/ '"$difok_option"'/' "$common_password_file"
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured password change to require at least eight different characters."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure password change requirement. This is a finding."
    fi
}

# Function to enforce password history to prohibit reuse for five generations
enforce_password_history() {
    local function_name="enforce_password_history"
    local vuln_id="V-261384"
    local rule_id="SV-261384r996583"

    local common_password_file="/etc/pam.d/common-password"
    local history_option="remember=5 use_authtok"

    if grep -q "pam_pwhistory.so" "$common_password_file"; then
        sed -i '/pam_pwhistory.so/ s/$/ '"$history_option"'/' "$common_password_file"
    else
        echo "password requisite pam_pwhistory.so $history_option" | tee -a "$common_password_file"
    fi

    if grep -q "pam_pwhistory.so.*remember=5" "$common_password_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured password history to prohibit reuse for five generations."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure password history requirement. This is a finding."
    fi
}

# Function to store only encrypted representations of passwords
store_encrypted_passwords() {
    local function_name="store_encrypted_passwords"
    local vuln_id="V-261385"
    local rule_id="SV-261385r996586"

    local common_password_file="/etc/pam.d/common-password"
    local unix_option="sha512"

    if grep -q "pam_unix.so" "$common_password_file"; then
        sed -i '/pam_unix.so/ s/$/ '"$unix_option"'/' "$common_password_file"
        sed -i '/pam_unix.so/ s/nullok//' "$common_password_file"
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured to store only encrypted representations of passwords with SHA512."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure encrypted password storage. This is a finding."
    fi
}

# Function to enforce a minimum password age of one day
#######################################################
#
# example of usage: enforce_min_password_age "username"
#
#######################################################
enforce_min_password_age() {
    local function_name="enforce_min_password_age"
    local vuln_id="V-261388"
    local rule_id="SV-261388r996591"
    local username="$1"

    passwd -n 1 "$username"

    local min_age
    min_age=$(chage -l "$username" | grep "Minimum" | awk '{print $4}')

    if [[ "$min_age" -eq 1 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured minimum password age of one day for user $username."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure minimum password age for user $username. This is a finding."
    fi
}

# Function to enforce a maximum password age of 60 days
#######################################################
#
# example of usage: enforce_max_password_age "username"
#
#######################################################
enforce_max_password_age() {
    local function_name="enforce_max_password_age"
    local vuln_id="V-261389"
    local rule_id="SV-261389r996593"
    local username="$1"

    passwd -x 60 "$username"

    local max_age
    max_age=$(chage -l "$username" | grep "Maximum" | awk '{print $4}')

    if [[ "$max_age" -eq 60 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured maximum password age of 60 days for user $username."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure maximum password age for user $username. This is a finding."
    fi
}

# Function to create the password history file
create_password_history_file() {
    local function_name="create_password_history_file"
    local vuln_id="V-261390"
    local rule_id="SV-261390r996595"

    local history_file="/etc/security/opasswd"

    touch "$history_file"
    chown root:root "$history_file"
    chmod 0600 "$history_file"

    if [[ -f "$history_file" && "$(stat -c %U "$history_file")" == "root" && "$(stat -c %G "$history_file")" == "root" && "$(stat -c %a "$history_file")" == "600" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Created password history file with correct ownership and permissions."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to create password history file. This is a finding."
    fi
}

# Function to configure SLEM 5 to require ENCRYPT_METHOD of SHA512
configure_encrypt_method() {
    local function_name="configure_encrypt_method"
    local vuln_id="V-261393"
    local rule_id="SV-261393r996602"

    local login_defs_file="/etc/login.defs"
    local encrypt_method="ENCRYPT_METHOD SHA512"

    if grep -q "^ENCRYPT_METHOD" "$login_defs_file"; then
        sed -i 's/^ENCRYPT_METHOD.*/'"$encrypt_method"'/' "$login_defs_file"
    else
        echo "$encrypt_method" | tee -a "$login_defs_file"
    fi

    if grep -q "^ENCRYPT_METHOD SHA512" "$login_defs_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured ENCRYPT_METHOD to SHA512 successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure ENCRYPT_METHOD to SHA512. This is a finding."
    fi
}

# Function to enforce minimum password age
configure_min_password_age() {
    local function_name="configure_min_password_age"
    local vuln_id="V-261394"
    local rule_id="SV-261394r996604"
    local min_password_age=1

    local login_defs_file="/etc/login.defs"
    local min_days="PASS_MIN_DAYS $min_password_age"

    if grep -q "^PASS_MIN_DAYS" "$login_defs_file"; then
        sed -i 's/^PASS_MIN_DAYS.*/'"$min_days"'/' "$login_defs_file"
    else
        echo "$min_days" | tee -a "$login_defs_file"
    fi

    if grep -q "^PASS_MIN_DAYS $min_password_age" "$login_defs_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured minimum password age to $min_password_age days successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure minimum password age. This is a finding."
    fi
}


# Function to enforce maximum password age
configure_max_password_age() {
    local function_name="configure_max_password_age"
    local vuln_id="V-261395"
    local rule_id="SV-261395r996607"
    local max_password_age=60

    local login_defs_file="/etc/login.defs"
    local max_days="PASS_MAX_DAYS $max_password_age"

    if grep -q "^PASS_MAX_DAYS" "$login_defs_file"; then
        sed -i 's/^PASS_MAX_DAYS.*/'"$max_days"'/' "$login_defs_file"
    else
        echo "$max_days" | tee -a "$login_defs_file"
    fi

    if grep -q "^PASS_MAX_DAYS $max_password_age" "$login_defs_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured maximum password age to $max_password_age days successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure maximum password age. This is a finding."
    fi
}

# Function to implement multifactor authentication by installing required packages
install_mfa_packages() {
    local function_name="install_mfa_packages"
    local vuln_id="V-261396"
    local rule_id="SV-261396r996610"

    local packages=("pam_pkcs11" "mozilla-nss" "mozilla-nss-tools" "pcsc-ccid" "pcsc-lite" "pcsc-tools" "opensc" "coolkey")

    for package in "${packages[@]}"; do
        zypper in -y "$package"
        if [[ $? -eq 0 ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Installed package $package successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to install package $package. This is a finding."
        fi
    done
}

# Function to implement multifactor authentication for remote access to privileged accounts via PAM
configure_mfa_pam() {
    local function_name="configure_mfa_pam"
    local vuln_id="V-261397"
    local rule_id="SV-261397r996612"

    local common_auth_file="/etc/pam.d/common-auth"
    local mfa_line="auth sufficient pam_pkcs11.so"

    if grep -q "pam_pkcs11.so" "$common_auth_file"; then
        sed -i 's|^auth.*pam_pkcs11.so.*|'"$mfa_line"'|' "$common_auth_file"
    else
        echo "$mfa_line" | tee -a "$common_auth_file"
    fi

    if grep -q "^auth sufficient pam_pkcs11.so" "$common_auth_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured multifactor authentication for remote access to privileged accounts via PAM successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure multifactor authentication for remote access to privileged accounts via PAM. This is a finding."
    fi
}

# Function to enable certificate status checking for PKI authentication
enable_cert_status_checking() {
    local function_name="enable_cert_status_checking"
    local vuln_id="V-261398"
    local rule_id="SV-261398r996615"

    local pam_pkcs11_conf_file="/etc/pam_pkcs11/pam_pkcs11.conf"
    local cert_policy_option="ocsp_on"

    sed -i 's|cert_policy = .*|&,'" $cert_policy_option"'|' "$pam_pkcs11_conf_file"

    if grep -q "cert_policy =.*ocsp_on" "$pam_pkcs11_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Enabled certificate status checking for PKI authentication successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to enable certificate status checking for PKI authentication. This is a finding."
    fi
}

# Function to configure NSS to prohibit cached authentications after one day
configure_nss_cache_timeout() {
    local function_name="configure_nss_cache_timeout"
    local vuln_id="V-261399"
    local rule_id="SV-261399r996617"

    if grep -q "^\[nss\]" /etc/sssd/sssd.conf; then
        if grep -q "memcache_timeout" /etc/sssd/sssd.conf; then
            sed -i '/memcache_timeout/c\memcache_timeout = 86400' /etc/sssd/sssd.conf
        else
            sed -i '/^\[nss\]/a\memcache_timeout = 86400' /etc/sssd/sssd.conf
        fi
    else
        echo -e "[nss]\nmemcache_timeout = 86400" | tee -a /etc/sssd/sssd.conf
    fi

    if grep -q "^memcache_timeout = 86400" /etc/sssd/sssd.conf; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured NSS to prohibit cached authentications after one day successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure NSS cache timeout. This is a finding."
    fi
}


# Function to configure PAM to prohibit cached authentications after one day
configure_pam_cache_timeout() {
    local function_name="configure_pam_cache_timeout"
    local vuln_id="V-261400"
    local rule_id="SV-261400r996619"

    if grep -q "^\[pam\]" /etc/sssd/sssd.conf; then
        if grep -q "offline_credentials_expiration" /etc/sssd/sssd.conf; then
            sed -i 's|offline_credentials_expiration.*|offline_credentials_expiration = 1|' /etc/sssd/sssd.conf
        else
            sed -i '/^\[pam\]/a\offline_credentials_expiration = 1' /etc/sssd/sssd.conf
        fi
    else
        echo -e "[pam]\noffline_credentials_expiration = 1" | tee -a /etc/sssd/sssd.conf
    fi

    if grep -q "^offline_credentials_expiration = 1" /etc/sssd/sssd.conf; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured PAM to prohibit cached authentications after one day successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure PAM cache timeout. This is a finding."
    fi
}


# Function to validate certificates for PKI-based authentication
validate_pki_certificates() {
    local function_name="validate_pki_certificates"
    local vuln_id="V-261401"
    local rule_id="SV-261401r996622"

    local pam_pkcs11_conf_file="/etc/pam_pkcs11/pam_pkcs11.conf"
    local cert_policy_option="ca,signature,ocsp_on"

    sed -i 's|cert_policy = .*|cert_policy = '"$cert_policy_option"'|' "$pam_pkcs11_conf_file"

    if grep -q "cert_policy =.*ca,signature,ocsp_on" "$pam_pkcs11_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured certificate validation for PKI-based authentication successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure certificate validation for PKI-based authentication. This is a finding."
    fi
}

# Function to copy PAM configuration files to their static locations and remove soft links
copy_pam_config_files() {
    local function_name="copy_pam_config_files"
    local vuln_id="V-261402"
    local rule_id="SV-261402r996624"

    sh -c 'for X in /etc/pam.d/common-*-pc; do cp -ivp --remove-destination $X ${X:0:-3}; done'

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Copied PAM configuration files to their static locations and removed soft links successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to copy PAM configuration files and remove soft links. This is a finding."
    fi
}

install_aide() {
    local function_name="install_aide"
    local vuln_id="V-261403"
    local rule_id="SV-261403r996627"

    zypper in -y aide
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Installed AIDE successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to install AIDE. This is a finding."
        return
    fi

    aide -i
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Initialized AIDE database successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to initialize AIDE database. This is a finding."
        return
    fi

    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Renamed AIDE database successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to rename AIDE database. This is a finding."
        return
    fi

    aide --check
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Performed AIDE manual check successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to perform AIDE manual check. This is a finding."
    fi
}

configure_aide_acls() {
    local function_name="configure_aide_acls"
    local vuln_id="V-261404"
    local rule_id="SV-261404r996629"

    local aide_conf_file="/etc/aide.conf"

    if grep -q "acl" "$aide_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "ACL rule is already present in AIDE configuration."
    else
        sed -i '/ALLXTRAS$/s/$/+acl/' "$aide_conf_file"
        if grep -q "acl" "$aide_conf_file"; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Added ACL rule to AIDE configuration successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to add ACL rule to AIDE configuration. This is a finding."
        fi
    fi
}

configure_aide_xattrs() {
    local function_name="configure_aide_xattrs"
    local vuln_id="V-261405"
    local rule_id="SV-261405r996631"

    local aide_conf_file="/etc/aide.conf"

    if grep -q "xattrs" "$aide_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "xattrs rule is already present in AIDE configuration."
    else
        sed -i '/ALLXTRAS$/s/$/+xattrs/' "$aide_conf_file"
        if grep -q "xattrs" "$aide_conf_file"; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Added xattrs rule to AIDE configuration successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to add xattrs rule to AIDE configuration. This is a finding."
        fi
    fi
}

configure_aide_audit_tools() {
    local function_name="configure_aide_audit_tools"
    local vuln_id="V-261406"
    local rule_id="SV-261406r996634"

    local aide_conf_file="/etc/aide.conf"
    local audit_tools=(
        "/usr/sbin/auditctl"
        "/usr/sbin/auditd"
        "/usr/sbin/ausearch"
        "/usr/sbin/aureport"
        "/usr/sbin/autrace"
        "/usr/sbin/audispd"
        "/usr/sbin/augenrules"
    )
    local rule="p+i+n+u+g+s+b+acl+selinux+xattrs+sha512"

    for tool in "${audit_tools[@]}"; do
        if grep -q "^$tool" "$aide_conf_file"; then
            sed -i 's|^'"$tool"'.*|'"$tool $rule"'|' "$aide_conf_file"
        else
            echo "$tool $rule" | tee -a "$aide_conf_file"
        fi
    done

    if grep -q "^/usr/sbin/auditctl $rule" "$aide_conf_file" && \
       grep -q "^/usr/sbin/auditd $rule" "$aide_conf_file" && \
       grep -q "^/usr/sbin/ausearch $rule" "$aide_conf_file" && \
       grep -q "^/usr/sbin/aureport $rule" "$aide_conf_file" && \
       grep -q "^/usr/sbin/autrace $rule" "$aide_conf_file" && \
       grep -q "^/usr/sbin/audispd $rule" "$aide_conf_file" && \
       grep -q "^/usr/sbin/augenrules $rule" "$aide_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured AIDE to protect the integrity of audit tools successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure AIDE to protect the integrity of audit tools. This is a finding."
    fi
}

configure_weekly_aide_check() {
    local function_name="configure_weekly_aide_check"
    local vuln_id="V-261407"
    local rule_id="SV-261407r996637"

    local cron_file="/etc/cron.weekly/aide"
    local cron_entry="0 0 * * * /usr/sbin/aide --check | /bin/mail -s \"\$HOSTNAME - Weekly AIDE integrity check run\" root@example_server_name.mil"

    echo "$cron_entry" | tee "$cron_file" > /dev/null

    if grep -q "$cron_entry" "$cron_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured weekly AIDE check successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure weekly AIDE check. This is a finding."
    fi
}

configure_daily_aide_check() {
    local function_name="configure_daily_aide_check"
    local vuln_id="V-261408"
    local rule_id="SV-261408r996640"

    local cron_file="/etc/cron.daily/aide"
    local cron_entry="0 0 * * * /usr/sbin/aide --check | /bin/mail -s \"\$HOSTNAME - Daily AIDE integrity check run\" root@example_server_name.mil"

    echo "$cron_entry" | tee "$cron_file" > /dev/null

    if grep -q "$cron_entry" "$cron_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured daily AIDE check successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure daily AIDE check. This is a finding."
    fi
}

configure_syslog_ng() {
    local function_name="configure_syslog_ng"
    local vuln_id="V-261409"
    local rule_id="SV-261409r996643"

    local syslog_ng_conf="/etc/syslog-ng/syslog-ng.conf"
    local syslog_entry="destination logserver { syslog(\"10.10.10.10\" transport(\"udp\") port(514)); }; log { source(src); destination(logserver); };"

    if ! grep -q "destination logserver" "$syslog_ng_conf"; then
        echo "$syslog_entry" | tee -a "$syslog_ng_conf" > /dev/null
    fi

    if grep -q "destination logserver" "$syslog_ng_conf"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured syslog-ng to offload messages successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure syslog-ng. This is a finding."
    fi
}

install_audit_package() {
    local function_name="install_audit_package"
    local vuln_id="V-261410"
    local rule_id="SV-261410r996645"

    zypper in -y audit
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Installed audit package successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to install audit package. This is a finding."
    fi
}

enable_auditd_service() {
    local function_name="enable_auditd_service"
    local vuln_id="V-261411"
    local rule_id="SV-261411r996646"

    systemctl enable auditd.service
    systemctl start auditd.service

    if systemctl is-active --quiet auditd.service; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Enabled and started auditd service successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to enable and start auditd service. This is a finding."
    fi
}

install_audit_audispd_plugins() {
    local function_name="install_audit_audispd_plugins"
    local vuln_id="V-261412"
    local rule_id="SV-261412r996649"

    zypper in -y audit-audispd-plugins
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Installed audit-audispd-plugins package successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to install audit-audispd-plugins package. This is a finding."
        return
    fi

    local au_remote_conf="/etc/audisp/plugins.d/au-remote.conf"
    local active_setting="active = yes"

    if grep -q "^active" "$au_remote_conf"; then
        sed -i 's/^active.*/'"$active_setting"'/' "$au_remote_conf"
    else
        echo "$active_setting" | tee -a "$au_remote_conf" > /dev/null
    fi

    if grep -q "^active = yes" "$au_remote_conf"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured au-remote.conf successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure au-remote.conf. This is a finding."
    fi
}

# Function to Configure Audit Storage Capacity Notification
configure_audit_storage_notification() {
    local function_name="configure_audit_storage_notification"
    local vuln_id="V-261414"
    local rule_id="SV-261414r996654"

    local auditd_conf_file="/etc/audit/auditd.conf"
    local space_left_setting="space_left = 25%"

    if grep -q "^space_left" "$auditd_conf_file"; then
        sed -i 's/^space_left.*/'"$space_left_setting"'/' "$auditd_conf_file"
    else
        echo "$space_left_setting" >> "$auditd_conf_file"
    fi

    if grep -q "^space_left = 25%" "$auditd_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit storage notification successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit storage notification. This is a finding."
    fi
}

# Function to Configure Audit Failure Action
configure_audit_failure_action() {
    local function_name="configure_audit_failure_action"
    local vuln_id="V-261415"
    local rule_id="SV-261415r996657"

    local auditd_conf_file="/etc/audit/auditd.conf"
    local failure_action="disk_full_action = HALT"

    if grep -q "^disk_full_action" "$auditd_conf_file"; then
        sed -i 's/^disk_full_action.*/'"$failure_action"'/' "$auditd_conf_file"
    else
        echo "$failure_action" >> "$auditd_conf_file"
    fi

    if grep -q "^disk_full_action = HALT" "$auditd_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit failure action successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit failure action. This is a finding."
    fi
}

# Function to Configure Network Failure Action for Audit Offloading
configure_network_failure_action() {
    local function_name="configure_network_failure_action"
    local vuln_id="V-261416"
    local rule_id="SV-261416r996660"

    local audisp_remote_conf_file="/etc/audisp/audisp-remote.conf"
    local network_failure_action="network_failure_action = syslog"

    if grep -q "^network_failure_action" "$audisp_remote_conf_file"; then
        sed -i 's/^network_failure_action.*/'"$network_failure_action"'/' "$audisp_remote_conf_file"
    else
        echo "$network_failure_action" >> "$audisp_remote_conf_file"
    fi

    if grep -q "^network_failure_action = syslog" "$audisp_remote_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured network failure action for audit offloading successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure network failure action for audit offloading. This is a finding."
    fi
}

# Function to Configure Disk Full Action for Audit Storage
configure_disk_full_action() {
    local function_name="configure_disk_full_action"
    local vuln_id="V-261417"
    local rule_id="SV-261417r996662"

    local audisp_remote_conf_file="/etc/audisp/audisp-remote.conf"
    local disk_full_action="disk_full_action = syslog"

    if grep -q "^disk_full_action" "$audisp_remote_conf_file"; then
        sed -i 's/^disk_full_action.*/'"$disk_full_action"'/' "$audisp_remote_conf_file"
    else
        echo "$disk_full_action" >> "$audisp_remote_conf_file"
    fi

    if grep -q "^disk_full_action = syslog" "$audisp_remote_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured disk full action for audit storage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure disk full action for audit storage. This is a finding."
    fi
}

# Function to Protect Audit Rules from Unauthorized Modification
protect_audit_rules() {
    local function_name="protect_audit_rules"
    local vuln_id="V-261418"
    local rule_id="SV-261418r996665"

    local permissions_local_file="/etc/permissions.local"
    local entries=(
        "/var/log/audit root:root 600"
        "/var/log/audit/audit.log root:root 600"
        "/etc/audit/audit.rules root:root 640"
        "/etc/audit/rules.d/audit.rules root:root 640"
    )

    for entry in "${entries[@]}"; do
        if ! grep -q "^$entry$" "$permissions_local_file"; then
            echo "$entry" >> "$permissions_local_file"
        fi
    done

    chkstat --set "$permissions_local_file"
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Protected audit rules from unauthorized modification successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to protect audit rules from unauthorized modification. This is a finding."
    fi
}

# This function configures the permissions for audit tools to ensure they have the proper permissions set in the permissions profile.
configure_audit_tools_permissions() {
    local function_name="configure_audit_tools_permissions"
    local vuln_id="V-261419"
    local rule_id="SV-261419r996668"

    local permissions_local_file="/etc/permissions.local"
    local entries=(
        "/usr/sbin/audispd root:root 750"
        "/usr/sbin/auditctl root:root 750"
        "/usr/sbin/auditd root:root 750"
        "/usr/sbin/ausearch root:root 755"
        "/usr/sbin/aureport root:root 755"
        "/usr/sbin/autrace root:root 750"
        "/usr/sbin/augenrules root:root 750"
    )

    for entry in "${entries[@]}"; do
        if ! grep -q "^$entry$" "$permissions_local_file"; then
            echo "$entry" >> "$permissions_local_file"
        fi
    done

    chkstat --set "$permissions_local_file"
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit tools permissions successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit tools permissions. This is a finding."
    fi
}

# This function configures SLEM 5 to offload audit records to a different system or media.
configure_audit_offload() {
    local function_name="configure_audit_offload"
    local vuln_id="V-261422"
    local rule_id="SV-261422r996674"

    local audisp_remote_conf_file="/etc/audisp/audisp-remote.conf"
    local remote_server="remote_server = <ip_address>"  # Replace <ip_address> with the actual IP address

    if grep -q "^remote_server" "$audisp_remote_conf_file"; then
        sed -i 's/^remote_server.*/'"$remote_server"'/' "$audisp_remote_conf_file"
    else
        echo "$remote_server" >> "$audisp_remote_conf_file"
    fi

    if grep -q "^remote_server = <ip_address>" "$audisp_remote_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit offloading successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit offloading. This is a finding."
    fi
}

# This function configures the auditd service to notify administrators in the event of an audit processing failure.
configure_auditd_notification() {
    local function_name="configure_auditd_notification"
    local vuln_id="V-261423"
    local rule_id="SV-261423r996677"

    # Configure postmaster alias
    if ! grep -q "^postmaster: root" /etc/aliases; then
        echo "postmaster: root" >> /etc/aliases
    fi

    # Configure root alias to forward to a monitored email address
    if ! grep -q "^root: box@server.mil" /etc/aliases; then
        echo "root: box@server.mil" >> /etc/aliases
    fi

    # Apply changes to /etc/aliases
    newaliases

    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured auditd notification successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure auditd notification. This is a finding."
    fi
}

# This function configures the auditd service to notify the administrators in the event of a SLEM 5 audit processing failure.
configure_auditd_action_mail_acct() {
    local function_name="configure_auditd_action_mail_acct"
    local vuln_id="V-261424"
    local rule_id="SV-261424r996679"

    local auditd_conf_file="/etc/audit/auditd.conf"
    local action_mail_acct="action_mail_acct = root"

    if grep -q "^action_mail_acct" "$auditd_conf_file"; then
        sed -i 's/^action_mail_acct.*/'"$action_mail_acct"'/' "$auditd_conf_file"
    else
        echo "$action_mail_acct" >> "$auditd_conf_file"
    fi

    if grep -q "^action_mail_acct = root" "$auditd_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured auditd action_mail_acct successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure auditd action_mail_acct. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "chacl" command.
configure_audit_chacl() {
    local function_name="configure_audit_chacl"
    local vuln_id="V-261425"
    local rule_id="SV-261425r996682"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local chacl_rule="-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k prim_mod"

    if ! grep -q "^$chacl_rule$" "$audit_rules_file"; then
        echo "$chacl_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for chacl command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for chacl command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "chage" command.
configure_audit_chage() {
    local function_name="configure_audit_chage"
    local vuln_id="V-261426"
    local rule_id="SV-261426r996685"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local chage_rule="-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage"

    if ! grep -q "^$chage_rule$" "$audit_rules_file"; then
        echo "$chage_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for chage command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for chage command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "chcon" command.
configure_audit_chcon() {
    local function_name="configure_audit_chcon"
    local vuln_id="V-261427"
    local rule_id="SV-261427r996688"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local chcon_rule="-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k prim_mod"

    if ! grep -q "^$chcon_rule$" "$audit_rules_file"; then
        echo "$chcon_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for chcon command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for chcon command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "chfn" command.
configure_audit_chfn() {
    local function_name="configure_audit_chfn"
    local vuln_id="V-261428"
    local rule_id="SV-261428r996691"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local chfn_rule="-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chfn"

    if ! grep -q "^$chfn_rule$" "$audit_rules_file"; then
        echo "$chfn_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for chfn command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for chfn command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "chmod" command.
configure_audit_chmod() {
    local function_name="configure_audit_chmod"
    local vuln_id="V-261429"
    local rule_id="SV-261429r996694"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local chmod_rule="-a always,exit -F path=/usr/bin/chmod -F perm=x -F auid>=1000 -F auid!=unset -k prim_mod"

    if ! grep -q "^$chmod_rule$" "$audit_rules_file"; then
        echo "$chmod_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for chmod command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for chmod command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "chsh" command.
configure_audit_chsh() {
    local function_name="configure_audit_chsh"
    local vuln_id="V-261430"
    local rule_id="SV-261430r996697"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local chsh_rule="-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chsh"

    if ! grep -q "^$chsh_rule$" "$audit_rules_file"; then
        echo "$chsh_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for chsh command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for chsh command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "crontab" command.
configure_audit_crontab() {
    local function_name="configure_audit_crontab"
    local vuln_id="V-261431"
    local rule_id="SV-261431r996700"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local crontab_rule="-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-crontab"

    if ! grep -q "^$crontab_rule$" "$audit_rules_file"; then
        echo "$crontab_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for crontab command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for crontab command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "gpasswd" command.
configure_audit_gpasswd() {
    local function_name="configure_audit_gpasswd"
    local vuln_id="V-261432"
    local rule_id="SV-261432r996703"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local gpasswd_rule="-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-gpasswd"

    if ! grep -q "^$gpasswd_rule$" "$audit_rules_file"; then
        echo "$gpasswd_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for gpasswd command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for gpasswd command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "insmod" command.
configure_audit_insmod() {
    local function_name="configure_audit_insmod"
    local vuln_id="V-261433"
    local rule_id="SV-261433r996706"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local insmod_rule="-w /sbin/insmod -p x -k modules"

    if ! grep -q "^$insmod_rule$" "$audit_rules_file"; then
        echo "$insmod_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for insmod command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for insmod command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "kmod" command.
configure_audit_kmod() {
    local function_name="configure_audit_kmod"
    local vuln_id="V-261434"
    local rule_id="SV-261434r996709"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local kmod_rule="-w /usr/bin/kmod -p x -k modules"

    if ! grep -q "^$kmod_rule$" "$audit_rules_file"; then
        echo "$kmod_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for kmod command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for kmod command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "modprobe" command.
configure_audit_modprobe() {
    local function_name="configure_audit_modprobe"
    local vuln_id="V-261435"
    local rule_id="SV-261435r996712"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local modprobe_rule="-w /sbin/modprobe -p x -k modules"

    if ! grep -q "^$modprobe_rule$" "$audit_rules_file"; then
        echo "$modprobe_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for modprobe command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for modprobe command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "newgrp" command.
configure_audit_newgrp() {
    local function_name="configure_audit_newgrp"
    local vuln_id="V-261436"
    local rule_id="SV-261436r996715"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local newgrp_rule="-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k privileged-newgrp"

    if ! grep -q "^$newgrp_rule$" "$audit_rules_file"; then
        echo "$newgrp_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for newgrp command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for newgrp command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "pam_timestamp_check" command.
configure_audit_pam_timestamp_check() {
    local function_name="configure_audit_pam_timestamp_check"
    local vuln_id="V-261437"
    local rule_id="SV-261437r996718"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local pam_timestamp_check_rule="-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam_timestamp_check"

    if ! grep -q "^$pam_timestamp_check_rule$" "$audit_rules_file"; then
        echo "$pam_timestamp_check_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for pam_timestamp_check command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for pam_timestamp_check command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "passwd" command.
configure_audit_passwd() {
    local function_name="configure_audit_passwd"
    local vuln_id="V-261438"
    local rule_id="SV-261438r996721"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local passwd_rule="-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd"

    if ! grep -q "^$passwd_rule$" "$audit_rules_file"; then
        echo "$passwd_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for passwd command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for passwd command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "rm" command.
configure_audit_rm() {
    local function_name="configure_audit_rm"
    local vuln_id="V-261439"
    local rule_id="SV-261439r996724"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local rm_rule="-a always,exit -F path=/usr/bin/rm -F perm=x -F auid>=1000 -F auid!=unset -k prim_mod"

    if ! grep -q "^$rm_rule$" "$audit_rules_file"; then
        echo "$rm_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for rm command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for rm command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to audit the execution of the module management program "rmmod".
configure_audit_rmmod() {
    local function_name="configure_audit_rmmod"
    local vuln_id="V-261440"
    local rule_id="SV-261440r996727"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local rmmod_rule="-w /sbin/rmmod -p x -k modules"

    if ! grep -q "^$rmmod_rule$" "$audit_rules_file"; then
        echo "$rmmod_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for rmmod command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for rmmod command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "setfacl" command.
configure_audit_setfacl() {
    local function_name="configure_audit_setfacl"
    local vuln_id="V-261441"
    local rule_id="SV-261441r996730"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local setfacl_rule="-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k prim_mod"

    if ! grep -q "^$setfacl_rule$" "$audit_rules_file"; then
        echo "$setfacl_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for setfacl command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for setfacl command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "ssh-agent" command.
configure_audit_ssh_agent() {
    local function_name="configure_audit_ssh_agent"
    local vuln_id="V-261442"
    local rule_id="SV-261442r996733"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local ssh_agent_rule="-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh-agent"

    if ! grep -q "^$ssh_agent_rule$" "$audit_rules_file"; then
        echo "$ssh_agent_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for ssh-agent command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for ssh-agent command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "ssh-keysign" command.
configure_audit_ssh_keysign() {
    local function_name="configure_audit_ssh_keysign"
    local vuln_id="V-261443"
    local rule_id="SV-261443r996736"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local ssh_keysign_rule="-a always,exit -F path=/usr/lib/ssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh-keysign"

    if ! grep -q "^$ssh_keysign_rule$" "$audit_rules_file"; then
        echo "$ssh_keysign_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for ssh-keysign command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for ssh-keysign command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "su" command.
configure_audit_su() {
    local function_name="configure_audit_su"
    local vuln_id="V-261444"
    local rule_id="SV-261444r996739"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local su_rule="-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change"

    if ! grep -q "^$su_rule$" "$audit_rules_file"; then
        echo "$su_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for su command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for su command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "sudo" command.
configure_audit_sudo() {
    local function_name="configure_audit_sudo"
    local vuln_id="V-261445"
    local rule_id="SV-261445r996742"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local sudo_rule="-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged-sudo"

    if ! grep -q "^$sudo_rule$" "$audit_rules_file"; then
        echo "$sudo_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for sudo command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for sudo command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "sudoedit" command.
configure_audit_sudoedit() {
    local function_name="configure_audit_sudoedit"
    local vuln_id="V-261446"
    local rule_id="SV-261446r996745"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local sudoedit_rule="-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=unset -k privileged-sudoedit"

    if ! grep -q "^$sudoedit_rule$" "$audit_rules_file"; then
        echo "$sudoedit_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for sudoedit command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for sudoedit command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "unix_chkpwd" and "unix2_chkpwd" commands.
configure_audit_unix_chkpwd() {
    local function_name="configure_audit_unix_chkpwd"
    local vuln_id="V-261447"
    local rule_id="SV-261447r996748"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local unix_chkpwd_rule="-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-chkpwd"
    local unix2_chkpwd_rule="-a always,exit -F path=/sbin/unix2_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix2-chkpwd"

    if ! grep -q "^$unix_chkpwd_rule$" "$audit_rules_file"; then
        echo "$unix_chkpwd_rule" >> "$audit_rules_file"
    fi

    if ! grep -q "^$unix2_chkpwd_rule$" "$audit_rules_file"; then
        echo "$unix2_chkpwd_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for unix_chkpwd and unix2_chkpwd command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for unix_chkpwd and unix2_chkpwd command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "usermod" command.
configure_audit_usermod() {
    local function_name="configure_audit_usermod"
    local vuln_id="V-261448"
    local rule_id="SV-261448r996751"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local usermod_rule="-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod"

    if ! grep -q "^$usermod_rule$" "$audit_rules_file"; then
        echo "$usermod_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for usermod command usage successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for usermod command usage. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record when all modifications to the "/etc/group" file occur.
configure_audit_group_file() {
    local function_name="configure_audit_group_file"
    local vuln_id="V-261449"
    local rule_id="SV-261449r996754"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local group_rule="-w /etc/group -p wa -k account_mod"

    if ! grep -q "^$group_rule$" "$audit_rules_file"; then
        echo "$group_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for modifications to /etc/group file successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for modifications to /etc/group file. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record when all modifications to the "/etc/security/opasswd" file occur.
configure_audit_opasswd_file() {
    local function_name="configure_audit_opasswd_file"
    local vuln_id="V-261450"
    local rule_id="SV-261450r996757"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local opasswd_rule="-w /etc/security/opasswd -p wa -k account_mod"

    if ! grep -q "^$opasswd_rule$" "$audit_rules_file"; then
        echo "$opasswd_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for modifications to /etc/security/opasswd file successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for modifications to /etc/security/opasswd file. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record when all modifications to the "/etc/passwd" file occur.
configure_audit_passwd_file() {
    local function_name="configure_audit_passwd_file"
    local vuln_id="V-261451"
    local rule_id="SV-261451r996760"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local passwd_rule="-w /etc/passwd -p wa -k account_mod"

    if ! grep -q "^$passwd_rule$" "$audit_rules_file"; then
        echo "$passwd_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for modifications to /etc/passwd file successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for modifications to /etc/passwd file. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record when all modifications to the "/etc/shadow" file occur.
configure_audit_shadow_file() {
    local function_name="configure_audit_shadow_file"
    local vuln_id="V-261452"
    local rule_id="SV-261452r996763"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local shadow_rule="-w /etc/shadow -p wa -k account_mod"

    if ! grep -q "^$shadow_rule$" "$audit_rules_file"; then
        echo "$shadow_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for modifications to /etc/shadow file successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for modifications to /etc/shadow file. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "chmod", "fchmod", and "fchmodat" system calls.
configure_audit_chmod_syscalls() {
    local function_name="configure_audit_chmod_syscalls"
    local vuln_id="V-261453"
    local rule_id="SV-261453r996848"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local chmod_rule_32="-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod"
    local chmod_rule_64="-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod"

    if ! grep -q "^$chmod_rule_32$" "$audit_rules_file"; then
        echo "$chmod_rule_32" >> "$audit_rules_file"
    fi

    if ! grep -q "^$chmod_rule_64$" "$audit_rules_file"; then
        echo "$chmod_rule_64" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for chmod, fchmod, and fchmodat system calls successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for chmod, fchmod, and fchmodat system calls. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "chown", "fchown", "fchownat", and "lchown" system calls.
configure_audit_chown_syscalls() {
    local function_name="configure_audit_chown_syscalls"
    local vuln_id="V-261454"
    local rule_id="SV-261454r996769"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local chown_rule_32="-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod"
    local chown_rule_64="-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod"

    if ! grep -q "^$chown_rule_32$" "$audit_rules_file"; then
        echo "$chown_rule_32" >> "$audit_rules_file"
    fi

    if ! grep -q "^$chown_rule_64$" "$audit_rules_file"; then
        echo "$chown_rule_64" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for chown, fchown, fchownat, and lchown system calls successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for chown, fchown, fchownat, and lchown system calls. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" system calls.
configure_audit_creat_open_syscalls() {
    local function_name="configure_audit_creat_open_syscalls"
    local vuln_id="V-261455"
    local rule_id="SV-261455r996772"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local creat_open_rule_32_1="-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access"
    local creat_open_rule_64_1="-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access"
    local creat_open_rule_32_2="-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"
    local creat_open_rule_64_2="-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access"

    if ! grep -q "^$creat_open_rule_32_1$" "$audit_rules_file"; then
        echo "$creat_open_rule_32_1" >> "$audit_rules_file"
    fi

    if ! grep -q "^$creat_open_rule_64_1$" "$audit_rules_file"; then
        echo "$creat_open_rule_64_1" >> "$audit_rules_file"
    fi

    if ! grep -q "^$creat_open_rule_32_2$" "$audit_rules_file"; then
        echo "$creat_open_rule_32_2" >> "$audit_rules_file"
    fi

    if ! grep -q "^$creat_open_rule_64_2$" "$audit_rules_file"; then
        echo "$creat_open_rule_64_2" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "delete_module" system call.
configure_audit_delete_module_syscall() {
    local function_name="configure_audit_delete_module_syscall"
    local vuln_id="V-261456"
    local rule_id="SV-261456r996775"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local delete_module_rule_32="-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k unload_module"
    local delete_module_rule_64="-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k unload_module"

    if ! grep -q "^$delete_module_rule_32$" "$audit_rules_file"; then
        echo "$delete_module_rule_32" >> "$audit_rules_file"
    fi

    if ! grep -q "^$delete_module_rule_64$" "$audit_rules_file"; then
        echo "$delete_module_rule_64" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for delete_module system call successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for delete_module system call. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "init_module" and "finit_module" system calls.
configure_audit_init_module_syscalls() {
    local function_name="configure_audit_init_module_syscalls"
    local vuln_id="V-261457"
    local rule_id="SV-261457r996778"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local init_module_rule_32="-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k moduleload"
    local init_module_rule_64="-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k moduleload"

    if ! grep -q "^$init_module_rule_32$" "$audit_rules_file"; then
        echo "$init_module_rule_32" >> "$audit_rules_file"
    fi

    if ! grep -q "^$init_module_rule_64$" "$audit_rules_file"; then
        echo "$init_module_rule_64" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for init_module and finit_module system calls successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for init_module and finit_module system calls. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "mount" system call.
configure_audit_mount_syscall() {
    local function_name="configure_audit_mount_syscall"
    local vuln_id="V-261458"
    local rule_id="SV-261458r996781"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local mount_rule_32="-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount"
    local mount_rule_64="-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount"

    if ! grep -q "^$mount_rule_32$" "$audit_rules_file"; then
        echo "$mount_rule_32" >> "$audit_rules_file"
    fi

    if ! grep -q "^$mount_rule_64$" "$audit_rules_file"; then
        echo "$mount_rule_64" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for mount system call successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for mount system call. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" system calls.
configure_audit_xattr_syscalls() {
    local function_name="configure_audit_xattr_syscalls"
    local vuln_id="V-261459"
    local rule_id="SV-261459r996784"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local xattr_rule_32="-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod"
    local xattr_rule_64="-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod"

    if ! grep -q "^$xattr_rule_32$" "$audit_rules_file"; then
        echo "$xattr_rule_32" >> "$audit_rules_file"
    fi

    if ! grep -q "^$xattr_rule_64$" "$audit_rules_file"; then
        echo "$xattr_rule_64" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "umount" and "umount2" system calls.
configure_audit_umount_syscalls() {
    local function_name="configure_audit_umount_syscalls"
    local vuln_id="V-261460"
    local rule_id="SV-261460r996787"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local umount_rule_32="-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=unset -k privileged-umount"
    local umount_rule_32_2="-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=unset -k privileged-umount"
    local umount_rule_64="-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=unset -k privileged-umount"

    if ! grep -q "^$umount_rule_32$" "$audit_rules_file"; then
        echo "$umount_rule_32" >> "$audit_rules_file"
    fi

    if ! grep -q "^$umount_rule_32_2$" "$audit_rules_file"; then
        echo "$umount_rule_32_2" >> "$audit_rules_file"
    fi

    if ! grep -q "^$umount_rule_64$" "$audit_rules_file"; then
        echo "$umount_rule_64" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for umount and umount2 system calls successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for umount and umount2 system calls. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for all uses of the "unlink", "unlinkat", "rename", "renameat", and "rmdir" system calls.
configure_audit_unlink_rename_syscalls() {
    local function_name="configure_audit_unlink_rename_syscalls"
    local vuln_id="V-261461"
    local rule_id="SV-261461r996790"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local unlink_rename_rule_32="-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k perm_mod"
    local unlink_rename_rule_64="-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k perm_mod"

    if ! grep -q "^$unlink_rename_rule_32$" "$audit_rules_file"; then
        echo "$unlink_rename_rule_32" >> "$audit_rules_file"
    fi

    if ! grep -q "^$unlink_rename_rule_64$" "$audit_rules_file"; then
        echo "$unlink_rename_rule_64" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for unlink, unlinkat, rename, renameat, and rmdir system calls successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for unlink, unlinkat, rename, renameat, and rmdir system calls. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for any privileged use of the "execve" system call.
configure_audit_execve_syscall() {
    local function_name="configure_audit_execve_syscall"
    local vuln_id="V-261462"
    local rule_id="SV-261462r996793"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local execve_rule_32_1="-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid"
    local execve_rule_64_1="-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid"
    local execve_rule_32_2="-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid"
    local execve_rule_64_2="-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid"

    if ! grep -q "^$execve_rule_32_1$" "$audit_rules_file"; then
        echo "$execve_rule_32_1" >> "$audit_rules_file"
    fi

    if ! grep -q "^$execve_rule_64_1$" "$audit_rules_file"; then
        echo "$execve_rule_64_1" >> "$audit_rules_file"
    fi

    if ! grep -q "^$execve_rule_32_2$" "$audit_rules_file"; then
        echo "$execve_rule_32_2" >> "$audit_rules_file"
    fi

    if ! grep -q "^$execve_rule_64_2$" "$audit_rules_file"; then
        echo "$execve_rule_64_2" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for privileged use of execve system call successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for privileged use of execve system call. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for any modifications to the "/var/log/lastlog" file.
configure_audit_lastlog_file() {
    local function_name="configure_audit_lastlog_file"
    local vuln_id="V-261463"
    local rule_id="SV-261463r996796"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local lastlog_rule="-w /var/log/lastlog -p wa -k logins"

    if ! grep -q "^$lastlog_rule$" "$audit_rules_file"; then
        echo "$lastlog_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for modifications to /var/log/lastlog file successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for modifications to /var/log/lastlog file. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for any modifications to the "/var/log/tallylog" file.
configure_audit_tallylog_file() {
    local function_name="configure_audit_tallylog_file"
    local vuln_id="V-261464"
    local rule_id="SV-261464r996799"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local tallylog_rule="-w /var/log/tallylog -p wa -k logins"

    if ! grep -q "^$tallylog_rule$" "$audit_rules_file"; then
        echo "$tallylog_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for modifications to /var/log/tallylog file successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for modifications to /var/log/tallylog file. This is a finding."
    fi
}

# This function configures SLEM 5 to generate audit records when successful/unsuccessful attempts to access the "/etc/sudoers" file and files in the "/etc/sudoers.d/" directory.
configure_audit_sudoers_files() {
    local function_name="configure_audit_sudoers_files"
    local vuln_id="V-261465"
    local rule_id="SV-261465r996802"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local sudoers_rule="-w /etc/sudoers -p wa -k privileged-actions"
    local sudoers_d_rule="-w /etc/sudoers.d -p wa -k privileged-actions"

    if ! grep -q "^$sudoers_rule$" "$audit_rules_file"; then
        echo "$sudoers_rule" >> "$audit_rules_file"
    fi

    if ! grep -q "^$sudoers_d_rule$" "$audit_rules_file"; then
        echo "$sudoers_d_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit records for access to /etc/sudoers and /etc/sudoers.d/ files successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit records for access to /etc/sudoers and /etc/sudoers.d/ files. This is a finding."
    fi
}

# This function configures the audit system to generate an audit event for any successful/unsuccessful uses of the "setfiles" command.
configure_audit_setfiles_command() {
    local function_name="configure_audit_setfiles_command"
    local vuln_id="V-261466"
    local rule_id="SV-261466r996805"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local setfiles_rule="-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"

    if ! grep -q "^$setfiles_rule$" "$audit_rules_file"; then
        echo "$setfiles_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit event for uses of the setfiles command successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit event for uses of the setfiles command. This is a finding."
    fi
}

# This function configures the audit system to generate an audit event for any successful/unsuccessful uses of the "semanage" command.
configure_audit_semanage_command() {
    local function_name="configure_audit_semanage_command"
    local vuln_id="V-261467"
    local rule_id="SV-261467r996808"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local semanage_rule="-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"

    if ! grep -q "^$semanage_rule$" "$audit_rules_file"; then
        echo "$semanage_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit event for uses of the semanage command successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit event for uses of the semanage command. This is a finding."
    fi
}

# This function configures the audit system to generate an audit event for any successful/unsuccessful uses of the "setsebool" command.
configure_audit_setsebool_command() {
    local function_name="configure_audit_setsebool_command"
    local vuln_id="V-261468"
    local rule_id="SV-261468r996811"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local setsebool_rule="-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"

    if ! grep -q "^$setsebool_rule$" "$audit_rules_file"; then
        echo "$setsebool_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit event for uses of the setsebool command successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit event for uses of the setsebool command. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for the "/run/utmp" file.
configure_audit_utmp_file() {
    local function_name="configure_audit_utmp_file"
    local vuln_id="V-261469"
    local rule_id="SV-261469r996814"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local utmp_rule="-w /run/utmp -p wa -k login_mod"

    if ! grep -q "^$utmp_rule$" "$audit_rules_file"; then
        echo "$utmp_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for /run/utmp file successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for /run/utmp file. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for the "/var/log/btmp" file.
configure_audit_btmp_file() {
    local function_name="configure_audit_btmp_file"
    local vuln_id="V-261470"
    local rule_id="SV-261470r996817"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local btmp_rule="-w /var/log/btmp -p wa -k login_mod"

    if ! grep -q "^$btmp_rule$" "$audit_rules_file"; then
        echo "$btmp_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for /var/log/btmp file successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for /var/log/btmp file. This is a finding."
    fi
}

# This function configures SLEM 5 to generate an audit record for the "/var/log/wtmp" file.
configure_audit_wtmp_file() {
    local function_name="configure_audit_wtmp_file"
    local vuln_id="V-261471"
    local rule_id="SV-261471r996820"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local wtmp_rule="-w /var/log/wtmp -p wa -k login_mod"

    if ! grep -q "^$wtmp_rule$" "$audit_rules_file"; then
        echo "$wtmp_rule" >> "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Configured audit record for /var/log/wtmp file successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure audit record for /var/log/wtmp file. This is a finding."
    fi
}

# This function removes the "-a task,never" rule from the /etc/audit/rules.d/audit.rules file.
remove_task_never_rule() {
    local function_name="remove_task_never_rule"
    local vuln_id="V-261472"
    local rule_id="SV-261472r996822"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local task_never_rule="-a task,never"

    if grep -q "^$task_never_rule$" "$audit_rules_file"; then
        sed -i "/^$task_never_rule$/d" "$audit_rules_file"
    fi

    augenrules --load
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Removed '-a task,never' rule from audit rules file successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to remove '-a task,never' rule from audit rules file. This is a finding."
    fi
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
prevent_usb_automount
assign_home_directories_new_users
define_default_permissions
enforce_logon_delay
assign_home_directories_existing_users
create_home_directories
edit_user_init_files
remove_world_writable_permissions
expire_temporary_accounts
configure_emergency_admin_accounts
assign_accounts_to_active_entities
disable_interactive_shell_noninteractive_accounts
disable_inactive_accounts
ensure_unique_uids
configure_pam_lastlog
configure_autologout
configure_pam_tally2
configure_logon_delay
configure_pam_tally2_directory
configure_selinux_targeted_policy
# map_user_to_selinux_role
configure_sudoers_defaults
remove_nopasswd_from_sudoers
# require_sudo_reauthentication
remove_specific_sudoers_entries
configure_sudoers_include
enforce_password_complexity_uppercase
enforce_password_complexity_lowercase
enforce_password_complexity_numeric
enforce_password_complexity_special
prevent_dictionary_passwords
enforce_min_password_length
enforce_password_change_difok
enforce_password_history
store_encrypted_passwords
# enforce_min_password_age
# enforce_max_password_age
create_password_history_file
configure_encrypt_method
configure_min_password_age
configure_max_password_age
install_mfa_packages
configure_mfa_pam
enable_cert_status_checking
configure_nss_cache_timeout
configure_pam_cache_timeout
validate_pki_certificates
copy_pam_config_files
install_aide
configure_aide_acls
configure_aide_xattrs
configure_aide_audit_tools
configure_weekly_aide_check
configure_daily_aide_check
configure_syslog_ng
install_audit_package
enable_auditd_service
install_audit_audispd_plugins
configure_audit_storage_notification
configure_audit_failure_action
configure_network_failure_action
configure_disk_full_action
protect_audit_rules
configure_audit_tools_permissions
configure_audit_offload
configure_auditd_notification
configure_auditd_action_mail_acct
configure_audit_chacl
configure_audit_chage
configure_audit_chcon
configure_audit_chfn
configure_audit_chmod
configure_audit_chsh
configure_audit_crontab
configure_audit_gpasswd
configure_audit_insmod
configure_audit_kmod
configure_audit_modprobe
configure_audit_newgrp
configure_audit_pam_timestamp_check
configure_audit_passwd
configure_audit_rm
configure_audit_rmmod
configure_audit_setfacl
configure_audit_ssh_agent
configure_audit_ssh_keysign
configure_audit_su
configure_audit_sudo
configure_audit_sudoedit
configure_audit_unix_chkpwd
configure_audit_usermod
configure_audit_group_file
configure_audit_opasswd_file
configure_audit_passwd_file
configure_audit_shadow_file
configure_audit_chmod_syscalls
configure_audit_chown_syscalls
configure_audit_creat_open_syscalls
configure_audit_delete_module_syscall
configure_audit_init_module_syscalls
configure_audit_mount_syscall
configure_audit_xattr_syscalls
configure_audit_umount_syscalls
configure_audit_unlink_rename_syscalls
configure_audit_execve_syscall
configure_audit_lastlog_file
configure_audit_tallylog_file
configure_audit_sudoers_files
configure_audit_setfiles_command
configure_audit_semanage_command
configure_audit_setsebool_command
configure_audit_utmp_file
configure_audit_btmp_file
configure_audit_wtmp_file
remove_task_never_rule
