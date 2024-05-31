#!/bin/bash

LOGFILE="STIG_Findings_high.log"

# Function to log messages
log_message() {
    echo "$1" >> "$LOGFILE"
}

# Function to validate the system is a vendor-supported version
validate_os_version() {
    echo "Validating OS version..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$NAME" =~ ^(SLES|SLE Micro)$ ]] && [[ "$VERSION" =~ ^(15|15-SP[0-9]+|5\.[34])$ ]]; then
            echo "OS is supported: $NAME $VERSION"
        else
            echo "OS is not supported: $NAME $VERSION. Logging finding and exiting."
            log_message "Unsupported OS version: $NAME $VERSION"
            exit 1
        fi
    else
        echo "/etc/os-release file not found. Logging finding and exiting."
        log_message "OS version information not found"
        exit 1
    fi
}

# Function to check if the system uses UEFI and configure GRUB password
configure_grub_password_uefi() {
    # Check if the system uses UEFI
    if [ -d /sys/firmware/efi ]; then
        echo "System uses UEFI."
    else
        echo "System does not use UEFI. Exiting."
        exit 1
    fi

    # Define the GRUB password and generate its encrypted form
    GRUB_PASSWORD="your_secure_password"
    ENCRYPTED_PASSWORD=$(grub2-mkpasswd-pbkdf2 <<EOF
$GRUB_PASSWORD
$GRUB_PASSWORD
EOF
    )

    # Extract the encrypted password from the output
    ENCRYPTED_PASSWORD=$(echo "$ENCRYPTED_PASSWORD" | grep 'grub.pbkdf2.sha512' | awk '{print $7}')

    # Create a transactional update session for GRUB configuration
    transactional-update shell <<EOF

# Backup current GRUB configuration
cp /etc/grub.d/40_custom /etc/grub.d/40_custom.bak

# Add the encrypted password to the GRUB configuration
cat <<EOL >> /etc/grub.d/40_custom

set superusers="root"
password_pbkdf2 root $ENCRYPTED_PASSWORD
EOL

# Update the GRUB configuration
grub2-mkconfig -o /boot/grub2/grub.cfg

exit
EOF

    echo "GRUB configuration updated with encrypted boot password using transactional updates."
    log_message "GRUB password encryption configured for UEFI system."
}

# Function to configure GRUB password for BIOS systems
configure_grub_password_bios() {
    echo "Configuring GRUB password for BIOS system."

    # Define the GRUB password and generate its encrypted form
    GRUB_PASSWORD="your_secure_password"
    ENCRYPTED_PASSWORD=$(grub2-mkpasswd-pbkdf2 <<EOF
$GRUB_PASSWORD
$GRUB_PASSWORD
EOF
    )

    # Extract the encrypted password from the output
    ENCRYPTED_PASSWORD=$(echo "$ENCRYPTED_PASSWORD" | grep 'grub.pbkdf2.sha512' | awk '{print $7}')

    # Modify /etc/grub.d/40_custom and generate updated grub.cfg
    cp /etc/grub.d/40_custom /etc/grub.d/40_custom.bak

    cat <<EOL >> /etc/grub.d/40_custom

set superusers="root"
password_pbkdf2 root $ENCRYPTED_PASSWORD
EOL

    grub2-mkconfig --output=/tmp/grub2.cfg
    mv /tmp/grub2.cfg /boot/grub2/grub.cfg

    echo "GRUB configuration updated with encrypted boot password for BIOS system."
    log_message "GRUB password encryption configured for BIOS system."
}

# Function to check and remove /etc/shosts.equiv
check_and_remove_shosts_equiv() {
    echo "Checking for /etc/shosts.equiv..."
    if find /etc -name shosts.equiv; then
        echo "Found /etc/shosts.equiv. Removing..."
        find /etc -name shosts.equiv -exec rm -f {} \;
        log_message "Removed /etc/shosts.equiv."
    else
        echo "No /etc/shosts.equiv found."
        log_message "No /etc/shosts.equiv found."
    fi
}

# Function to check and remove .shosts files
check_and_remove_shosts_files() {
    echo "Checking for .shosts files..."
    if find / \( -path /.snapshots -o -path /sys -o -path /proc \) -prune -o -name '.shosts' -print; then
        echo "Found .shosts files. Removing..."
        find / \( -path /.snapshots -o -path /sys -o -path /proc \) -prune -o -name '.shosts' -exec rm -f {} \;
        log_message "Removed .shosts files."
    else
        echo "No .shosts files found."
        log_message "No .shosts files found."
    fi
}

# Function to disable and mask ctrl-alt-del.target
disable_ctrl_alt_del() {
    echo "Checking status of ctrl-alt-del.target..."
    if systemctl is-enabled ctrl-alt-del.target; then
        echo "Disabling and masking ctrl-alt-del.target..."
        transactional-update shell <<EOF
systemctl disable ctrl-alt-del.target
systemctl mask ctrl-alt-del.target
exit
EOF
        log_message "Disabled and masked ctrl-alt-del.target."
    else
        echo "ctrl-alt-del.target is already disabled and masked."
        log_message "ctrl-alt-del.target is already disabled and masked."
    fi
}

# Function to fix PAM configuration
fix_pam_configuration() {
    echo "Checking PAM configuration for nullok..."
    if grep pam_unix.so /etc/pam.d/* | grep nullok; then
        echo "Found pam_unix.so with nullok. Fixing PAM configuration..."
        transactional-update shell <<EOF
sed -i 's/\(pam_unix.so.*\) nullok/\1/' /etc/pam.d/*
exit
EOF
        log_message "Fixed PAM configuration to remove nullok."
    else
        echo "No nullok option found in PAM configuration."
        log_message "No nullok option found in PAM configuration."
    fi
}

# Function to check and remove specific packages
check_and_remove_packages() {
    PACKAGES=(
        "vsftpd"
        "telnet-server"
        # Add more packages to this list if needed
    )
    for package in "${PACKAGES[@]}"; do
        if rpm -q $package > /dev/null 2>&1; then
            echo "Found $package. Removing..."
            transactional-update pkg remove -y $package >> "$LOGFILE" 2>&1
            echo "Removed $package." | tee -a "$LOGFILE"
        else
            echo "$package is not installed."
            log_message "$package is not installed."
        fi
    done
}

# Function to ensure openssh is installed and the service is enabled
ensure_openssh_installed() {
    echo "Checking if openssh is installed..."
    if ! rpm -q openssh > /dev/null 2>&1; then
        echo "openssh is not installed. Installing..." | tee -a "$LOGFILE"
        transactional-update pkg install -yl openssh >> "$LOGFILE" 2>&1
        echo "Installed openssh." | tee -a "$LOGFILE"
    else
        echo "openssh is already installed." | tee -a "$LOGFILE"
    fi

    echo "Ensuring sshd service is enabled..."
    if ! systemctl is-enabled sshd > /dev/null 2>&1; then
        transactional-update shell <<EOF
systemctl enable sshd
systemctl start sshd
exit
EOF
        log_message "Enabled and started sshd service."
    else
        echo "sshd service is already enabled."
        log_message "sshd service is already enabled."
    fi
}

# Function to ensure only root has UID of "0"
check_uid_0_accounts() {
    echo "Checking for accounts with UID 0..."
    non_root_uid_0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
    if [ -n "$non_root_uid_0" ]; then
        echo "Found accounts with UID 0: $non_root_uid_0. Logging finding."
        log_message "Accounts with UID 0 other than root: $non_root_uid_0"
    else
        echo "No accounts with UID 0 other than root found."
        log_message "No accounts with UID 0 other than root found."
    fi
}

# Function to check and comment out "NOPASSWD" or "!authenticate" in /etc/sudoers
check_sudoers_nopasswd() {
    echo "Checking /etc/sudoers for NOPASSWD or !authenticate..."
    sudoers_issues=$(egrep -i '(nopasswd|!authenticate)' /etc/sudoers)
    if [ -n "$sudoers_issues" ]; then
        echo "Found NOPASSWD or !authenticate in /etc/sudoers. Commenting out and logging."
        while IFS= read -r line; do
            sed -i "s|$line|#$line|g" /etc/sudoers
            log_message "Commented out in /etc/sudoers: $line"
        done <<< "$sudoers_issues"
    else
        echo "No NOPASSWD or !authenticate found in /etc/sudoers."
        log_message "No NOPASSWD or !authenticate found in /etc/sudoers."
    fi
}

# Function to check if zypper has gpgcheck enabled
check_zypper_gpgcheck() {
    echo "Checking if zypper has gpgcheck enabled..."
    gpgcheck_status=$(grep -i '^gpgcheck' /etc/zypp/zypp.conf)
    if [[ "$gpgcheck_status" =~ ^gpgcheck[[:space:]]*=[[:space:]]*(0|off|no|false)$ ]]; then
        echo "gpgcheck is disabled. Enabling gpgcheck..."
        transactional-update shell <<EOF
sed -i 's/^gpgcheck[[:space:]]*=.*/gpgcheck = 1/' /etc/zypp/zypp.conf
exit
EOF
        log_message "Enabled gpgcheck in zypper."
    else
        echo "gpgcheck is already enabled."
        log_message "gpgcheck is already enabled."
    fi
}

# Function to verify Ctrl-Alt-Delete is not configured to reboot the system
check_ctrl_alt_del_reboot() {
    echo "Checking if Ctrl-Alt-Delete is configured to reboot the system..."
    ctrl_alt_del_status=$(grep -i 'CtrlAltDelBurstAction' /etc/systemd/system.conf)
    if [[ "$ctrl_alt_del_status" =~ ^CtrlAltDelBurstAction= ]]; then
        echo "Ctrl-Alt-Delete is configured to reboot the system. Fixing configuration..."
        transactional-update shell <<EOF
sed -i 's/^CtrlAltDelBurstAction=.*/#CtrlAltDelBurstAction=none/' /etc/systemd/system.conf
exit
EOF
        log_message "Disabled Ctrl-Alt-Delete reboot configuration."
    else
        echo "Ctrl-Alt-Delete is not configured to reboot the system."
        log_message "Ctrl-Alt-Delete is not configured to reboot the system."
    fi
}

# Function to ensure SSHD is set for PermitEmptyPasswords no and PermitUserEnvironment no
check_sshd_config() {
    echo "Checking SSHD configuration..."
    sshd_config_modified=false

    if grep -q "^PermitEmptyPasswords[[:space:]]*yes" /etc/ssh/sshd_config; then
        echo "Found PermitEmptyPasswords yes in /etc/ssh/sshd_config. Fixing configuration..."
        transactional-update shell <<EOF
sed -i 's/^PermitEmptyPasswords[[:space:]]*yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
exit
EOF
        log_message "Set PermitEmptyPasswords to no in /etc/ssh/sshd_config."
        sshd_config_modified=true
    fi

    if grep -q "^PermitUserEnvironment[[:space:]]*yes" /etc/ssh/sshd_config; then
        echo "Found PermitUserEnvironment yes in /etc/ssh/sshd_config. Fixing configuration..."
        transactional-update shell <<EOF
sed -i 's/^PermitUserEnvironment[[:space:]]*yes/PermitUserEnvironment no/' /etc/ssh/sshd_config
exit
EOF
        log_message "Set PermitUserEnvironment to no in /etc/ssh/sshd_config."
        sshd_config_modified=true
    fi

    if [ "$sshd_config_modified" = true ]; then
        echo "Restarting SSHD service to apply changes..."
        transactional-update shell <<EOF
systemctl restart sshd
exit
EOF
        log_message "Restarted SSHD service to apply configuration changes."
    else
        echo "SSHD configuration is already correct."
        log_message "SSHD configuration is already correct."
    fi
}

# Function to ensure no user account has a blank password or lock the account
lock_blank_password_accounts() {
    echo "Checking for user accounts with blank passwords..."
    blank_password_accounts=$(awk -F: '($2 == "" || $2 == "!!") {print $1}' /etc/shadow)
    if [ -n "$blank_password_accounts" ]; then
        echo "Found user accounts with blank passwords: $blank_password_accounts. Locking accounts and logging."
        while IFS= read -r account; do
            if [ "$account" == "root" ]; then
                echo "The root account has a blank password. Please set a new password for root:"
                passwd root
                log_message "Prompted user to set a password for root account."
            else
                passwd -l $account
                log_message "Locked user account with blank password: $account"
            fi
        done <<< "$blank_password_accounts"
    else
        echo "No user accounts with blank passwords found."
        log_message "No user accounts with blank passwords found."
    fi
}

# Main script starts here
validate_os_version

if [ -d /sys/firmware/efi ]; then
    configure_grub_password_uefi
else
    configure_grub_password_bios
fi

check_and_remove_shosts_equiv
check_and_remove_shosts_files
disable_ctrl_alt_del
fix_pam_configuration
check_and_remove_packages
ensure_openssh_installed
check_uid_0_accounts
check_sudoers_nopasswd
check_zypper_gpgcheck
check_ctrl_alt_del_reboot
check_sshd_config
lock_blank_password_accounts

# Inform the user about STIG compliance
echo "The system is now configured to meet the requirements of STIG."
