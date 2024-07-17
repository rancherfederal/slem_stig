#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Exiting."
    exit 1
fi

LOGFILE="/root/base_hardening.log"

# Function to log messages
log_message() {
    echo "$(date): $1" | tee -a $LOGFILE
}

# Function to configure SELinux
setup_selinux() {
    current_mode=$(sestatus | grep 'Current mode' | awk '{print $3}')
    if [ "$1" == "$current_mode" ]; then
        log_message "SELinux is already set to $1 mode."
    else
        log_message "Setting up SELinux to $1 mode..."
        sed -i "s/^SELINUX=.*/SELINUX=$1/" /etc/selinux/config
        log_message "SELinux is set to $1. Rebooting to apply changes..."
        reboot
    fi
}

# Function to configure FIPS
setup_fips() {
    fips_enabled=$(grep -c 'fips=1' /proc/cmdline)
    if [ "$1" == "enable" ] && [ "$fips_enabled" -eq 0 ]; then
        log_message "Enabling FIPS mode..."
        zypper install -y -t pattern microos-fips
        sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 fips=1"/' /etc/default/grub
        grub2-mkconfig -o /boot/grub2/grub.cfg
        log_message "FIPS mode enabled. Rebooting to apply FIPS mode..."
        reboot
    elif [ "$1" == "disable" ] && [ "$fips_enabled" -ne 0 ]; then
        log_message "Disabling FIPS mode..."
        sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\) fips=1/\1"/' /etc/default/grub
        grub2-mkconfig -o /boot/grub2/grub.cfg
        log_message "FIPS mode disabled. Rebooting to apply changes..."
        reboot
    else
        log_message "FIPS mode is already set as requested."
    fi
}

# Check and Configure PAM for SSHD
configure_pam_sshd() {
    log_message "Configuring PAM for SSHD..."
    cat << EOF > /etc/pam.d/sshd
#%PAM-1.0

auth       requisite    pam_nologin.so
auth       include      common-auth
account    requisite    pam_nologin.so
account    include      common-account
password   include      common-password
session    required     pam_loginuid.so
session    include      common-session
session    optional     pam_lastlog.so silent noupdate showfailed
EOF
    log_message "PAM for SSHD configured."
}

configure_common_pam() {
    log_message "Configuring common PAM modules..."

    # Configure common-auth
    cat << EOF > /etc/pam.d/common-auth
auth required pam_env.so
auth optional pam_gnome_keyring.so
auth required pam_unix.so try_first_pass
EOF

    # Configure common-account
    cat << EOF > /etc/pam.d/common-account
account required pam_unix.so try_first_pass
EOF

    # Configure common-password
    cat << EOF > /etc/pam.d/common-password
password requisite pam_cracklib.so
password required pam_unix.so use_authtok nullok shadow try_first_pass
EOF

    # Configure common-session
    cat << EOF > /etc/pam.d/common-session
session required pam_selinux.so close
session optional pam_systemd.so
session required pam_limits.so
session required pam_unix.so try_first_pass
session optional pam_umask.so
session required pam_selinux.so open
session optional pam_env.so
EOF

    log_message "Common PAM modules configured."
}

# Default choices
selinux_choice="enforcing"
fips_choice="enable"

# User choices
log_message "The default security configuration enables both SELinux and FIPS."
read -p "Would you like to disable SELinux? (yes/no): " disable_selinux
if [ "$disable_selinux" == "yes" ]; then
    selinux_choice="disabled"
fi

read -p "Would you like to disable FIPS mode? (yes/no): " disable_fips
if [ "$disable_fips" == "yes" ]; then
    fips_choice="disable"
fi

# Applying user choices
[ "$selinux_choice" == "enforcing" ] && setup_selinux enforcing
[ "$selinux_choice" == "disabled" ] && setup_selinux disabled

[ "$fips_choice" == "enable" ] && setup_fips enable
[ "$fips_choice" == "disable" ] && setup_fips disable

# Configure PAM for SSHD
configure_pam_sshd
configure_common_pam

# Optional reboot to apply all changes
read -p "Would you like to reboot now to apply all changes? (yes/no): " reboot_now
if [ "$reboot_now" == "yes" ]; then
    log_message "Rebooting now..."
    reboot
else
    log_message "Please reboot manually to apply all changes."
fi
