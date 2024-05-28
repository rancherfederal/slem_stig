#!/bin/bash

# Function to configure SELinux
setup_selinux() {
    current_mode=$(sestatus | grep 'SELinux status' | awk '{print $3}')
    if [ "$1" == "$current_mode" ]; then
        echo "SELinux is already set to $1 mode."
    else
        echo "Setting up SELinux to $1 mode..."
        transactional-update setup-selinux
        sed -i "s/^SELINUX=.*/SELINUX=$1/" /etc/selinux/config
        echo "SELinux is set to $1. Rebooting to apply changes..."
        reboot
    fi
}

# Function to configure FIPS
setup_fips() {
    fips_enabled=$(grep -c 'fips=1' /proc/cmdline)
    if [ "$1" == "enable" ] && [ "$fips_enabled" -eq 0 ]; then
        echo "Enabling FIPS mode..."
        transactional-update pkg install -t pattern microos-fips
        sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 fips=1"/' /etc/default/grub
        transactional-update grub.cfg
        echo "FIPS mode enabled. Rebooting to apply FIPS mode..."
        reboot
    elif [ "$1" == "disable" ] && [ "$fips_enabled" -ne 0 ]; then
        echo "Disabling FIPS mode..."
        sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\) fips=1/\1"/' /etc/default/grub
        transactional-update grub.cfg
        echo "FIPS mode disabled. Rebooting to apply changes..."
        reboot
    else
        echo "FIPS mode is already set as requested."
    fi
}

# Check and Configure PAM for SSHD
configure_pam_sshd() {
    echo "Checking PAM configuration for SSHD..."
    if ! grep -q "pam_tally2.so" /etc/pam.d/sshd; then
        echo "Configuring PAM for SSHD..."
        # Configuring PAM modules for SSHD
        cat << EOF > /etc/pam.d/sshd
# PAM configuration for the Secure Shell service

# Standard Un*x authentication.
auth       required     pam_tally2.so deny=5 onerr=fail unlock_time=900
auth       required     pam_env.so
auth       required     pam_unix.so nullok

# Disallow non-root logins when /etc/nologin exists
account    required     pam_nologin.so

# Set environment variables from /etc/security/pam_env.conf
session    required     pam_env.so
EOF
        echo "PAM for SSHD configured."
    else
        echo "PAM configuration for SSHD is already set."
    fi
}

# Default choices
selinux_choice="enable"
fips_choice="enable"

# User choices
echo "The default security configuration enables both SELinux and FIPS."
read -p "Would you like to disable SELinux? (yes/no): " disable_selinux
if [ "$disable_selinux" == "yes" ]; then
    selinux_choice="disable"
fi

read -p "Would you like to disable FIPS mode? (yes/no): " disable_fips
if [ "$disable_fips" == "yes" ]; then
    fips_choice="disable"
fi

# Applying user choices
[ "$selinux_choice" == "enable" ] && setup_selinux enforcing
[ "$selinux_choice" == "disable" ] && setup_selinux disabled

[ "$fips_choice" == "enable" ] && setup_fips enable
[ "$fips_choice" == "disable" ] && setup_fips disable

# Configure PAM for SSHD
configure_pam_sshd

# Optional reboot to apply all changes
echo "Would you like to reboot now to apply all changes? (yes/no): "
read reboot_now
if [ "$reboot_now" == "yes" ]; then
    echo "Rebooting now..."
    reboot
else
    echo "Please reboot manually to apply all changes."
fi
