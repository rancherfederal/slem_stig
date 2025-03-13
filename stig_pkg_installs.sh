#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Exiting."
    exit 1
fi

LOGFILE="stig_pkg_installs.log"

# Make a new logfile
> "$LOGFILE"

# Function to log messages
log_message() {
    local function_name="$1"
    local message="$2"
    echo "$function_name: | $message" >> "$LOGFILE"
}

# Packages to be installed per STIG's from the following Vulnerability IDs
# KBD                   V-261276
# MFA                   V-261396
# AIDE                  V-261403
# AIDE AUDIT            V-261410
# AUDIT AUDISPD PLUGINS V-261412

install_pkgs() {
    local function_name="install_pkgs"
    local pkgs=("pam_pkcs11" "mozilla-nss" "mozilla-nss-tools" "pcsc-ccid" "pcsc-lite" "pcsc-tools" "opensc" "coolkey" "kbd" "aide" "audit" "audit-audispd-plugins")

    # Using a transactional shell to install packages in a single session
    transactional-update shell <<EOF
zypper -nq update 
zypper -nq install ${pkgs[@]}
exit
EOF

    # Check if transactional shell executed successfully
    if [[ $? -eq 0 ]]; then
        log_message "$function_name" "SLEM 5 packages have been installed successfully in a transactional session."
    else
        log_message "$function_name" "Failed to install SLEM 5 packages within the transactional session."
        exit 1
    fi
}

install_pkgs
