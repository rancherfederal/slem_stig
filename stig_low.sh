#!/bin/bash

LOGFILE="stig.log"

# Function to log messages
log_message() {
    echo "$1" >> "$LOGFILE"
}

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Exiting."
    exit 1
fi

# Function to configure concurrent session limits
configure_concurrent_session_limits() {
    local function_name="configure_concurrent_session_limits"
    local vuln_id="V-261367"
    local rule_id="SV-261367r996839"

    local limits_conf_file="/etc/security/limits.conf"
    local maxlogins_rule="* hard maxlogins 10"

    if ! grep -q "^$maxlogins_rule$" "$limits_conf_file"; then
        echo "$maxlogins_rule" >> "$limits_conf_file"
    fi

    if grep -q "^$maxlogins_rule$" "$limits_conf_file"; then
        log_message "$function_name: Vuln_ID: $vuln_id Rule_ID: $rule_id Configured concurrent session limits successfully."
    else
        log_message "$function_name: Vuln_ID: $vuln_id Rule_ID: $rule_id Failed to configure concurrent session limits. This is a finding."
    fi
}

# Function to verify the installation of the policycoreutils package
verify_policycoreutils_installed() {
    local function_name="verify_policycoreutils_installed"
    local vuln_id="V-261368"
    local rule_id="SV-261368r996548"

    if zypper search -i policycoreutils | grep -q "^i"; then
        log_message "$function_name: Vuln_ID: $vuln_id Rule_ID: $rule_id Verified policycoreutils package is installed successfully."
    else
        log_message "$function_name: Vuln_ID: $vuln_id Rule_ID: $rule_id Policycoreutils package is not installed. This is a finding."
    fi
}

# Function to configure audit event multiplexor to use Kerberos
configure_audisp_kerberos() {
    local function_name="configure_audisp_kerberos"
    local vuln_id="V-261421"
    local rule_id="SV-261421r996672"

    local audisp_remote_conf_file="/etc/audisp/audisp-remote.conf"
    local krb5_rule="enable_krb5 = yes"

    if ! grep -q "^$krb5_rule$" "$audisp_remote_conf_file"; then
        sed -i '/\[remote\]/a enable_krb5 = yes' "$audisp_remote_conf_file"
    fi

    if grep -q "^$krb5_rule$" "$audisp_remote_conf_file"; then
        log_message "$function_name: Vuln_ID: $vuln_id Rule_ID: $rule_id Configured audit event multiplexor to use Kerberos successfully."
    else
        log_message "$function_name: Vuln_ID: $vuln_id Rule_ID: $rule_id Failed to configure audit event multiplexor to use Kerberos. This is a finding."
    fi
}

# Example usage of the functions
configure_concurrent_session_limits
verify_policycoreutils_installed
configure_audisp_kerberos
