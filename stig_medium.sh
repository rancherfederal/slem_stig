#!/bin/bash

LOGFILE="STIG_findings_medium.log"
DEFAULT_USER="defaultuser"
DEFAULT_GROUP="defaultgroup"

# Function to install a list of packages using transactional-update
install_packages() {
    local packages=(
        "pam_pkcs11"
        "mozilla-nss"
        "mozilla-nss-tools"
        "pcsc-ccid"
        # Add more packages here as needed
    )
    for package in "${packages[@]}"; do
        echo "Installing package: $package" | tee -a "$LOGFILE"
        if transactional-update pkg install -yl "$package" >> "$LOGFILE" 2>&1; then
            echo "Successfully installed package: $package" | tee -a "$LOGFILE"
        else
            echo "Failed to install package: $package" | tee -a "$LOGFILE"
        fi
    done
}

# Function to set temporary accounts to expire in 72 hours
expire_temporary_accounts() {
    echo "Checking for temporary accounts to set expiration." | tee -a "$LOGFILE"
    TEMPORARY_USERS=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd) # Adjust UID range if necessary
    CURRENT_DATE=$(date +%s)
    EXPIRATION_DATE=$(date -d "72 hours" +%s)

    for user in $TEMPORARY_USERS; do
        USER_EXPIRATION=$(chage -l $user | grep "Account expires" | awk -F: '{print $2}' | xargs -I{} date -d {} +%s)
        if [ -z "$USER_EXPIRATION" ] || [ "$USER_EXPIRATION" -gt "$EXPIRATION_DATE" ]; then
            echo "Setting expiration for user: $user to 72 hours from now." | tee -a "$LOGFILE"
            if chage -E $(date -d "72 hours" +%Y-%m-%d) $user >> "$LOGFILE" 2>&1; then
                echo "Successfully set expiration for user: $user" | tee -a "$LOGFILE"
            else
                echo "Failed to set expiration for user: $user" | tee -a "$LOGFILE"
            fi
        fi
    done
}

# Function to initialize AIDE
initialize_aide() {
    echo "Initializing AIDE." | tee -a "$LOGFILE"
    if aide -i >> "$LOGFILE" 2>&1; then
        echo "AIDE initialization successful." | tee -a "$LOGFILE"
        if mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db >> "$LOGFILE" 2>&1; then
            echo "AIDE database moved to /var/lib/aide/aide.db" | tee -a "$LOGFILE"
        else
            echo "Failed to move AIDE database." | tee -a "$LOGFILE"
        fi
    else
        echo "AIDE initialization failed." | tee -a "$LOGFILE"
    fi
}

# Function to ensure SSHD FIPS-validated key exchange algorithms
configure_sshd_kex() {
    local sshd_config="/etc/ssh/sshd_config"
    local required_kex="ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256"
    
    echo "Checking SSHD KexAlgorithms configuration." | tee -a "$LOGFILE"
    if grep -iq "^KexAlgorithms $required_kex" "$sshd_config"; then
        echo "SSHD KexAlgorithms are correctly configured." | tee -a "$LOGFILE"
    else
        echo "Updating SSHD KexAlgorithms to FIPS-validated algorithms." | tee -a "$LOGFILE"
        if grep -iq "^KexAlgorithms" "$sshd_config"; then
            sed -i "s/^KexAlgorithms.*/KexAlgorithms $required_kex/" "$sshd_config"
        else
            echo "KexAlgorithms $required_kex" >> "$sshd_config"
        fi
        if systemctl restart sshd >> "$LOGFILE" 2>&1; then
            echo "SSHD restarted successfully with updated KexAlgorithms." | tee -a "$LOGFILE"
        else
            echo "Failed to restart SSHD with updated KexAlgorithms." | tee -a "$LOGFILE"
        fi
    fi
}

# Function to verify the operating system specifies only the default "include" directory for the /etc/sudoers file
check_sudoers_include() {
    local sudoers_file="/etc/sudoers"
    local include_line="@includedir /etc/sudoers.d"
    
    echo "Checking /etc/sudoers for @includedir /etc/sudoers.d." | tee -a "$LOGFILE"
    if grep -q "^@includedir /etc/sudoers.d" "$sudoers_file"; then
        echo "Correct include directory found in /etc/sudoers." | tee -a "$LOGFILE"
    else
        echo "Updating /etc/sudoers to include the correct directory." | tee -a "$LOGFILE"
        if grep -q "^@includedir" "$sudoers_file"; then
            sed -i "s|^@includedir.*|$include_line|" "$sudoers_file"
        else
            echo "$include_line" >> "$sudoers_file"
        fi
        echo "Successfully updated /etc/sudoers to include @includedir /etc/sudoers.d." | tee -a "$LOGFILE"
    fi
}

# Function to verify the system default permissions for all authenticated users
check_umask() {
    local login_defs="/etc/login.defs"
    local umask_setting="UMASK 077"
    
    echo "Checking /etc/login.defs for UMASK setting." | tee -a "$LOGFILE"
    if grep -iq "^UMASK 000" "$login_defs"; then
        echo "UMASK is set to 000, which is a CAT I finding." | tee -a "$LOGFILE"
    elif grep -iq "^UMASK 077" "$login_defs"; then
        echo "UMASK is correctly set to 077." | tee -a "$LOGFILE"
    else
        echo "Updating UMASK to 077 in /etc/login.defs." | tee -a "$LOGFILE"
        if grep -iq "^UMASK" "$login_defs"; then
            sed -i "s/^UMASK.*/$umask_setting/" "$login_defs"
        else
            echo "$umask_setting" >> "$login_defs"
        fi
        echo "Successfully updated UMASK to 077 in /etc/login.defs." | tee -a "$LOGFILE"
    fi
}

# Function to verify all files and directories have a valid group and owner
check_files_ownership() {
    local filesystem_type="xfs"
    local files_no_group
    local files_no_user

    echo "Checking for files and directories without a valid group." | tee -a "$LOGFILE"
    files_no_group=$(sudo find / -fstype "$filesystem_type" -nogroup)
    if [ -n "$files_no_group" ]; then
        echo "Found files and directories without a valid group." | tee -a "$LOGFILE"
        echo "$files_no_group" | while read -r file; do
            echo "Fixing group for $file" | tee -a "$LOGFILE"
            if sudo chown :"$DEFAULT_GROUP" "$file" >> "$LOGFILE" 2>&1; then
                echo "Successfully fixed group for $file" | tee -a "$LOGFILE"
            else
                echo "Failed to fix group for $file" | tee -a "$LOGFILE"
            fi
        done
    else
        echo "No files or directories found without a valid group." | tee -a "$LOGFILE"
    fi

    echo "Checking for files and directories without a valid owner." | tee -a "$LOGFILE"
    files_no_user=$(sudo find / -fstype "$filesystem_type" -nouser)
    if [ -n "$files_no_user" ]; then
        echo "Found files and directories without a valid owner." | tee -a "$LOGFILE"
        echo "$files_no_user" | while read -r file; do
            echo "Fixing owner for $file" | tee -a "$LOGFILE"
            if sudo chown "$DEFAULT_USER:" "$file" >> "$LOGFILE" 2>&1; then
                echo "Successfully fixed owner for $file" | tee -a "$LOGFILE"
            else
                echo "Failed to fix owner for $file" | tee -a "$LOGFILE"
            fi
        done
    else
        echo "No files or directories found without a valid owner." | tee -a "$LOGFILE"
    fi
}

# Function to verify that network interfaces are not in promiscuous mode unless approved by the ISSO
check_promiscuous_mode() {
    echo "Checking for network interfaces in promiscuous mode." | tee -a "$LOGFILE"
    local interfaces_in_promiscuous_mode
    interfaces_in_promiscuous_mode=$(ip link | grep -i promisc)
    if [ -n "$interfaces_in_promiscuous_mode" ]; then
        echo "Found network interfaces in promiscuous mode:" | tee -a "$LOGFILE"
        echo "$interfaces_in_promiscuous_mode" | tee -a "$LOGFILE"
        # Add logic here to check for ISSO approval and documentation if necessary
        echo "Disabling promiscuous mode on the following interfaces:" | tee -a "$LOGFILE"
        echo "$interfaces_in_promiscuous_mode" | awk -F: '{print $2}' | while read -r interface; do
            echo "Disabling promiscuous mode on $interface" | tee -a "$LOGFILE"
            if sudo ip link set "$interface" promisc off >> "$LOGFILE" 2>&1; then
                echo "Successfully disabled promiscuous mode on $interface" | tee -a "$LOGFILE"
            else
                echo "Failed to disable promiscuous mode on $interface" | tee -a "$LOGFILE"
            fi
        done
    else
        echo "No network interfaces found in promiscuous mode." | tee -a "$LOGFILE"
    fi
}

# Function to verify the SUSE operating system is not performing IPv4 and IPv6 packet forwarding
check_ip_forwarding() {
    echo "Checking if IPv6 packet forwarding is disabled by default." | tee -a "$LOGFILE"
    if sysctl net.ipv6.conf.default.forwarding &> /dev/null; then
        local ipv6_default_forwarding
        ipv6_default_forwarding=$(sysctl net.ipv6.conf.default.forwarding | awk '{print $3}')
        if [ "$ipv6_default_forwarding" -eq 0 ]; then
            echo "IPv6 packet forwarding is disabled by default." | tee -a "$LOGFILE"
        else
            echo "IPv6 packet forwarding is enabled by default. Disabling it." | tee -a "$LOGFILE"
            if sudo sysctl -w net.ipv6.conf.default.forwarding=0 >> "$LOGFILE" 2>&1; then
                echo "Successfully disabled IPv6 packet forwarding by default." | tee -a "$LOGFILE"
                echo "net.ipv6.conf.default.forwarding=0" | sudo tee -a /etc/sysctl.conf >> "$LOGFILE"
            else
                echo "Failed to disable IPv6 packet forwarding by default." | tee -a "$LOGFILE"
            fi
        fi
    else
        echo "IPv6 default forwarding configuration not found." | tee -a "$LOGFILE"
    fi

    echo "Checking if IPv6 packet forwarding is disabled for all interfaces." | tee -a "$LOGFILE"
    if sysctl net.ipv6.conf.all.forwarding &> /dev/null; then
        local ipv6_all_forwarding
        ipv6_all_forwarding=$(sysctl net.ipv6.conf.all.forwarding | awk '{print $3}')
        if [ "$ipv6_all_forwarding" -eq 0 ]; then
            echo "IPv6 packet forwarding is disabled for all interfaces." | tee -a "$LOGFILE"
        else
            echo "IPv6 packet forwarding is enabled for all interfaces. Disabling it." | tee -a "$LOGFILE"
            if sudo sysctl -w net.ipv6.conf.all.forwarding=0 >> "$LOGFILE" 2>&1; then
                echo "Successfully disabled IPv6 packet forwarding for all interfaces." | tee -a "$LOGFILE"
                echo "net.ipv6.conf.all.forwarding=0" | sudo tee -a /etc/sysctl.conf >> "$LOGFILE"
            else
                echo "Failed to disable IPv6 packet forwarding for all interfaces." | tee -a "$LOGFILE"
            fi
        fi
    else
        echo "IPv6 all forwarding configuration not found." | tee -a "$LOGFILE"
    fi

    echo "Checking if IPv4 packet forwarding is disabled by default." | tee -a "$LOGFILE"
    if sysctl net.ipv4.conf.default.forwarding &> /dev/null; then
        local ipv4_default_forwarding
        ipv4_default_forwarding=$(sysctl net.ipv4.conf.default.forwarding | awk '{print $3}')
        if [ "$ipv4_default_forwarding" -eq 0 ]; then
            echo "IPv4 packet forwarding is disabled by default." | tee -a "$LOGFILE"
        else
            echo "IPv4 packet forwarding is enabled by default. Disabling it." | tee -a "$LOGFILE"
            if sudo sysctl -w net.ipv4.conf.default.forwarding=0 >> "$LOGFILE" 2>&1; then
                echo "Successfully disabled IPv4 packet forwarding by default." | tee -a "$LOGFILE"
                echo "net.ipv4.conf.default.forwarding=0" | sudo tee -a /etc/sysctl.conf >> "$LOGFILE"
            else
                echo "Failed to disable IPv4 packet forwarding by default." | tee -a "$LOGFILE"
            fi
        fi
    else
        echo "IPv4 default forwarding configuration not found." | tee -a "$LOGFILE"
    fi

    echo "Checking if IPv4 packet forwarding is disabled for all interfaces." | tee -a "$LOGFILE"
    if sysctl net.ipv4.conf.all.forwarding &> /dev/null; then
        local ipv4_all_forwarding
        ipv4_all_forwarding=$(sysctl net.ipv4.conf.all.forwarding | awk '{print $3}')
        if [ "$ipv4_all_forwarding" -eq 0 ]; then
            echo "IPv4 packet forwarding is disabled for all interfaces." | tee -a "$LOGFILE"
        else
            echo "IPv4 packet forwarding is enabled for all interfaces. Disabling it." | tee -a "$LOGFILE"
            if sudo sysctl -w net.ipv4.conf.all.forwarding=0 >> "$LOGFILE" 2>&1; then
                echo "Successfully disabled IPv4 packet forwarding for all interfaces." | tee -a "$LOGFILE"
                echo "net.ipv4.conf.all.forwarding=0" | sudo tee -a /etc/sysctl.conf >> "$LOGFILE"
            else
                echo "Failed to disable IPv4 packet forwarding for all interfaces." | tee -a "$LOGFILE"
            fi
        fi
    else
        echo "IPv4 all forwarding configuration not found." | tee -a "$LOGFILE"
    fi
}

# Function to verify IPv4 and IPv6 ICMP redirects are disabled
check_icmp_redirects() {
    echo "Checking if IPv4 ICMP redirects are disabled." | tee -a "$LOGFILE"
    local ipv4_icmp_redirects
    ipv4_icmp_redirects=$(sysctl net.ipv4.conf.all.accept_redirects | awk '{print $3}')
    if [ "$ipv4_icmp_redirects" -eq 0 ]; then
        echo "IPv4 ICMP redirects are disabled." | tee -a "$LOGFILE"
    else
        echo "IPv4 ICMP redirects are enabled. Disabling them." | tee -a "$LOGFILE"
        if sudo sysctl -w net.ipv4.conf.all.accept_redirects=0 >> "$LOGFILE" 2>&1 && sudo sysctl -w net.ipv4.conf.default.accept_redirects=0 >> "$LOGFILE" 2>&1; then
            echo "Successfully disabled IPv4 ICMP redirects." | tee -a "$LOGFILE"
            echo "net.ipv4.conf.all.accept_redirects=0" | sudo tee -a /etc/sysctl.conf >> "$LOGFILE"
            echo "net.ipv4.conf.default.accept_redirects=0" | sudo tee -a /etc/sysctl.conf >> "$LOGFILE"
        else
            echo "Failed to disable IPv4 ICMP redirects." | tee -a "$LOGFILE"
        fi
    fi

    echo "Checking if IPv6 ICMP redirects are disabled." | tee -a "$LOGFILE"
    local ipv6_icmp_redirects
    ipv6_icmp_redirects=$(sysctl net.ipv6.conf.all.accept_redirects | awk '{print $3}')
    if [ "$ipv6_icmp_redirects" -eq 0 ]; then
        echo "IPv6 ICMP redirects are disabled." | tee -a "$LOGFILE"
    else
        echo "IPv6 ICMP redirects are enabled. Disabling them." | tee -a "$LOGFILE"
        if sudo sysctl -w net.ipv6.conf.all.accept_redirects=0 >> "$LOGFILE" 2>&1 && sudo sysctl -w net.ipv6.conf.default.accept_redirects=0 >> "$LOGFILE" 2>&1; then
            echo "Successfully disabled IPv6 ICMP redirects." | tee -a "$LOGFILE"
            echo "net.ipv6.conf.all.accept_redirects=0" | sudo tee -a /etc/sysctl.conf >> "$LOGFILE"
            echo "net.ipv6.conf.default.accept_redirects=0" | sudo tee -a /etc/sysctl.conf >> "$LOGFILE"
        else
            echo "Failed to disable IPv6 ICMP redirects." | tee -a "$LOGFILE"
        fi
    fi
}

# Function to ensure IPv4 and IPv6 source routing is disabled
check_source_route() {
    echo "Checking if IPv4 source routing is disabled." | tee -a "$LOGFILE"
    local ipv4_source_route
    ipv4_source_route=$(sysctl net.ipv4.conf.all.accept_source_route | awk '{print $3}')
    if [ "$ipv4_source_route" -eq 0 ]; then
        echo "IPv4 source routing is disabled." | tee -a "$LOGFILE"
    else
        echo "IPv4 source routing is enabled. Disabling it." | tee -a "$LOGFILE"
        if sudo sysctl -w net.ipv4.conf.all.accept_source_route=0 >> "$LOGFILE" 2>&1 && sudo sysctl -w net.ipv4.conf.default.accept_source_route=0 >> "$LOGFILE" 2>&1; then
            echo "Successfully disabled IPv4 source routing." | tee -a "$LOGFILE"
            echo "net.ipv4.conf.all.accept_source_route=0" | sudo tee -a /etc/sysctl.conf >> "$LOGFILE"
            echo "net.ipv4.conf.default.accept_source_route=0" | sudo tee -a /etc/sysctl.conf >> "$LOGFILE"
        else
            echo "Failed to disable IPv4 source routing." | tee -a "$LOGFILE"
        fi
    fi

    echo "Checking if IPv6 source routing is disabled." | tee -a "$LOGFILE"
    local ipv6_source_route
    ipv6_source_route=$(sysctl net.ipv6.conf.all.accept_source_route | awk '{print $3}')
    if [ "$ipv6_source_route" -eq 0 ]; then
        echo "IPv6 source routing is disabled." | tee -a "$LOGFILE"
    else
        echo "IPv6 source routing is enabled. Disabling it." | tee -a "$LOGFILE"
        if sudo sysctl -w net.ipv6.conf.all.accept_source_route=0 >> "$LOGFILE" 2>&1 && sudo sysctl -w net.ipv6.conf.default.accept_source_route=0 >> "$LOGFILE" 2>&1; then
            echo "Successfully disabled IPv6 source routing." | tee -a "$LOGFILE"
            echo "net.ipv6.conf.all.accept_source_route=0" | sudo tee -a /etc/sysctl.conf >> "$LOGFILE"
            echo "net.ipv6.conf.default.accept_source_route=0" | sudo tee -a /etc/sysctl.conf >> "$LOGFILE"
        else
            echo "Failed to disable IPv6 source routing." | tee -a "$LOGFILE"
        fi
    fi
}

# Function to configure SSH settings
configure_ssh() {
    local sshd_config="/etc/ssh/sshd_config"
    
    echo "Disabling SSH X11 forwarding and setting StrictModes to yes." | tee -a "$LOGFILE"
    if grep -iq "^X11Forwarding" "$sshd_config"; then
        sed -i "s/^X11Forwarding.*/X11Forwarding no/" "$sshd_config"
    else
        echo "X11Forwarding no" >> "$sshd_config"
    fi
    if grep -iq "^StrictModes" "$sshd_config"; then
        sed -i "s/^StrictModes.*/StrictModes yes/" "$sshd_config"
    else
        echo "StrictModes yes" >> "$sshd_config"
    fi

    echo "Disabling known hosts authentication by setting IgnoreUserKnownHosts to yes." | tee -a "$LOGFILE"
    if grep -iq "^IgnoreUserKnownHosts" "$sshd_config"; then
        sed -i "s/^IgnoreUserKnownHosts.*/IgnoreUserKnownHosts yes/" "$sshd_config"
    else
        echo "IgnoreUserKnownHosts yes" >> "$sshd_config"
    fi

    echo "Verifying SSH private keys have mode 0600." | tee -a "$LOGFILE"
    find /etc/ssh -type f -name 'ssh_host_*_key' -exec stat -c "%a %n" {} \; | while read -r mode file; do
        if [ "$mode" -ne 600 ]; then
            echo "File $file has mode $mode, changing to 0600." | tee -a "$LOGFILE"
            if sudo chmod 0600 "$file" >> "$LOGFILE" 2>&1; then
                echo "Successfully changed mode of $file to 0600." | tee -a "$LOGFILE"
            else
                echo "Failed to change mode of $file." | tee -a "$LOGFILE"
            fi
        fi
    done

    echo "Verifying SSH public keys have mode 0644." | tee -a "$LOGFILE"
    find /etc/ssh -name 'ssh_host*key.pub' -exec stat -c "%a %n" {} \; | while read -r mode file; do
        if [ "$mode" -gt 644 ]; then
            echo "File $file has mode $mode, changing to 0644." | tee -a "$LOGFILE"
            if sudo chmod 0644 "$file" >> "$LOGFILE" 2>&1; then
                echo "Successfully changed mode of $file to 0644." | tee -a "$LOGFILE"
            else
                echo "Failed to change mode of $file." | tee -a "$LOGFILE"
            fi
        fi
    done

    if systemctl restart sshd >> "$LOGFILE" 2>&1; then
        echo "SSHD restarted successfully with updated settings." | tee -a "$LOGFILE"
    else
        echo "Failed to restart SSHD with updated settings." | tee -a "$LOGFILE"
    fi
}

# Function to copy PAM configuration files to static locations and remove soft links
# and to verify the system is not configured to bypass password requirements for privilege escalation
check_and_fix_pam() {
    echo "Copying PAM configuration files to their static locations and removing soft links." | tee -a "$LOGFILE"
    
    sudo sh -c 'for X in /etc/pam.d/common-*-pc; do
        echo "Copying $X to ${X:0:-3}" | tee -a "'$LOGFILE'"
        if cp -ivp --remove-destination "$X" "${X:0:-3}" >> "'$LOGFILE'" 2>&1; then
            echo "Successfully copied $X to ${X:0:-3}" | tee -a "'$LOGFILE'"
        else
            echo "Failed to copy $X to ${X:0:-3}" | tee -a "'$LOGFILE'"
        fi
    done'

    echo "Verifying the SUSE operating system is configured to not overwrite PAM configuration on package changes." | tee -a "$LOGFILE"
    echo "Checking for soft links between PAM configuration files." | tee -a "$LOGFILE"
    local pam_links
    pam_links=$(find /etc/pam.d/ -type l -iname "common-*")

    if [ -n "$pam_links" ]; then
        echo "Found soft links between PAM configuration files:" | tee -a "$LOGFILE"
        echo "$pam_links" | tee -a "$LOGFILE"
        echo "$pam_links" | while read -r link; do
            echo "Removing soft link: $link" | tee -a "$LOGFILE"
            if rm "$link" >> "$LOGFILE" 2>&1; then
                echo "Successfully removed soft link: $link" | tee -a "$LOGFILE"
            else
                echo "Failed to remove soft link: $link" | tee -a "$LOGFILE"
            fi
        done
    else
        echo "No soft links found between PAM configuration files." | tee -a "$LOGFILE"
    fi

    echo "Verifying the SUSE operating system enforces a delay of at least four seconds between logon prompts following a failed logon attempt." | tee -a "$LOGFILE"
    if grep -q "pam_faildelay" /etc/pam.d/common-auth; then
        if grep -q "pam_faildelay.so delay=4000000" /etc/pam.d/common-auth; then
            echo "The delay is correctly set to 4000000 microseconds." | tee -a "$LOGFILE"
        else
            echo "The delay is not set correctly. Updating the delay to 4000000 microseconds." | tee -a "$LOGFILE"
            if sed -i '/pam_faildelay/s/.*/auth required pam_faildelay.so delay=4000000/' /etc/pam.d/common-auth >> "$LOGFILE" 2>&1; then
                echo "Successfully updated the delay to 4000000 microseconds." | tee -a "$LOGFILE"
            else
                echo "Failed to update the delay." | tee -a "$LOGFILE"
            fi
        fi
    else
        echo "The pam_faildelay line is missing. Adding the delay setting." | tee -a "$LOGFILE"
        if echo "auth required pam_faildelay.so delay=4000000" >> /etc/pam.d/common-auth; then
            echo "Successfully added the delay setting." | tee -a "$LOGFILE"
        else
            echo "Failed to add the delay setting." | tee -a "$LOGFILE"
        fi
    fi

    echo "Checking /etc/pam.d/sudo for pam_succeed_if." | tee -a "$LOGFILE"
    if grep -iq "pam_succeed_if" /etc/pam.d/sudo; then
        echo "Found pam_succeed_if in /etc/pam.d/sudo. Removing it." | tee -a "$LOGFILE"
        if sed -i '/pam_succeed_if/d' /etc/pam.d/sudo >> "$LOGFILE" 2>&1; then
            echo "Successfully removed pam_succeed_if from /etc/pam.d/sudo." | tee -a "$LOGFILE"
        else
            echo "Failed to remove pam_succeed_if from /etc/pam.d/sudo." | tee -a "$LOGFILE"
        fi
    else
        echo "No pam_succeed_if entries found in /etc/pam.d/sudo." | tee -a "$LOGFILE"
    fi
}

# Function to disable kdump.service and log it
disable_kdump_service() {
    echo "Checking if kdump.service is running." | tee -a "$LOGFILE"
    if systemctl is-active --quiet kdump.service; then
        echo "kdump.service is running. Disabling and stopping it." | tee -a "$LOGFILE"

        if sudo systemctl stop kdump.service >> "$LOGFILE" 2>&1; then
            echo "Successfully stopped kdump.service." | tee -a "$LOGFILE"
        else
            echo "Failed to stop kdump.service." | tee -a "$LOGFILE"
        fi

        if sudo systemctl disable kdump.service >> "$LOGFILE" 2>&1; then
            echo "Successfully disabled kdump.service." | tee -a "$LOGFILE"
        else
            echo "Failed to disable kdump.service." | tee -a "$LOGFILE"
        fi
    else
        echo "kdump.service is not running." | tee -a "$LOGFILE"
    fi
}

# Function to verify the SUSE operating system enforces a delay of at least four seconds between logon prompts following a failed logon attempt
check_and_fix_fail_delay() {
    echo "Verifying the SUSE operating system enforces a delay of at least four seconds between logon prompts following a failed logon attempt." | tee -a "$LOGFILE"

    if grep -q "^FAIL_DELAY" /etc/login.defs; then
        current_delay=$(grep "^FAIL_DELAY" /etc/login.defs | awk '{print $2}')
        if [ "$current_delay" -eq 4 ]; then
            echo "FAIL_DELAY is correctly set to 4 seconds." | tee -a "$LOGFILE"
        else
            echo "FAIL_DELAY is set to $current_delay seconds, updating to 4 seconds." | tee -a "$LOGFILE"
            if sed -i 's/^FAIL_DELAY.*/FAIL_DELAY 4/' /etc/login.defs >> "$LOGFILE" 2>&1; then
                echo "Successfully updated FAIL_DELAY to 4 seconds." | tee -a "$LOGFILE"
            else
                echo "Failed to update FAIL_DELAY." | tee -a "$LOGFILE"
            fi
        fi
    else
        echo "FAIL_DELAY is not set, adding FAIL_DELAY 4 to /etc/login.defs." | tee -a "$LOGFILE"
        if echo "FAIL_DELAY 4" >> /etc/login.defs; then
            echo "Successfully added FAIL_DELAY 4 to /etc/login.defs." | tee -a "$LOGFILE"
        else
            echo "Failed to add FAIL_DELAY 4 to /etc/login.defs." | tee -a "$LOGFILE"
        fi
    fi
}

check_syscall_auditing() {
    echo "Verifying syscall auditing has not been disabled." | tee -a "$LOGFILE"
    
    local auditctl_output
    auditctl_output=$(auditctl -l | grep -i "a task,never")
    
    if [ -n "$auditctl_output" ]; then
        echo "Syscall auditing has been disabled by a rule: $auditctl_output" | tee -a "$LOGFILE"
        echo "This is a finding. Please manually inspect and correct the configuration." | tee -a "$LOGFILE"
    else
        echo "Syscall auditing is correctly configured." | tee -a "$LOGFILE"
    fi

    echo "Verifying the default rule '-a task,never' is not statically defined." | tee -a "$LOGFILE"
    
    local static_rule
    static_rule=$(grep -rv "^#" /etc/audit/rules.d/ | grep -i "a task,never")
    
    if [ -n "$static_rule" ]; then
        echo "Found static definition of '-a task,never' in audit rules: $static_rule" | tee -a "$LOGFILE"
        echo "Removing the static definition of '-a task,never'." | tee -a "$LOGFILE"
        if sed -i '/a task,never/d' /etc/audit/rules.d/* >> "$LOGFILE" 2>&1; then
            echo "Successfully removed the static definition of '-a task,never'." | tee -a "$LOGFILE"
            if systemctl restart auditd >> "$LOGFILE" 2>&1; then
                echo "Auditd service restarted successfully." | tee -a "$LOGFILE"
            else
                echo "Failed to restart auditd service." | tee -a "$LOGFILE"
            fi
        else
            echo "Failed to remove the static definition of '-a task,never'." | tee -a "$LOGFILE"
        fi
    else
        echo "No static definition of '-a task,never' found in audit rules." | tee -a "$LOGFILE"
    fi
}

# Function to verify auditing for /var/log/btmp, /var/log/wtmp, /run/utmp, and specific system calls
check_and_fix_audit_logs() {
    echo "Verifying if /var/log/btmp, /var/log/wtmp, and /run/utmp are being audited." | tee -a "$LOGFILE"

    # Check /var/log/btmp
    local btmp_audit_rule
    btmp_audit_rule=$(auditctl -l | grep -w '/var/log/btmp')

    if [ -n "$btmp_audit_rule" ]; then
        echo "/var/log/btmp is being audited." | tee -a "$LOGFILE"
    else
        echo "/var/log/btmp is not being audited. Adding audit rule." | tee -a "$LOGFILE"
        if echo "-w /var/log/btmp -p wa -k login_mod" >> /etc/audit/rules.d/audit.rules 2>> "$LOGFILE"; then
            echo "Successfully added audit rule for /var/log/btmp." | tee -a "$LOGFILE"
            if auditctl -w /var/log/btmp -p wa -k login_mod >> "$LOGFILE" 2>&1; then
                echo "Successfully applied audit rule for /var/log/btmp." | tee -a "$LOGFILE"
            else
                echo "Failed to apply audit rule for /var/log/btmp." | tee -a "$LOGFILE"
            fi
            if systemctl restart auditd >> "$LOGFILE" 2>&1; then
                echo "Auditd service restarted successfully." | tee -a "$LOGFILE"
            else
                echo "Failed to restart auditd service." | tee -a "$LOGFILE"
            fi
        else
            echo "Failed to add audit rule for /var/log/btmp." | tee -a "$LOGFILE"
        fi
    fi

    # Check /var/log/wtmp
    local wtmp_audit_rule
    wtmp_audit_rule=$(auditctl -l | grep -w '/var/log/wtmp')

    if [ -n "$wtmp_audit_rule" ]; then
        echo "/var/log/wtmp is being audited." | tee -a "$LOGFILE"
    else
        echo "/var/log/wtmp is not being audited. Adding audit rule." | tee -a "$LOGFILE"
        if echo "-w /var/log/wtmp -p wa -k login_mod" >> /etc/audit/rules.d/audit.rules 2>> "$LOGFILE"; then
            echo "Successfully added audit rule for /var/log/wtmp." | tee -a "$LOGFILE"
            if auditctl -w /var/log/wtmp -p wa -k login_mod >> "$LOGFILE" 2>&1; then
                echo "Successfully applied audit rule for /var/log/wtmp." | tee -a "$LOGFILE"
            else
                echo "Failed to apply audit rule for /var/log/wtmp." | tee -a "$LOGFILE"
            fi
            if systemctl restart auditd >> "$LOGFILE" 2>&1; then
                echo "Auditd service restarted successfully." | tee -a "$LOGFILE"
            else
                echo "Failed to restart auditd service." | tee -a "$LOGFILE"
            fi
        else
            echo "Failed to add audit rule for /var/log/wtmp." | tee -a "$LOGFILE"
        fi
    fi

    # Check /run/utmp
    local utmp_audit_rule
    utmp_audit_rule=$(auditctl -l | grep -w '/run/utmp')

    if [ -n "$utmp_audit_rule" ]; then
        echo "/run/utmp is being audited." | tee -a "$LOGFILE"
    else
        echo "/run/utmp is not being audited. Adding audit rule." | tee -a "$LOGFILE"
        if echo "-w /run/utmp -p wa -k login_mod" >> /etc/audit/rules.d/audit.rules 2>> "$LOGFILE"; then
            echo "Successfully added audit rule for /run/utmp." | tee -a "$LOGFILE"
            if auditctl -w /run/utmp -p wa -k login_mod >> "$LOGFILE" 2>&1; then
                echo "Successfully applied audit rule for /run/utmp." | tee -a "$LOGFILE"
            else
                echo "Failed to apply audit rule for /run/utmp." | tee -a "$LOGFILE"
            fi
            if systemctl restart auditd >> "$LOGFILE" 2>&1; then
                echo "Auditd service restarted successfully." | tee -a "$LOGFILE"
            else
                echo "Failed to restart auditd service." | tee -a "$LOGFILE"
            fi
        else
            echo "Failed to add audit rule for /run/utmp." | tee -a "$LOGFILE"
        fi
    fi

    # Check unlink, unlinkat, rename, renameat, rmdir system calls
    local syscall_audit_rule
    syscall_audit_rule=$(auditctl -l | grep 'unlink\|rename\|rmdir')

    if [[ ! "$syscall_audit_rule" =~ "arch=b32" ]] || [[ ! "$syscall_audit_rule" =~ "arch=b64" ]]; then
        echo "System calls unlink, unlinkat, rename, renameat, rmdir are not being audited correctly. Adding audit rules." | tee -a "$LOGFILE"
        if echo "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -k perm_mod" >> /etc/audit/rules.d/audit.rules 2>> "$LOGFILE" && \
           echo "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -k perm_mod" >> /etc/audit/rules.d/audit.rules 2>> "$LOGFILE"; then
            echo "Successfully added audit rules for unlink, unlinkat, rename, renameat, rmdir system calls." | tee -a "$LOGFILE"
            if auditctl -a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -k perm_mod >> "$LOGFILE" 2>&1 && \
               auditctl -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -k perm_mod >> "$LOGFILE" 2>&1; then
                echo "Successfully applied audit rules for unlink, unlinkat, rename, renameat, rmdir system calls." | tee -a "$LOGFILE"
            else
                echo "Failed to apply audit rules for unlink, unlinkat, rename, renameat, rmdir system calls." | tee -a "$LOGFILE"
            fi
            if systemctl restart auditd >> "$LOGFILE" 2>&1; then
                echo "Auditd service restarted successfully." | tee -a "$LOGFILE"
            else
                echo "Failed to restart auditd service." | tee -a "$LOGFILE"
            fi
        else
            echo "Failed to add audit rules for unlink, unlinkat, rename, renameat, rmdir system calls." | tee -a "$LOGFILE"
        fi
    else
        echo "System calls unlink, unlinkat, rename, renameat, rmdir are being audited correctly." | tee -a "$LOGFILE"
    fi
}

# Call the functions
install_packages
expire_temporary_accounts
initialize_aide
configure_sshd_kex
check_sudoers_include
check_umask
check_files_ownership
check_promiscuous_mode
check_ip_forwarding
check_icmp_redirects
check_source_route
configure_ssh
copy_and_fix_pam
disable_kdump_service
check_and_fix_fail_delay
check_syscall_auditing
check_and_fix_audit_log
