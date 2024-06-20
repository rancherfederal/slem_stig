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

# Function to verify that the "audit-audispd-plugins" package is installed and the "au-remote" plugin is enabled
check_audit_audispd_plugins() {
    local package_name="audit-audispd-plugins"

    echo "Checking if $package_name package is installed." >> "$LOGFILE"
    if ! zypper info "$package_name" | grep -q "Installed: Yes"; then
        echo "$package_name package is not installed. Installing it using transactional-update." >> "$LOGFILE"
        if transactional-update pkg install -y "$package_name" >> "$LOGFILE" 2>&1; then
            echo "Successfully installed $package_name." >> "$LOGFILE"
        else
            echo "Failed to install $package_name." >> "$LOGFILE"
        fi
    else
        echo "$package_name package is already installed." >> "$LOGFILE"
    fi

    echo "Verifying the 'au-remote' plugin is enabled." >> "$LOGFILE"
    if ! grep -q "^active = yes" /etc/audisp/plugins.d/au-remote.conf; then
        echo "'au-remote' plugin is not enabled. Enabling it." >> "$LOGFILE"
        transactional-update shell <<EOF
        sed -i "s/^active.*/active = yes/" /etc/audisp/plugins.d/au-remote.conf
        systemctl restart auditd
EOF
        echo "Enabled 'au-remote' plugin and restarted auditd." >> "$LOGFILE"
    else
        echo "'au-remote' plugin is already enabled." >> "$LOGFILE"
    fi

    if systemctl is-active --quiet auditd; then
        echo "auditd service is active." >> "$LOGFILE"
    else
        echo "Failed to restart auditd service." >> "$LOGFILE"
    fi
}

# Function to verify AIDE configuration for audit tools
check_aide_configuration() {
    local aide_config_file="/etc/aide.conf"
    local expected_entries=(
        "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+selinux+xattrs+sha512"
        "/usr/sbin/auditd p+i+n+u+g+s+b+acl+selinux+xattrs+sha512"
        "/usr/sbin/ausearch p+i+n+u+g+s+b+acl+selinux+xattrs+sha512"
        "/usr/sbin/aureport p+i+n+u+g+s+b+acl+selinux+xattrs+sha512"
        "/usr/sbin/autrace p+i+n+u+g+s+b+acl+selinux+xattrs+sha512"
        "/usr/sbin/audispd p+i+n+u+g+s+b+acl+selinux+xattrs+sha512"
        "/usr/sbin/augenrules p+i+n+u+g+s+b+acl+selinux+xattrs+sha512"
    )

    echo "Checking AIDE configuration for audit tools." >> "$LOGFILE"
    local missing_entries=()

    for entry in "${expected_entries[@]}"; do
        if ! grep -Fxq "$entry" "$aide_config_file"; then
            missing_entries+=("$entry")
        fi
    done

    if [ ${#missing_entries[@]} -eq 0 ]; then
        echo "AIDE is properly configured to protect the integrity of the audit tools." >> "$LOGFILE"
    else
        echo "AIDE is missing the following entries for audit tools:" >> "$LOGFILE"
        printf "%s\n" "${missing_entries[@]}" >> "$LOGFILE"
        
        transactional-update shell <<EOF
        for entry in "${missing_entries[@]}"; do
            echo "\$entry" >> $aide_config_file
        done
        exit
EOF

        echo "Added missing entries to $aide_config_file and restarting AIDE initialization." >> "$LOGFILE"
        transactional-update --continue-init
    fi
}

# Function to verify and fix permissions for SUSE audit tools
check_audit_tools_permissions() {
    local permissions_file="/etc/permissions.local"
    local expected_permissions=(
        "/usr/sbin/audispd root:root 0750"
        "/usr/sbin/auditctl root:root 0750"
        "/usr/sbin/auditd root:root 0750"
        "/usr/sbin/ausearch root:root 0755"
        "/usr/sbin/aureport root:root 0755"
        "/usr/sbin/autrace root:root 0750"
        "/usr/sbin/augenrules root:root 0750"
    )

    echo "Checking permissions in $permissions_file for audit tools." >> "$LOGFILE"
    local missing_permissions=()

    for permission in "${expected_permissions[@]}"; do
        if ! grep -Fxq "$permission" "$permissions_file"; then
            missing_permissions+=("$permission")
        fi
    done

    if [ ${#missing_permissions[@]} -eq 0 ]; then
        echo "All required permissions for audit tools are present in $permissions_file." >> "$LOGFILE"
    else
        echo "Missing the following permissions in $permissions_file:" >> "$LOGFILE"
        printf "%s\n" "${missing_permissions[@]}" >> "$LOGFILE"
        
        transactional-update shell <<EOF
        for permission in "${missing_permissions[@]}"; do
            echo "\$permission" >> $permissions_file
        done
        exit
EOF

        echo "Added missing permissions to $permissions_file." >> "$LOGFILE"
    fi

    echo "Verifying permissions using chkstat." >> "$LOGFILE"
    local chkstat_output
    chkstat_output=$(chkstat $permissions_file 2>&1)

    if [ -z "$chkstat_output" ]; then
        echo "All audit information files and folders have correct permissions." >> "$LOGFILE"
    else
        echo "Permissions issues found by chkstat:" >> "$LOGFILE"
        echo "$chkstat_output" >> "$LOGFILE"
        transactional-update shell <<EOF
        chkstat --system --set
        exit
EOF
        echo "Permissions fixed using chkstat." >> "$LOGFILE"
    fi
}

# Function to verify and fix permissions for audit rules
check_audit_rules_permissions() {
    local permissions_file="/etc/permissions.local"
    local expected_permissions=(
        "/var/log/audit root:root 600"
        "/var/log/audit/audit.log root:root 600"
        "/etc/audit/audit.rules root:root 640"
        "/etc/audit/rules.d/audit.rules root:root 640"
    )

    echo "Checking permissions in $permissions_file for audit rules." >> "$LOGFILE"
    local missing_permissions=()

    for permission in "${expected_permissions[@]}"; do
        if ! grep -iFxq "$permission" "$permissions_file"; then
            missing_permissions+=("$permission")
        fi
    done

    if [ ${#missing_permissions[@]} -eq 0 ]; then
        echo "All required permissions for audit rules are present in $permissions_file." >> "$LOGFILE"
    else
        echo "Missing the following permissions in $permissions_file:" >> "$LOGFILE"
        printf "%s\n" "${missing_permissions[@]}" >> "$LOGFILE"
        
        transactional-update shell <<EOF
for permission in "${missing_permissions[@]}"; do
    echo "\$permission" >> $permissions_file
done
EOF

        echo "Added missing permissions to $permissions_file." >> "$LOGFILE"
    fi

    echo "Verifying permissions using chkstat." >> "$LOGFILE"
    transactional-update shell <<EOF
chkstat --system --set >> "$LOGFILE" 2>&1
EOF

    local chkstat_output
    chkstat_output=$(chkstat $permissions_file 2>&1)

    if [ -z "$chkstat_output" ]; then
        echo "All audit information files and folders have correct permissions." >> "$LOGFILE"
    else
        echo "Permissions issues found by chkstat:" >> "$LOGFILE"
        echo "$chkstat_output" >> "$LOGFILE"
        transactional-update shell <<EOF
chkstat --system --set >> "$LOGFILE" 2>&1
EOF
        echo "Permissions fixed using chkstat." >> "$LOGFILE"
    fi
}

# Function to verify and fix the disk_full_action setting in auditd.conf
check_disk_full_action() {
    local auditd_conf_file="/etc/audit/auditd.conf"
    local valid_actions=("SYSLOG" "SINGLE" "HALT")

    echo "Checking disk_full_action setting in $auditd_conf_file." >> "$LOGFILE"
    local disk_full_action
    disk_full_action=$(grep -E "^disk_full_action" "$auditd_conf_file" | awk -F= '{print $2}' | xargs)

    if [[ ! " ${valid_actions[@]} " =~ " ${disk_full_action} " ]]; then
        echo "Invalid or missing disk_full_action setting: $disk_full_action" >> "$LOGFILE"
        
        transactional-update shell <<EOF
sed -i '/^disk_full_action/d' $auditd_conf_file
echo "disk_full_action = SYSLOG" >> $auditd_conf_file
EOF

        echo "Set disk_full_action to SYSLOG in $auditd_conf_file." >> "$LOGFILE"
    else
        echo "disk_full_action is correctly set to $disk_full_action." >> "$LOGFILE"
    fi
}

# Function to verify and fix aliases in /etc/aliases
check_aliases() {
    local aliases_file="/etc/aliases"
    local monitored_email="monitored@example.com"  # Replace with the actual monitored email account

    echo "Checking postmaster alias in $aliases_file." >> "$LOGFILE"
    local postmaster_alias
    postmaster_alias=$(grep -i "^postmaster:" "$aliases_file" | awk -F: '{print $2}' | xargs)

    if [ "$postmaster_alias" != "root" ]; then
        echo "Invalid or missing postmaster alias: $postmaster_alias" >> "$LOGFILE"
        
        transactional-update shell <<EOF
sed -i '/^postmaster:/d' $aliases_file
echo "postmaster: root" >> $aliases_file
EOF

        echo "Set postmaster alias to root in $aliases_file." >> "$LOGFILE"
    else
        echo "postmaster alias is correctly set to root." >> "$LOGFILE"
    fi

    echo "Checking root alias in $aliases_file." >> "$LOGFILE"
    local root_alias
    root_alias=$(grep -i "^root:" "$aliases_file" | awk -F: '{print $2}' | xargs)

    if [ "$root_alias" != "$monitored_email" ]; then
        echo "Invalid or missing root alias: $root_alias" >> "$LOGFILE"
        
        transactional-update shell <<EOF
sed -i '/^root:/d' $aliases_file
echo "root: $monitored_email" >> $aliases_file
EOF

        echo "Set root alias to $monitored_email in $aliases_file." >> "$LOGFILE"
    else
        echo "root alias is correctly set to $monitored_email." >> "$LOGFILE"
    fi

    echo "Reloading aliases database." >> "$LOGFILE"
    newaliases >> "$LOGFILE" 2>&1
}

# Function to verify and fix the action_mail_acct setting in auditd.conf
check_action_mail_acct() {
    local auditd_conf_file="/etc/audit/auditd.conf"
    local expected_account="root"

    echo "Checking action_mail_acct setting in $auditd_conf_file." >> "$LOGFILE"
    local action_mail_acct
    action_mail_acct=$(grep -E "^action_mail_acct" "$auditd_conf_file" | awk -F= '{print $2}' | xargs)

    if [ "$action_mail_acct" != "$expected_account" ]; then
        echo "Invalid or missing action_mail_acct setting: $action_mail_acct" >> "$LOGFILE"
        
        transactional-update shell <<EOF
sed -i '/^action_mail_acct/d' $auditd_conf_file
echo "action_mail_acct = $expected_account" >> $auditd_conf_file
exit
EOF

        echo "Set action_mail_acct to $expected_account in $auditd_conf_file." >> "$LOGFILE"
    else
        echo "action_mail_acct is correctly set to $expected_account." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "su" command
check_su_command_audit() {
    local audit_rule="-a always,exit -S all -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-priv_change"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'su' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/bin/su' > /dev/null; then
        echo "'su' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'su' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        systemctl restart auditd
        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'su' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "delete_module" system call
check_module_audit() {
    local audit_rule_b32="-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k moduleload"
    local audit_rule_b64="-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k moduleload"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'init_module' and 'finit_module' system calls are being audited." >> "$LOGFILE"
    local missing_rules=false

    if ! auditctl -l | grep -q "$audit_rule_b32"; then
        echo "Missing audit rule for 'init_module' and 'finit_module' system calls (b32)." >> "$LOGFILE"
        missing_rules=true
    fi

    if ! auditctl -l | grep -q "$audit_rule_b64"; then
        echo "Missing audit rule for 'init_module' and 'finit_module' system calls (b64)." >> "$LOGFILE"
        missing_rules=true
    fi

    if [ "$missing_rules" = true ]; then
        transactional-update shell <<EOF
echo "$audit_rule_b32" >> $audit_rules_file
echo "$audit_rule_b64" >> $audit_rules_file
exit
EOF

        echo "Added audit rules for 'init_module' and 'finit_module' system calls to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'init_module' and 'finit_module' system calls are already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "delete_module" system call
check_delete_module_audit() {
    local audit_rule_b32="-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -k unload_module"
    local audit_rule_b64="-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -k unload_module"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'delete_module' system call is being audited." >> "$LOGFILE"
    local missing_rules=false

    if ! auditctl -l | grep -q 'delete_module'; then
        echo "Missing audit rule for 'delete_module' system call." >> "$LOGFILE"
        missing_rules=true
    fi

    if [ "$missing_rules" = true ]; then
        transactional-update shell <<EOF
echo "$audit_rule_b32" >> $audit_rules_file
echo "$audit_rule_b64" >> $audit_rules_file
exit
EOF

        echo "Added audit rules for 'delete_module' system call to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'delete_module' system call is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "pam_timestamp_check" command
check_pam_timestamp_check_audit() {
    local audit_rule="-a always,exit -S all -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-pam_timestamp_check"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'pam_timestamp_check' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/sbin/pam_timestamp_check' > /dev/null; then
        echo "'pam_timestamp_check' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'pam_timestamp_check' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'pam_timestamp_check' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "usermod" command
check_usermod_audit() {
    local audit_rule="-a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-usermod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'usermod' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/sbin/usermod' > /dev/null; then
        echo "'usermod' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'usermod' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'usermod' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "passmass" command
check_passmass_audit() {
    local audit_rule="-a always,exit -S all -F path=/usr/bin/passmass -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-passmass"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'passmass' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/bin/passmass' > /dev/null; then
        echo "'passmass' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'passmass' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'passmass' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "lastlog" file
check_lastlog_audit() {
    local audit_rule="-w /var/log/lastlog -p wa -k logins"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'lastlog' file is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/var/log/lastlog' > /dev/null; then
        echo "'lastlog' file is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'lastlog' file to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'lastlog' file is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "tallylog" file
check_tallylog_audit() {
    local audit_rule="-w /var/log/tallylog -p wa -k logins"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'tallylog' file is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/var/log/tallylog' > /dev/null; then
        echo "'tallylog' file is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'tallylog' file to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'tallylog' file is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "rm" command
check_rm_audit() {
    local audit_rule="-a always,exit -S all -F path=/usr/bin/rm -F perm=x -F auid>=1000 -F auid!=-1 -k prim_mod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'rm' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/bin/rm' > /dev/null; then
        echo "'rm' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'rm' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'rm' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "chcon" command
check_chcon_audit() {
    local audit_rule="-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -k prim_mod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'chcon' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/bin/chcon' > /dev/null; then
        echo "'chcon' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'chcon' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'chcon' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "chacl" command
check_chacl_audit() {
    local audit_rule="-a always,exit -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -k prim_mod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'chacl' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/bin/chacl' > /dev/null; then
        echo "'chacl' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'chacl' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'chacl' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "setfacl" command
check_setfacl_audit() {
    local audit_rule="-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -k prim_mod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'setfacl' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/bin/setfacl' > /dev/null; then
        echo "'setfacl' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'setfacl' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'setfacl' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "chmod" command
check_chmod_audit() {
    local audit_rule="-a always,exit -S all -F path=/usr/bin/chmod -F perm=x -F auid>=1000 -F auid!=-1 -k prim_mod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'chmod' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/bin/chmod' > /dev/null; then
        echo "'chmod' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'chmod' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'chmod' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "kmod" command
check_kmod_audit() {
    local audit_rule="-w /usr/bin/kmod -p x -k modules"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'kmod' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/bin/kmod' > /dev/null; then
        echo "'kmod' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'kmod' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'kmod' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "modprobe" command
check_modprobe_audit() {
    local audit_rule="-w /sbin/modprobe -p x -k modules"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'modprobe' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/sbin/modprobe' > /dev/null; then
        echo "'modprobe' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'modprobe' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'modprobe' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "rmmod" command
check_rmmod_audit() {
    local audit_rule="-w /sbin/rmmod -p x -k modules"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'rmmod' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/sbin/rmmod' > /dev/null; then
        echo "'rmmod' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'rmmod' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'rmmod' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "insmod" command
check_insmod_audit() {
    local audit_rule="-w /sbin/insmod -p x -k modules"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'insmod' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/sbin/insmod' > /dev/null; then
        echo "'insmod' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'insmod' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'insmod' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "sudoedit" command
check_sudoedit_audit() {
    local audit_rule="-a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-sudoedit"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'sudoedit' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/bin/sudoedit' > /dev/null; then
        echo "'sudoedit' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'sudoedit' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'sudoedit' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "chmod", "fchmod", and "fchmodat" system calls
check_chmod_syscalls_audit() {
    local audit_rule_b32="-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod"
    local audit_rule_b64="-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'chmod', 'fchmod', and 'fchmodat' system calls are being audited." >> "$LOGFILE"
    local missing_rules=false

    if ! auditctl -l | grep -q 'chmod'; then
        echo "Missing audit rule for 'chmod', 'fchmod', and 'fchmodat' system calls." >> "$LOGFILE"
        missing_rules=true
    fi

    if [ "$missing_rules" = true ]; then
        transactional-update shell <<EOF
echo "$audit_rule_b32" >> $audit_rules_file
echo "$audit_rule_b64" >> $audit_rules_file
exit
EOF

        echo "Added audit rules for 'chmod', 'fchmod', and 'fchmodat' system calls to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'chmod', 'fchmod', and 'fchmodat' system calls are already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" system calls
check_xattr_syscalls_audit() {
    local audit_rule_b32="-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod"
    local audit_rule_b64="-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'setxattr', 'fsetxattr', 'lsetxattr', 'removexattr', 'fremovexattr', and 'lremovexattr' system calls are being audited." >> "$LOGFILE"
    local missing_rules=false

    if ! auditctl -l | grep -q 'xattr'; then
        echo "Missing audit rule for 'setxattr', 'fsetxattr', 'lsetxattr', 'removexattr', 'fremovexattr', and 'lremovexattr' system calls." >> "$LOGFILE"
        missing_rules=true
    fi

    if [ "$missing_rules" = true ]; then
        transactional-update shell <<EOF
echo "$audit_rule_b32" >> $audit_rules_file
echo "$audit_rule_b64" >> $audit_rules_file
exit
EOF

        echo "Added audit rules for 'setxattr', 'fsetxattr', 'lsetxattr', 'removexattr', 'fremovexattr', and 'lremovexattr' system calls to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'setxattr', 'fsetxattr', 'lsetxattr', 'removexattr', 'fremovexattr', and 'lremovexattr' system calls are already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" system calls
check_open_truncate_syscalls_audit() {
    local audit_rule_b32_perm="-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k perm_access"
    local audit_rule_b64_perm="-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k perm_access"
    local audit_rule_b32_acces="-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k perm_access"
    local audit_rule_b64_acces="-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k perm_access"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'creat', 'open', 'openat', 'open_by_handle_at', 'truncate', and 'ftruncate' system calls are being audited." >> "$LOGFILE"
    local missing_rules=false

    if ! auditctl -l | grep -q 'open\|truncate\|creat'; then
        echo "Missing audit rule for 'creat', 'open', 'openat', 'open_by_handle_at', 'truncate', and 'ftruncate' system calls." >> "$LOGFILE"
        missing_rules=true
    fi

    if [ "$missing_rules" = true ]; then
        transactional-update shell <<EOF
echo "$audit_rule_b32_perm" >> $audit_rules_file
echo "$audit_rule_b64_perm" >> $audit_rules_file
echo "$audit_rule_b32_acces" >> $audit_rules_file
echo "$audit_rule_b64_acces" >> $audit_rules_file
exit
EOF

        echo "Added audit rules for 'creat', 'open', 'openat', 'open_by_handle_at', 'truncate', and 'ftruncate' system calls to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'creat', 'open', 'openat', 'open_by_handle_at', 'truncate', and 'ftruncate' system calls are already being audited." >> "$LOGFILE"
    fi
}

# Function to configure audit rules for access to /etc/sudoers and /etc/sudoers.d/
configure_sudoers_audit() {
    local audit_rule_sudoers="-w /etc/sudoers -p wa -k privileged-actions"
    local audit_rule_sudoers_d="-w /etc/sudoers.d -p wa -k privileged-actions"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if access to '/etc/sudoers' and '/etc/sudoers.d/' is being audited." >> "$LOGFILE"
    local missing_rules=false

    if ! auditctl -l | grep -q '/etc/sudoers'; then
        echo "Missing audit rule for '/etc/sudoers'." >> "$LOGFILE"
        missing_rules=true
    fi

    if ! auditctl -l | grep -q '/etc/sudoers.d'; then
        echo "Missing audit rule for '/etc/sudoers.d/'." >> "$LOGFILE"
        missing_rules=true
    fi

    if [ "$missing_rules" = true ]; then
        transactional-update shell <<EOF
echo "$audit_rule_sudoers" >> $audit_rules_file
echo "$audit_rule_sudoers_d" >> $audit_rules_file
exit
EOF

        echo "Added audit rules for '/etc/sudoers' and '/etc/sudoers.d/' to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'/etc/sudoers' and '/etc/sudoers.d/' are already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "crontab" command
check_crontab_audit() {
    local audit_rule="-a always,exit -S all -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-crontab"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'crontab' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/bin/crontab' > /dev/null; then
        echo "'crontab' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'crontab' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'crontab' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "chage" command
check_chage_audit() {
    local audit_rule="-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-chage"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'chage' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/bin/chage' > /dev/null; then
        echo "'chage' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'chage' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'chage' command is already being audited." >> "$LOGFILE"
    fi
}

check_unix_chkpwd_audit() {
    local audit_rule_unix_chkpwd="-a always,exit -S all -F path=/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-unix-chkpwd"
    local audit_rule_unix2_chkpwd="-a always,exit -S all -F path=/sbin/unix2_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-unix2-chkpwd"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'unix_chkpwd' and 'unix2_chkpwd' commands are being audited." >> "$LOGFILE"
    if ! auditctl -l | egrep -w "(unix_chkpwd|unix2_chkpwd)" > /dev/null; then
        echo "'unix_chkpwd' or 'unix2_chkpwd' commands are not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule_unix_chkpwd" >> $audit_rules_file
echo "$audit_rule_unix2_chkpwd" >> $audit_rules_file
exit
EOF

        echo "Added audit rules for 'unix_chkpwd' and 'unix2_chkpwd' commands to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'unix_chkpwd' and 'unix2_chkpwd' commands are already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "passwd" command
check_passwd_audit() {
    local audit_rule="-a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-passwd"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if the 'passwd' command is being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/usr/bin/passwd' > /dev/null; then
        echo "'passwd' command is not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for 'passwd' command to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "'passwd' command is already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix the status and enablement of the auditd service
check_auditd_service() {
    echo "Checking if the 'auditd' service is active and enabled." >> "$LOGFILE"
    
    local service_status=$(systemctl is-active auditd.service)
    local service_enabled=$(systemctl is-enabled auditd.service)

    if [ "$service_status" != "active" ] || [ "$service_enabled" != "enabled" ]; then
        echo "'auditd' service is not active or not enabled." >> "$LOGFILE"

        transactional-update shell <<EOF
systemctl enable auditd.service
systemctl start auditd.service
exit
EOF

        echo "Enabled and started the 'auditd' service." >> "$LOGFILE"

        # Verify the changes
        service_status=$(systemctl is-active auditd.service)
        service_enabled=$(systemctl is-enabled auditd.service)

        if [ "$service_status" == "active" ] && [ "$service_enabled" == "enabled" ]; then
            echo "'auditd' service is now active and enabled." >> "$LOGFILE"
        else
            echo "Failed to activate or enable the 'auditd' service." >> "$LOGFILE"
        fi
    else
        echo "'auditd' service is already active and enabled." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "/etc/gshadow" file
check_gshadow_audit() {
    local audit_rule="-w /etc/gshadow -p wa -k account_mod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if modifications to '/etc/gshadow' are being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/etc/gshadow' > /dev/null; then
        echo "Modifications to '/etc/gshadow' are not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for '/etc/gshadow' to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "Modifications to '/etc/gshadow' are already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "/etc/security/opasswd" file
check_opasswd_audit() {
    local audit_rule="-w /etc/security/opasswd -p wa -k account_mod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if modifications to '/etc/security/opasswd' are being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/etc/security/opasswd' > /dev/null; then
        echo "Modifications to '/etc/security/opasswd' are not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for '/etc/security/opasswd' to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "Modifications to '/etc/security/opasswd' are already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "/etc/shadow" file
check_shadow_audit() {
    local audit_rule="-w /etc/shadow -p wa -k account_mod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if modifications to '/etc/shadow' are being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/etc/shadow' > /dev/null; then
        echo "Modifications to '/etc/shadow' are not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for '/etc/shadow' to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "Modifications to '/etc/shadow' are already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "/etc/group" file
check_group_audit() {
    local audit_rule="-w /etc/group -p wa -k account_mod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if modifications to '/etc/group' are being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/etc/group' > /dev/null; then
        echo "Modifications to '/etc/group' are not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for '/etc/group' to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "Modifications to '/etc/group' are already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix audit rules for the "/etc/passwd" file
check_passwd_audit() {
    local audit_rule="-w /etc/passwd -p wa -k account_mod"
    local audit_rules_file="/etc/audit/rules.d/audit.rules"

    echo "Checking if modifications to '/etc/passwd' are being audited." >> "$LOGFILE"
    if ! auditctl -l | grep -w '/etc/passwd' > /dev/null; then
        echo "Modifications to '/etc/passwd' are not being audited or audit rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$audit_rule" >> $audit_rules_file
exit
EOF

        echo "Added audit rule for '/etc/passwd' to $audit_rules_file." >> "$LOGFILE"

        # Restart the auditd service to apply the changes
        transactional-update shell <<EOF
systemctl restart auditd
exit
EOF

        if systemctl is-active --quiet auditd; then
            echo "auditd service restarted successfully." >> "$LOGFILE"
        else
            echo "Failed to restart auditd service." >> "$LOGFILE"
        fi
    else
        echo "Modifications to '/etc/passwd' are already being audited." >> "$LOGFILE"
    fi
}

# Function to verify and fix the use of pam_cracklib for preventing dictionary words in passwords
check_pam_cracklib() {
    local pam_file="/etc/pam.d/common-password"
    local pam_rule="password requisite pam_cracklib.so"

    echo "Checking if 'pam_cracklib.so' is being used to prevent dictionary words in passwords." >> "$LOGFILE"
    if ! grep -q 'pam_cracklib.so' "$pam_file"; then
        echo "'pam_cracklib.so' is not being used or the rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
echo "$pam_rule" >> $pam_file
exit
EOF

        echo "Added pam_cracklib rule to $pam_file." >> "$LOGFILE"
    else
        echo "'pam_cracklib.so' is already being used to prevent dictionary words in passwords." >> "$LOGFILE"
    fi
}

# Function to verify and fix the enforcement of password complexity by requiring at least one special character
check_pam_cracklib_special_char() {
    local pam_file="/etc/pam.d/common-password"
    local pam_rule="password requisite pam_cracklib.so ocredit=-1"

    echo "Checking if 'pam_cracklib.so' enforces password complexity by requiring at least one special character." >> "$LOGFILE"
    if ! grep -q 'password .* pam_cracklib.so .* ocredit=-1' "$pam_file"; then
        echo "'pam_cracklib.so' is not enforcing password complexity or the rule is missing." >> "$LOGFILE"
        
        transactional-update shell <<EOF
sed -i '/pam_cracklib.so/d' $pam_file
echo "$pam_rule" >> $pam_file
exit
EOF

        echo "Added pam_cracklib rule with ocredit=-1 to $pam_file." >> "$LOGFILE"
    else
        echo "'pam_cracklib.so' is already enforcing password complexity by requiring at least one special character." >> "$LOGFILE"
    fi
}

# Call the function
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
check_audit_audispd_plugins
check_aide_configuration
check_audit_tools_permissions
check_audit_rules_permissions
check_disk_full_action
check_aliases
check_action_mail_acct
check_su_command_audit
check_module_audit
check_delete_module_audit
check_pam_timestamp_check_audit
check_usermod_audit
check_passmass_audit
check_lastlog_audit
check_tallylog_audit
check_rm_audit
check_chcon_audit
check_chacl_audit
check_setfacl_audit
check_chmod_audit
check_kmod_audit
check_modprobe_audit
check_rmmod_audit
check_insmod_audit
check_sudoedit_audit
check_chmod_syscalls_audit
check_xattr_syscalls_audit
check_open_truncate_syscalls_audit
configure_sudoers_audit
check_crontab_audit
check_chage_audit
check_unix_chkpwd_audit
check_passwd_audit
check_auditd_service
check_gshadow_audit
check_opasswd_audit
check_shadow_audit
check_group_audit
check_passwd_audit
check_pam_cracklib
check_pam_cracklib_special_char
