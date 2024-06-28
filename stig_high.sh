#!/bin/bash

LOGFILE="stig_high.log"

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

# Function to check if SLEM 5 is vendor supported
check_slem_version() {
    local function_name="check_slem_version"
    local vuln_id="V-261263"
    local rule_id="SV-261263r996826"

    local os_release_info
    os_release_info=$(cat /etc/os-release)

    local name
    local version
    name=$(echo "$os_release_info" | grep '^NAME=' | cut -d '=' -f 2 | tr -d '"')
    version=$(echo "$os_release_info" | grep '^VERSION=' | cut -d '=' -f 2 | tr -d '"')

    if [[ "$name" == "SLE Micro" && "$version" == "5.2" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SLEM 5 version is supported."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Installed version of SLEM 5 is not supported. This is a finding."
    fi
}

# Function to disable the Ctrl-Alt-Delete sequence for the command line
disable_ctrl_alt_del() {
    local function_name="disable_ctrl_alt_del"
    local vuln_id="V-261266"
    local rule_id="SV-261266r996292"

    local disable_status
    local mask_status
    disable_status=$(systemctl is-enabled ctrl-alt-del.target)
    mask_status=$(systemctl is-enabled ctrl-alt-del.target)

    if [[ "$disable_status" == "disabled" && "$mask_status" == "masked" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Ctrl-Alt-Delete sequence is already disabled and masked."
    else
        sudo systemctl disable ctrl-alt-del.target
        sudo systemctl mask ctrl-alt-del.target
        sudo systemctl daemon-reload

        disable_status=$(systemctl is-enabled ctrl-alt-del.target)
        mask_status=$(systemctl is-enabled ctrl-alt-del.target)

        if [[ "$disable_status" == "disabled" && "$mask_status" == "masked" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Ctrl-Alt-Delete sequence has been disabled and masked successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to disable and mask the Ctrl-Alt-Delete sequence. This is a finding."
        fi
    fi
}

# Function to check if SLEM 5 has set an encrypted root password in grub.cfg
check_encrypted_root_password() {
    local function_name="check_encrypted_root_password"
    local vuln_id="V-261267"
    local rule_id="SV-261267r996295"
    
    if [[ -d /sys/firmware/efi ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "System uses EFI, BIOS requirement is not applicable."
        return
    fi

    local grub_password_entry
    grub_password_entry=$(sudo cat /boot/grub2/grub.cfg | grep -i password)

    if [[ "$grub_password_entry" == password_pbkdf2* ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Encrypted root password is correctly set in grub.cfg."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Encrypted root password is not set correctly in grub.cfg. This is a finding."
    fi
}

# Function to configure SLEM 5 to encrypt the boot password
configure_boot_password_encryption() {
    local function_name="configure_boot_password_encryption"
    local vuln_id="V-261268"
    local rule_id="SV-261268r996298"
    
    if [[ ! -d /sys/firmware/efi ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "System does not use UEFI, requirement is not applicable."
        return
    fi

    local grub_password_hash
    grub_password_hash=$(echo "password" | grub2-mkpasswd-pbkdf2 | grep -oP '(?<=is ).*')
    if [[ -z "$grub_password_hash" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to generate GRUB bootloader password hash."
        return
    fi

    sudo sed -i '/^set superusers=/d' /etc/grub.d/40_custom
    sudo sed -i '/^password_pbkdf2/d' /etc/grub.d/40_custom
    echo "set superusers=\"root\"" | sudo tee -a /etc/grub.d/40_custom
    echo "password_pbkdf2 root $grub_password_hash" | sudo tee -a /etc/grub.d/40_custom

    sudo grub2-mkconfig --output=/tmp/grub2.cfg
    sudo mv /tmp/grub2.cfg /boot/efi/EFI/BOOT/grub.cfg

    local grub_config
    grub_config=$(sudo cat /boot/efi/EFI/BOOT/grub.cfg | grep -i password_pbkdf2)

    if [[ "$grub_config" == *password_pbkdf2* ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Boot password encryption configured successfully."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure boot password encryption. This is a finding."
    fi
}

# Function to configure SLEM 5 tool zypper to enable gpgcheck
configure_zypper_gpgcheck() {
    local function_name="configure_zypper_gpgcheck"
    local vuln_id="V-261274"
    local rule_id="SV-261274r996312"

    local zypp_conf_file="/etc/zypp/zypp.conf"
    local gpgcheck_setting="gpgcheck = on"

    if grep -q "^gpgcheck = on" "$zypp_conf_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "gpgcheck is already enabled in zypp.conf."
    else
        if grep -q "^gpgcheck" "$zypp_conf_file"; then
            sudo sed -i 's/^gpgcheck.*/gpgcheck = on/' "$zypp_conf_file"
        else
            echo "$gpgcheck_setting" | sudo tee -a "$zypp_conf_file"
        fi

        if grep -q "^gpgcheck = on" "$zypp_conf_file"; then
            log_message "$function_name" "$vuln_id" "$rule_id" "gpgcheck has been enabled in zypp.conf."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to enable gpgcheck in zypp.conf. This is a finding."
        fi
    fi
}

# Function to verify the telnet-server package is not installed
verify_telnet_server_not_installed() {
    local function_name="verify_telnet_server_not_installed"
    local vuln_id="V-261277"
    local rule_id="SV-261277r996318"

    if sudo zypper se telnet-server | grep -q "Installed"; then
        sudo zypper remove -y telnet-server
        if sudo zypper se telnet-server | grep -q "Installed"; then
            log_message "$function_name" "$vuln_id" "$rule_id" "telnet-server package is installed and could not be removed. This is a finding."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "telnet-server package was installed but has been removed successfully."
        fi
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "telnet-server package is not installed."
    fi
}

# Function to verify disk encryption and FIPS mode
verify_disk_encryption_and_fips_mode() {
    local function_name="verify_disk_encryption_and_fips_mode"
    local vuln_id="V-261284"
    local rule_id="SV-261284r996333"

    local unencrypted_partitions
    unencrypted_partitions=$(sudo blkid | grep -v -e "crypto_LUKS" -e "/boot" -e "tmpfs" -e "/proc" -e "/sys")
    if [[ -n "$unencrypted_partitions" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Unencrypted partitions found: $unencrypted_partitions. This is a finding."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "All partitions are encrypted with crypto_LUKS."
    fi

    if [[ ! -f /etc/crypttab ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "/etc/crypttab file does not exist. This is a finding."
    else
        local missing_crypttab_entries
        for uuid in $(sudo blkid | grep "crypto_LUKS" | awk -F\" '{print $2}'); do
            if ! grep -q "$uuid" /etc/crypttab; then
                missing_crypttab_entries+="$uuid "
            fi
        done
        
        if [[ -n "$missing_crypttab_entries" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "Missing entries in /etc/crypttab for UUIDs: $missing_crypttab_entries. This is a finding."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "All crypto_LUKS partitions have entries in /etc/crypttab."
        fi
    fi

    local fips_enabled
    fips_enabled=$(sudo sysctl -a | grep -w "crypto.fips_enabled" | awk '{print $3}')

    if [[ "$fips_enabled" -eq 1 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "System is running in FIPS mode."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "System is not running in FIPS mode. This is a finding."
    fi
}

# Function to verify the SSH package is installed
verify_ssh_package_installed() {
    local function_name="verify_ssh_package_installed"
    local vuln_id="V-261327"
    local rule_id="SV-261327r996450"

    local openssh_installed
    openssh_installed=$(zypper info openssh | grep -i "Installed" | awk '{print $3}')

    if [[ "$openssh_installed" == "Yes" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "openssh package is installed."
    else
        sudo zypper install -y openssh
        openssh_installed=$(zypper info openssh | grep -i "Installed" | awk '{print $3}')
        if [[ "$openssh_installed" == "Yes" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "openssh package was not installed but has been installed successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "openssh package is not installed and could not be installed. This is a finding."
        fi
    fi
}

# Function to enable and start the openssh service
enable_and_start_openssh_service() {
    local function_name="enable_and_start_openssh_service"
    local vuln_id="V-261328"
    local rule_id="SV-261328r996453"

    local sshd_enabled
    sshd_enabled=$(systemctl is-enabled sshd.service)
    if [[ "$sshd_enabled" == "enabled" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "sshd.service is already enabled."
    else
        sudo systemctl enable sshd.service
        sshd_enabled=$(systemctl is-enabled sshd.service)
        
        if [[ "$sshd_enabled" == "enabled" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "sshd.service has been enabled successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to enable sshd.service. This is a finding."
        fi
    fi

    sudo systemctl restart sshd.service
    local sshd_active
    sshd_active=$(systemctl is-active sshd.service)
    if [[ "$sshd_active" == "active" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "sshd.service is running."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to start sshd.service. This is a finding."
    fi
}

# Function to configure SSH to disable unattended or automatic logon
configure_ssh_no_unattended_logon() {
    local function_name="configure_ssh_no_unattended_logon"
    local vuln_id="V-261330"
    local rule_id="SV-261330r996457"

    local sshd_config_file="/etc/ssh/sshd_config"
    local permit_empty_passwords="PermitEmptyPasswords no"
    local permit_user_environment="PermitUserEnvironment no"
    
    if grep -q "^PermitEmptyPasswords" "$sshd_config_file"; then
        sudo sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$sshd_config_file"
    else
        echo "$permit_empty_passwords" | sudo tee -a "$sshd_config_file"
    fi

    if grep -q "^PermitUserEnvironment" "$sshd_config_file"; then
        sudo sed -i 's/^PermitUserEnvironment.*/PermitUserEnvironment no/' "$sshd_config_file"
    else
        echo "$permit_user_environment" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service
    
    local permit_empty_passwords_applied
    local permit_user_environment_applied
    permit_empty_passwords_applied=$(grep "^PermitEmptyPasswords no" "$sshd_config_file")
    permit_user_environment_applied=$(grep "^PermitUserEnvironment no" "$sshd_config_file")
    
    if [[ -n "$permit_empty_passwords_applied" && -n "$permit_user_environment_applied" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH configuration to disable unattended or automatic logon is correctly applied."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to apply SSH configuration to disable unattended or automatic logon. This is a finding."
    fi
}

configure_ssh_fips_approved_ciphers() {
    local function_name="configure_ssh_fips_approved_ciphers"
    local vuln_id="V-261334"
    local rule_id="SV-261334r996467"

    local sshd_config_file="/etc/ssh/sshd_config"
    local fips_ciphers="Ciphers aes256-ctr,aes192-ctr,aes128-ctr"
    
    if grep -q "^Ciphers" "$sshd_config_file"; then
        sudo sed -i 's/^Ciphers.*/'"$fips_ciphers"'/' "$sshd_config_file"
    else
        echo "$fips_ciphers" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service
    
    local ciphers_applied
    ciphers_applied=$(grep "^Ciphers" "$sshd_config_file")
    
    if [[ "$ciphers_applied" == "$fips_ciphers" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH server is configured to use only FIPS 140-2/140-3 approved ciphers."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure SSH server to use only FIPS 140-2/140-3 approved ciphers. This is a finding."
    fi
}

# Function to configure SSH to use only FIPS 140-2/140-3 approved MACs
configure_ssh_fips_approved_macs() {
    local function_name="configure_ssh_fips_approved_macs"
    local vuln_id="V-261335"
    local rule_id="SV-261335r996469"

    local sshd_config_file="/etc/ssh/sshd_config"
    local fips_macs="MACs hmac-sha2-512,hmac-sha2-256"
    
    if grep -q "^MACs" "$sshd_config_file"; then
        sudo sed -i 's/^MACs.*/'"$fips_macs"'/' "$sshd_config_file"
    else
        echo "$fips_macs" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service
    
    local macs_applied
    macs_applied=$(grep "^MACs" "$sshd_config_file")
    
    if [[ "$macs_applied" == "$fips_macs" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH daemon is configured to use only FIPS 140-2/140-3 approved MACs."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure SSH daemon to use only FIPS 140-2/140-3 approved MACs. This is a finding."
    fi
}

# Function to configure SSH to use only FIPS 140-2/140-3 validated key exchange algorithms
configure_ssh_fips_approved_kex_algorithms() {
    local function_name="configure_ssh_fips_approved_kex_algorithms"
    local vuln_id="V-261336"
    local rule_id="SV-261336r996472"

    local sshd_config_file="/etc/ssh/sshd_config"
    local fips_kex_algorithms="KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256"
    
    if grep -q "^KexAlgorithms" "$sshd_config_file"; then
        sudo sed -i 's/^KexAlgorithms.*/'"$fips_kex_algorithms"'/' "$sshd_config_file"
    else
        echo "$fips_kex_algorithms" | sudo tee -a "$sshd_config_file"
    fi

    sudo systemctl restart sshd.service
    
    local kex_algorithms_applied
    kex_algorithms_applied=$(grep "^KexAlgorithms" "$sshd_config_file")
    
    if [[ "$kex_algorithms_applied" == "$fips_kex_algorithms" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "SSH server is configured to use only FIPS 140-2/140-3 validated key exchange algorithms."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to configure SSH server to use only FIPS 140-2/140-3 validated key exchange algorithms. This is a finding."
    fi
}

# Function to remove any .shosts files found
remove_shosts_files() {
    local function_name="remove_shosts_files"
    local vuln_id="V-261343"
    local rule_id="SV-261343r996489"

    local shosts_files
    shosts_files=$(find / -name ".shosts" 2>/dev/null)

    if [[ -n "$shosts_files" ]]; then
        for file in $shosts_files; do
            sudo rm -f "$file"
        done

        local remaining_shosts_files
        remaining_shosts_files=$(find / -name ".shosts" 2>/dev/null)

        if [[ -z "$remaining_shosts_files" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" ".shosts files found and removed successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to remove some .shosts files. This is a finding."
        fi
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "No .shosts files found."
    fi
}

# Function to remove any shosts.equiv files found
remove_shosts_equiv_files() {
    local function_name="remove_shosts_equiv_files"
    local vuln_id="V-261344"
    local rule_id="SV-261344r996490"

    local shosts_equiv_files
    shosts_equiv_files=$(find / -name "shosts.equiv" 2>/dev/null)

    if [[ -n "$shosts_equiv_files" ]]; then
        for file in $shosts_equiv_files; do
            sudo rm -f "$file"
        done

        local remaining_shosts_equiv_files
        remaining_shosts_equiv_files=$(find / -name "shosts.equiv" 2>/dev/null)

        if [[ -z "$remaining_shosts_equiv_files" ]]; then
            log_message "$function_name" "$vuln_id" "$rule_id" "shosts.equiv files found and removed successfully."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to remove some shosts.equiv files. This is a finding."
        fi
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "No shosts.equiv files found."
    fi
}

# Function to configure GUI to not allow unattended or automatic logon
configure_gui_no_unattended_logon() {
    local function_name="configure_gui_no_unattended_logon"
    local vuln_id="V-261345"
    local rule_id="SV-261345r996493"

    local displaymanager_config_file="/etc/sysconfig/displaymanager"
    local autologin_setting="DISPLAYMANAGER_AUTOLOGIN=\"\""
    local password_less_login_setting="DISPLAYMANAGER_PASSWORD_LESS_LOGIN=\"no\""
    
    if [[ ! -f "$displaymanager_config_file" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "/etc/sysconfig/displaymanager file does not exist. This requirement is not applicable."
        return
    fi

    if grep -q "^DISPLAYMANAGER_AUTOLOGIN" "$displaymanager_config_file"; then
        sudo sed -i 's/^DISPLAYMANAGER_AUTOLOGIN.*/'"$autologin_setting"'/' "$displaymanager_config_file"
    else
        echo "$autologin_setting" | sudo tee -a "$displaymanager_config_file"
    fi

    if grep -q "^DISPLAYMANAGER_PASSWORD_LESS_LOGIN" "$displaymanager_config_file"; then
        sudo sed -i 's/^DISPLAYMANAGER_PASSWORD_LESS_LOGIN.*/'"$password_less_login_setting"'/' "$displaymanager_config_file"
    else
        echo "$password_less_login_setting" | sudo tee -a "$displaymanager_config_file"
    fi

    local autologin_applied
    local password_less_login_applied
    autologin_applied=$(grep "^DISPLAYMANAGER_AUTOLOGIN" "$displaymanager_config_file")
    password_less_login_applied=$(grep "^DISPLAYMANAGER_PASSWORD_LESS_LOGIN" "$displaymanager_config_file")
    
    if [[ "$autologin_applied" == "$autologin_setting" && "$password_less_login_applied" == "$password_less_login_setting" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "GUI configuration to disable unattended or automatic logon is correctly applied."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to apply GUI configuration to disable unattended or automatic logon. This is a finding."
    fi
}

# Function to change the UID of any non-root account with UID 0
change_non_root_uid_zero() {
    local function_name="change_non_root_uid_zero"
    local vuln_id="V-261359"
    local rule_id="SV-261359r996526"

    local non_root_uid_zero_accounts
    non_root_uid_zero_accounts=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)

    if [[ -n "$non_root_uid_zero_accounts" ]]; then
        for account in $non_root_uid_zero_accounts; do
            local current_uid
            current_uid=$(id -u "$account")
            local new_uid

            if [[ "$account" =~ ^(system_account_pattern)$ ]]; then
                new_uid=$(awk -F: '($3 >= 1 && $3 < 1000) {if ($3 > max) max=$3} END {print max+1}' /etc/passwd)
            else
                new_uid=$(awk -F: '($3 >= 1000) {if ($3 > max) max=$3} END {print max+1}' /etc/passwd)
            fi

            sudo usermod -u "$new_uid" "$account"
            if [[ $? -eq 0 ]]; then
                log_message "$function_name" "$vuln_id" "$rule_id" "Changed UID of account '$account' from $current_uid to $new_uid."
            else
                log_message "$function_name" "$vuln_id" "$rule_id" "Failed to change UID of account '$account' from $current_uid. This is a finding."
            fi
        done
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "No non-root accounts with UID 0 found."
    fi
}

# Function to configure SLEM 5 to not allow blank or null passwords
configure_no_blank_passwords() {
    local function_name="configure_no_blank_passwords"
    local vuln_id="V-261386"
    local rule_id="SV-261386r996587"

    local pam_files=("/etc/pam.d/common-auth" "/etc/pam.d/common-password")

    for pam_file in "${pam_files[@]}"; do
        if grep -q "nullok" "$pam_file"; then
            sudo sed -i 's/nullok//g' "$pam_file"

            if grep -q "nullok" "$pam_file"; then
                log_message "$function_name" "$vuln_id" "$rule_id" "Failed to remove 'nullok' from $pam_file. This is a finding."
            else
                log_message "$function_name" "$vuln_id" "$rule_id" "'nullok' option removed from $pam_file successfully."
            fi
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "'nullok' option not found in $pam_file."
        fi
    done
}

# Function to ensure all accounts have a password or are locked
ensure_accounts_have_password_or_locked() {
    local function_name="ensure_accounts_have_password_or_locked"
    local vuln_id="V-261387"
    local rule_id="SV-261387r996588"

    local no_password_accounts
    no_password_accounts=$(awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1}' /etc/shadow)

    if [[ -n "$no_password_accounts" ]]; then
        for account in $no_password_accounts; do
            if [[ "$account" != "root" && "$account" != "" ]]; then
                sudo passwd -l "$account"

                if [[ $? -eq 0 ]]; then
                    log_message "$function_name" "$vuln_id" "$rule_id" "Account '$account' has been locked successfully."
                else
                    log_message "$function_name" "$vuln_id" "$rule_id" "Failed to lock account '$account'. This is a finding."
                fi
            fi
        done
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "All accounts have a password or are already locked."
    fi
}

# Function to configure password encryption method to SHA512 and lock accounts not using SHA512
configure_password_encryption_sha512() {
    local function_name="configure_password_encryption_sha512"
    local vuln_id="V-261391"
    local rule_id="SV-261391r996598"

    local login_defs_file="/etc/login.defs"
    local encrypt_method="ENCRYPT_METHOD SHA512"

    if grep -q "^ENCRYPT_METHOD" "$login_defs_file"; then
        sudo sed -i 's/^ENCRYPT_METHOD.*/'"$encrypt_method"'/' "$login_defs_file"
    else
        echo "$encrypt_method" | sudo tee -a "$login_defs_file"
    fi

    local encrypt_method_applied
    encrypt_method_applied=$(grep "^ENCRYPT_METHOD" "$login_defs_file")

    if [[ "$encrypt_method_applied" == "$encrypt_method" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Password encryption method set to SHA512 in $login_defs_file."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set password encryption method to SHA512 in $login_defs_file. This is a finding."
    fi

    local non_sha512_accounts
    non_sha512_accounts=$(awk -F: '($2 !~ /^\$6\$/) {print $1}' /etc/shadow)

    if [[ -n "$non_sha512_accounts" ]]; then
        for account in $non_sha512_accounts; do
            if [[ "$account" != "root" && "$account" != "" ]]; then
                sudo passwd -l "$account"

                if [[ $? -eq 0 ]]; then
                    log_message "$function_name" "$vuln_id" "$rule_id" "Account '$account' using non-SHA512 hashing has been locked successfully."
                else
                    log_message "$function_name" "$vuln_id" "$rule_id" "Failed to lock account '$account' using non-SHA512 hashing. This is a finding."
                fi
            fi
        done
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "All accounts are using SHA512 hashing."
    fi
}

# Function to configure shadow password suite to use sufficient number of hashing rounds
configure_password_hashing_rounds() {
    local function_name="configure_password_hashing_rounds"
    local vuln_id="V-261392"
    local rule_id="SV-261392r996600"

    local login_defs_file="/etc/login.defs"
    local min_rounds="SHA_CRYPT_MIN_ROUNDS 5000"

    if grep -q "^SHA_CRYPT_MIN_ROUNDS" "$login_defs_file"; then
        sudo sed -i 's/^SHA_CRYPT_MIN_ROUNDS.*/'"$min_rounds"'/' "$login_defs_file"
    else
        echo "$min_rounds" | sudo tee -a "$login_defs_file"
    fi

    local rounds_applied
    rounds_applied=$(grep "^SHA_CRYPT_MIN_ROUNDS" "$login_defs_file")

    if [[ "$rounds_applied" == "$min_rounds" ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "Password hashing rounds set to 5000 in $login_defs_file."
    else
        log_message "$function_name" "$vuln_id" "$rule_id" "Failed to set password hashing rounds to 5000 in $login_defs_file. This is a finding."
    fi
}

# Function to configure SLEM 5 to run in FIPS mode
configure_fips_mode() {
    local function_name="configure_fips_mode"
    local vuln_id="V-261473"
    local rule_id="SV-261473r996824"

    local grub_cfg_file="/etc/default/grub"
    local kernel_params="fips=1"
    
    local fips_enabled
    fips_enabled=$(sudo sysctl -a | grep -w "crypto.fips_enabled" | awk '{print $3}')

    if [[ "$fips_enabled" -eq 1 ]]; then
        log_message "$function_name" "$vuln_id" "$rule_id" "System is already running in FIPS mode."
        return
    fi

    if grep -q "fips=1" "$grub_cfg_file"; then
        log_message "$function_name" "$vuln_id" "$rule_id" "fips=1 is already added to the kernel parameters."
    else
        sudo sed -i 's/GRUB_CMDLINE_LINUX="/&fips=1 /' "$grub_cfg_file"
        sudo grub2-mkconfig -o /boot/grub2/grub.cfg

        if grep -q "fips=1" /boot/grub2/grub.cfg; then
            log_message "$function_name" "$vuln_id" "$rule_id" "fips=1 added to kernel parameters successfully. Reboot the system to apply changes."
        else
            log_message "$function_name" "$vuln_id" "$rule_id" "Failed to add fips=1 to kernel parameters. This is a finding."
        fi
    fi
}

# Run the checks
check_slem_version
disable_ctrl_alt_del
check_encrypted_root_password
configure_boot_password_encryption
configure_zypper_gpgcheck
verify_telnet_server_not_installed
verify_disk_encryption_and_fips_mode
verify_ssh_package_installed
enable_and_start_openssh_service
configure_ssh_no_unattended_logon
configure_ssh_fips_approved_ciphers
configure_ssh_fips_approved_macs
configure_ssh_fips_approved_kex_algorithms
remove_shosts_files
remove_shosts_equiv_files
configure_gui_no_unattended_logon
change_non_root_uid_zero
configure_no_blank_passwords
ensure_accounts_have_password_or_locked
configure_password_encryption_sha512
configure_password_hashing_rounds
configure_fips_mode
