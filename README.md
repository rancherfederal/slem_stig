# 12 Mar 2025 *These scripts have been tested with SLE Micro 5.5*

# DISA STIG SLE Micro 5 v1r1 was released 20 June 2024

To run a STIG script on SLE Micro since it is transactional, run `transactional-update run <script>`, reboot, and run the next.

Order to run the scripts
1. stig_pkg_installs.sh
2. security_hardening.sh
3. stig_low.sh
4. stig_med.sh
5. stig_high.sh

When running, check each file for potential settings that need exceptions and comment out the repsective function calls.
Password encryption is set to SHA512, after running stig_high.sh make sure you reset passwords with passwd <user> before rebooting.
There are still some minor findings, see below.

## Description of files

security_hardening.sh: this script is taken from the SUSE Linux Enterprise Micro 5.3 Security and Hardening Guide, it implements SELinux, Authentication with PAM, and FIPS 140-3 compliance

stig_high.sh: this script takes the data from DISA STIG SLE Micro 5 v1r1 for any "high vulnerabilities" and applies the recommended fixes.

stig_medium.sh: this script takes the data from DISA STIG SLE Micro 5 v1r1 for any "medium vulnerabilities" and applies the recommended fixes.

stig_medium_user_input.sh: this script takes the data from DISA STIG SLE Micro 5 v1r1 for any "medium vulnerabilities" that requires customization on a per user/organizational use and applies the recommended fixes.

stig_low.sh: this script takes the data from DISA STIG SLE Micro 5 v1r1 for any "low vulnerabilities" and applies the recommended fixes.

stig_pkg_installs.sh: this script is where you place any packages that DISA STIG may require to be installed so that they can run as a single transaction.

# Findings

This section shows current findings that are still left to work on.

## High Vulnerabilities

check_slem_version: Vuln_ID: V-261263 Rule_ID: SV-261263r996826 | Installed version of SLEM 5 is not supported. This is a finding. DISA STIG is set at SLEM 5.2

verify_disk_encryption_and_fips_mode: Vuln_ID: V-261284 Rule_ID: SV-261284r996333 | /etc/crypttab file does not exist. This is a finding.

## Medium Vulnerabilities

configure_fstab_nosuid_home: Vuln_ID: V-261285 Rule_ID: SV-261285r996838 | Failed to configure /etc/fstab to use the nosuid option for user home directories. This is a finding.

prevent_unauthorized_access_to_error_messages: Vuln_ID: V-261308 Rule_ID: SV-261308r996395 | Failed to set permissions of /var/log/messages to root:root 640. This is a finding.

configure_firewalld_and_panic_mode: Vuln_ID: V-261310 Rule_ID: SV-261310r996401 | Failed to enable and start firewalld.service. This is a finding.

disable_ipv4_icmp_redirects_all: Vuln_ID: V-261315 Rule_ID: SV-261315r996415 | Failed to disable IPv4 ICMP redirects acceptance. This is a finding.

configure_nss_cache_timeout: Vuln_ID: V-261399 Rule_ID: SV-261399r996617 | Failed to configure NSS cache timeout. This is a finding.

configure_pam_cache_timeout: Vuln_ID: V-261400 Rule_ID: SV-261400r996619 | Failed to configure PAM cache timeout. This is a finding.

install_aide: Vuln_ID: V-261403 Rule_ID: SV-261403r996627 | Failed to perform AIDE manual check. This is a finding.

configure_weekly_aide_check: Vuln_ID: V-261407 Rule_ID: SV-261407r996637 | Failed to configure weekly AIDE check. This is a finding.

configure_daily_aide_check: Vuln_ID: V-261408 Rule_ID: SV-261408r996640 | Failed to configure daily AIDE check. This is a finding.

configure_syslog_ng: Vuln_ID: V-261409 Rule_ID: SV-261409r996643 | Failed to configure syslog-ng. This is a finding.

install_audit_audispd_plugins: Vuln_ID: V-261412 Rule_ID: SV-261412r996649 | Failed to configure au-remote.conf. This is a finding.

configure_network_failure_action: Vuln_ID: V-261416 Rule_ID: SV-261416r996660 | Failed to configure network failure action for audit offloading. This is a finding.

configure_disk_full_action: Vuln_ID: V-261417 Rule_ID: SV-261417r996662 | Failed to configure disk full action for audit storage. This is a finding.

configure_audit_offload: Vuln_ID: V-261422 Rule_ID: SV-261422r996674 | Failed to configure audit offloading. This is a finding.

configure_auditd_notification: Vuln_ID: V-261423 Rule_ID: SV-261423r996677 | Failed to configure auditd notification. This is a finding.


## Low Vulnerabilities

configure_audisp_kerberos: Vuln_ID: V-261421 Rule_ID: SV-261421r996672 Failed to configure audit event multiplexor to use Kerberos. This is a finding.
