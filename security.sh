#!/bin/bash
# NSA Ultra Secure Air-Gapped Workstation Setup for Rocky Linux 9.7
# Author: ChatGPT | Safe NSA-style
# Usage: sudo bash nsa_airgap.sh

set -euo pipefail

echo "[*] Starting NSA Ultra-Secure Air-Gapped Hardening..."

# -----------------------------------
# 1) Update system and install tools
# -----------------------------------
dnf -y update
dnf -y install firewalld fail2ban policycoreutils-python-utils setools selinux-policy-devel \
               libseccomp audit audispd-plugins rng-tools python3-policycoreutils \
               bash-completion git vim wget tcpdump sysstat iproute grub2-efi shim

systemctl enable --now firewalld
systemctl enable --now fail2ban
systemctl enable --now rngd

# -----------------------------------
# 2) Secure Boot + UEFI lockdown
# -----------------------------------
echo "[*] Configuring Secure Boot..."
# Ensure system bootloader is signed
grub2-editenv - set menu_auto_hide=1
mokutil --sb-state

# Optional: Lock the bootloader password
echo "rootsecure" | grub2-setpassword --stdin

# -----------------------------------
# 3) Firewall lockdown + port-knocking
# -----------------------------------
firewall-cmd --permanent --set-default-zone=drop
firewall-cmd --permanent --zone=trusted --add-service=ssh
firewall-cmd --permanent --zone=trusted --add-service=dns
firewall-cmd --permanent --zone=trusted --add-service=http
firewall-cmd --permanent --zone=trusted --add-service=https
firewall-cmd --permanent --add-icmp-block=echo-request
firewall-cmd --permanent --add-icmp-block=echo-reply
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port port="33434-33500" protocol="udp" drop'
firewall-cmd --reload

# Port-knocking setup
dnf -y install knockd
cat >/etc/knockd.conf <<EOL
[options]
logfile = /var/log/knockd.log

[openSSH]
sequence    = 7001,8001,9001
seq_timeout = 10
command     = firewall-cmd --zone=trusted --add-source=%IP% --permanent && firewall-cmd --reload
tcpflags    = syn

[closeSSH]
sequence    = 9001,8001,7001
seq_timeout = 10
command     = firewall-cmd --zone=trusted --remove-source=%IP% --permanent && firewall-cmd --reload
tcpflags    = syn
EOL
systemctl enable --now knockd

# -----------------------------------
# 4) Fail2Ban configuration
# -----------------------------------
cat >/etc/fail2ban/jail.local <<EOL
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/secure
maxretry = 3
findtime = 300
bantime = 36000
backend = systemd
EOL
systemctl restart fail2ban

# -----------------------------------
# 5) SELinux Enforcing + custom NSA policy
# -----------------------------------
setenforce 1
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

# Restrict all but essential services
semanage permissive -d sshd_t
semanage permissive -d firewalld_t
semanage permissive -d chronyd_t

# -----------------------------------
# 6) Kernel Hardening + IMA/EVM
# -----------------------------------
cat >/etc/sysctl.d/99-nsa-airgap.conf <<EOL
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
kernel.kerneloops = 0
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.ip_forward = 0
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOL
sysctl --system

# IMA/EVM setup
modprobe ima
modprobe evm
echo 'appraise=fix' > /sys/kernel/security/ima/policy
echo 'ima_appraise=on' >> /etc/default/grub
grub2-mkconfig -o /boot/efi/EFI/rocky/grub.cfg

# -----------------------------------
# 7) Auditd NSA-style offline logging
# -----------------------------------
systemctl enable --now auditd
auditctl -e 1
auditctl -w /etc/ -p wa -k etc-changes
auditctl -w /usr/bin/ -p x -k bin-exec
auditctl -w /var/log/ -p wa -k log-changes

# Store audit logs locally (air-gapped)
mkdir -p /var/audit-airgap
chown root:root /var/audit-airgap
chmod 700 /var/audit-airgap

# -----------------------------------
# 8) Sandbox critical services
# -----------------------------------
mkdir -p /etc/systemd/system/ssh.service.d
cat >/etc/systemd/system/ssh.service.d/override.conf <<EOL
[Service]
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes
ReadOnlyPaths=/etc /usr
InaccessiblePaths=/root
EOL
systemctl daemon-reexec
systemctl restart sshd

# -----------------------------------
# 9) MAC address randomization
# -----------------------------------
nmcli connection modify "*" 802-11-wireless.cloned-mac-address random
nmcli connection up "*"

# -----------------------------------
# 10) Optional minimal GUI lockdown
# -----------------------------------
dnf -y groupremove "Server with GUI"
systemctl set-default multi-user.target

# -----------------------------------
# 11) Final checks
# -----------------------------------
echo "[*] Hardening complete. Verification:"
firewall-cmd --list-all-zones
getenforce
sysctl -a | grep rp_filter
auditctl -l

echo "[*] NSA Ultra Secure Air-Gapped Hardening applied successfully!"
