#!/bin/bash

set -euo pipefail

echo "[*] Starting Ultra Mega Max NSA Hardening..."

# ----------------------------
# 1) System update & basics
# ----------------------------
dnf -y update
dnf -y install firewalld fail2ban policycoreutils-python-utils setools selinux-policy-devel \
               libseccomp audit audispd-plugins rng-tools python3-policycoreutils \
               bash-completion git vim wget tcpdump sysstat iproute

systemctl enable --now firewalld
systemctl enable --now fail2ban
systemctl enable --now rngd

# ----------------------------
# 2) Firewall lockdown
# ----------------------------
echo "[*] Configuring firewalld lockdown..."

# Default DROP zone
firewall-cmd --permanent --set-default-zone=drop
firewall-cmd --permanent --zone=trusted --add-service=ssh
firewall-cmd --permanent --zone=trusted --add-service=dns
firewall-cmd --permanent --zone=trusted --add-service=http
firewall-cmd --permanent --zone=trusted --add-service=https

# Anti-scan ports
firewall-cmd --permanent --add-icmp-block=echo-request
firewall-cmd --permanent --add-icmp-block=echo-reply
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port port="33434-33500" protocol="udp" drop'

firewall-cmd --reload

# ----------------------------
# 3) Port knocking (3-step) for SSH
# ----------------------------
echo "[*] Installing and configuring knockd..."
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

# ----------------------------
# 4) Fail2Ban configuration
# ----------------------------
echo "[*] Configuring Fail2Ban..."
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

# ----------------------------
# 5) SELinux strict enforcing
# ----------------------------
echo "[*] Enabling SELinux enforcing..."
setenforce 1
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

# ----------------------------
# 6) Kernel Hardening (sysctl)
# ----------------------------
echo "[*] Applying kernel hardening..."
cat >/etc/sysctl.d/99-nsa-hardening.conf <<EOL
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
kernel.kerneloops = 0
fs.suid_dumpable = 0
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

# ----------------------------
# 7) Auditd + NSA-style logging
# ----------------------------
echo "[*] Configuring auditd..."
systemctl enable --now auditd

auditctl -e 1
auditctl -w /etc/ -p wa -k etc-changes
auditctl -w /usr/bin/ -p x -k bin-exec
auditctl -w /var/log/ -p wa -k log-changes

# ----------------------------
# 8) Sandbox minimal services
# ----------------------------
echo "[*] Restricting services using systemd sandboxing..."
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

# ----------------------------
# 9) MAC address randomization
# ----------------------------
echo "[*] Enabling MAC address randomization..."
nmcli connection modify "*" 802-11-wireless.cloned-mac-address random
nmcli connection up "*"

# ----------------------------
# 10) Final checks
# ----------------------------
echo "[*] Hardening complete. Verifying..."
firewall-cmd --list-all-zones
getenforce
sysctl -a | grep rp_filter

echo "[*] Ultra Mega Max Super Extreme NSA Hardening applied successfully!"
