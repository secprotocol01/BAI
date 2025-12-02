#!/bin/bash
# NSA RED CELL PENTESTING WORKSTATION
# Rocky Linux 9.7 – Secure + Offensive Tools (Safe)

set -euo pipefail
echo "[*] Starting NSA Red Cell Workstation Build..."

# ---------------------------------------------------------
# 1) Update + base tools
# ---------------------------------------------------------
dnf -y update
dnf -y install \
    firewalld fail2ban policycoreutils-python-utils setools \
    selinux-policy-devel libseccomp audit audispd-plugins rng-tools \
    git vim wget curl tcpdump sysstat iproute bash-completion \
    python3 python3-pip

systemctl enable --now firewalld
systemctl enable --now fail2ban
systemctl enable --now rngd

# ---------------------------------------------------------
# 2) Hardening: Firewall (pentest-friendly)
# ---------------------------------------------------------
echo "[*] Configuring firewall..."

firewall-cmd --set-default-zone=public
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-service=dns

# Allow pentesting tools to run outbound scans
firewall-cmd --permanent --add-masquerade

# Drop some attack detection ports
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port port="33434-33500" protocol="udp" drop'

firewall-cmd --reload

# ---------------------------------------------------------
# 3) Fail2Ban
# ---------------------------------------------------------
cat >/etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = ssh
logpath = /var/log/secure
maxretry = 4
findtime = 300
bantime = 3600
EOF
systemctl restart fail2ban

# ---------------------------------------------------------
# 4) SELinux enforcing, tuned for pentesting
# ---------------------------------------------------------
echo "[*] Configuring SELinux..."
setenforce 1
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

# Allow packet capture by tools like Wireshark (safe)
semanage fcontext -a -t bin_t "/usr/bin/dumpcap"
semanage permissive -a ping_t

# ---------------------------------------------------------
# 5) Kernel hardening (compatible with scanners)
# ---------------------------------------------------------
cat >/etc/sysctl.d/99-nsa-redcell.conf <<EOF
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.ip_forward = 1
EOF

sysctl --system

# ---------------------------------------------------------
# 6) Auditd logging
# ---------------------------------------------------------
systemctl enable --now auditd

auditctl -e 1
auditctl -w /etc/ -p wa -k config-change
auditctl -w /var/log/ -p wa -k log-change
auditctl -w /usr/bin/ -p x -k exec-monitor

# ---------------------------------------------------------
# 7) SSH sandboxing
# ---------------------------------------------------------
mkdir -p /etc/systemd/system/sshd.service.d
cat >/etc/systemd/system/sshd.service.d/override.conf <<EOF
[Service]
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
EOF

systemctl daemon-reexec
systemctl restart sshd

# ---------------------------------------------------------
# 8) MAC randomization for Wi-Fi only
# ---------------------------------------------------------
nmcli connection modify "*" 802-11-wireless.cloned-mac-address random || true

# ---------------------------------------------------------
# 9) KEEP GUI (important for tools)
# ---------------------------------------------------------
systemctl set-default graphical.target

# ---------------------------------------------------------

# ---------------------------------------------------------
echo "[*] Installing pentesting suite..."

dnf -y install \
    nmap \
    wireshark \
    aircrack-ng \
    hashcat \
    hydra \
    john \
    seclists \
    traceroute \
    ettercap \
    socat \
    htop \
    iperf3

# Python tools
pip3 install --upgrade pip

pip3 install \
    impacket \
    mitm6 \
    dnspython \
    paramiko \
    scapy \
    flask \
    requests

# Responder (legal)
git clone https://github.com/lgandx/Responder /opt/Responder
chmod +x /opt/Responder/Responder.py

# ---------------------------------------------------------
# 11) Final summary
# ---------------------------------------------------------
echo "==============================================="
echo "[✓] NSA Red Cell Workstation Ready"
echo "✔ SELinux enforcing + kernel hardening"
echo "✔ All essential pentesting tools installed"
echo "✔ System secured to NSA-style standards"
echo "==============================================="
