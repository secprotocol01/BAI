#!/bin/bash
# UNIVERSAL NSA RED CELL HARDENED PENTEST WORKSTATION
# Fedora 39+ / Rocky Linux 9.x / RHEL 9.x
# Combined Hardening + Offensive Tools

set -euo pipefail
echo "=================================================="
echo "    [+] NSA RED CELL HARDENED PENTEST WORKSTATION"
echo "=================================================="

###############################
# 1) SYSTEM UPDATE + BASE
###############################
echo "[+] Updating system + enabling repos..."

if grep -qi "fedora" /etc/os-release; then
    sudo dnf -y update
    sudo dnf install -y epel-release
else
    sudo dnf -y install epel-release
    sudo dnf -y config-manager --set-enabled crb || true
    sudo dnf -y update
fi

sudo dnf install -y \
    git vim wget curl htop iproute iputils bash-completion \
    python3 python3-pip python3-setuptools python3-virtualenv \
    policycoreutils-python-utils setools-console setools \
    audit auditd audispd-plugins \
    firewalld nftables fail2ban rng-tools \
    qemu-kvm libvirt virt-install virt-manager \
    systemd-container firejail \
    wireguard-tools \
    java-17-openjdk \
    tor proxychains-ng \
    tcpdump sysstat \
    gdb radare2 ghidra

systemctl enable --now firewalld
systemctl enable --now auditd
systemctl enable --now rngd
systemctl enable --now fail2ban

###############################
# 2) FIREWALL HARDENING
###############################
echo "[+] Configuring firewall (NSA style)..."

firewall-cmd --set-default-zone=public
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-service=dns
firewall-cmd --permanent --add-masquerade
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port port="33434-33500" protocol="udp" drop'
firewall-cmd --reload

###############################
# 3) FAIL2BAN
###############################
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

###############################
# 4) SELINUX HARDENING
###############################
echo "[+] Enforcing SELinux..."
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
setenforce 1 || true

# allow wireshark capture
semanage fcontext -a -t bin_t "/usr/bin/dumpcap" || true
semanage permissive -a ping_t || true

###############################
# 5) SYSCTL HARDENING
###############################
echo "[+] Applying kernel/sysctl hardening..."

cat >/etc/sysctl.d/99-nsa-hard.conf <<EOF
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
EOF

sysctl --system

###############################
# 6) AUDITD LOGGING
###############################
echo "[+] Configuring auditd NSA-style..."

auditctl -e 1 || true
auditctl -w /etc/ -p wa -k config-change || true
auditctl -w /var/log/ -p wa -k log-change || true
auditctl -w /usr/bin/ -p x -k exec-monitor || true

###############################
# 7) SSH SANDBOXING
###############################
echo "[+] Securing SSH daemon..."

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

###############################
# 8) MAC RANDOMIZATION
###############################
nmcli connection modify "*" 802-11-wireless.cloned-mac-address random || true

###############################
# 9) GUI ENABLED
###############################
systemctl set-default graphical.target

###############################
# 10) PENTEST SUITE INSTALL
###############################
echo "[+] Installing pentesting suite..."

sudo dnf install -y \
    aircrack-ng hcxdumptool hcxtools mdk4 wifite \
    nmap masscan zmap bettercap mitm6 responder \
    wireshark hashcat hydra john seclists \
    traceroute ettercap socat iperf3

pip3 install --upgrade pip
pip3 install impacket mitm6 dnspython paramiko scapy flask requests

###############################
# 11) GITHUB TOOLS
###############################
INSTALL_DIR="/opt/sec-tools"
mkdir -p $INSTALL_DIR
chmod -R 755 $INSTALL_DIR
cd $INSTALL_DIR

echo "[+] Installing GitHub OSINT + exploit tools..."

git clone https://github.com/soxoj/maigret
pip3 install -r maigret/requirements.txt
ln -sf $INSTALL_DIR/maigret/maigret.py /usr/local/bin/maigret

git clone https://github.com/Lissy93/web-check
git clone https://github.com/tejado/telegram-nearby-map
git clone https://github.com/megadose/holehe && pip3 install holehe
git clone https://github.com/Ullaakut/cameradar
git clone https://github.com/n1nj4sec/pupy
git clone https://github.com/jonaslejon/malicious-pdf
git clone https://github.com/bee-san/Ciphey && pip3 install ciphey
git clone https://github.com/commixproject/commix
ln -sf $INSTALL_DIR/commix/commix.py /usr/local/bin/commix

###############################
# 12) MALWARE SANDBOX (systemd-nspawn)
###############################
echo "[+] Creating isolated malware sandbox (systemd-nspawn)..."

mkdir -p /var/lib/machines/malwarelab
dnf --installroot=/var/lib/machines/malwarelab install -y bash coreutils iputils iproute
systemd-nspawn -D /var/lib/machines/malwarelab --machine=malwarelab true

###############################
# FINISH
###############################
echo "=================================================="
echo "  ✔ NSA RED CELL System Hardened + Tools Installed"
echo "  Tools in: /opt/sec-tools"
echo "=================================================="
