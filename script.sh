#!/bin/bash
set -e

echo "=================================================="
echo "      [+] FEDORA HARDENING + HACKING SUITE"
echo "=================================================="

######################################################
# SYSTEM UPDATE & BASE PACKAGES
######################################################
echo "[+] Updating system..."
sudo dnf update -y
sudo dnf install epel-release -y
sudo dnf update -y

######################################################
# SECURITY ESSENTIALS
######################################################
echo "[+] Installing security essentials..."
sudo dnf install -y \
    policycoreutils-python-utils \
    setools-console \
    audit audit-libs auditd \
    firewalld nftables \
    wireguard-tools \
    tor proxychains-ng \
    qemu-kvm libvirt virt-install virt-manager \
    firejail \
    systemd-container \
    java-17-openjdk \
    git wget curl python3 python3-pip python3-setuptools python3-virtualenv

######################################################
# NETWORKING / REVERSE ENGINEERING / WIFI
######################################################
echo "[+] Installing Wi-Fi + Networking tools..."
sudo dnf install -y \
    aircrack-ng hcxdumptool hcxtools mdk4 wifite \
    nmap masscan zmap bettercap mitm6 responder \
    gdb radare2 ghidra

######################################################
# PYTHON PREP
######################################################
echo "[+] Upgrading pip..."
pip3 install --upgrade pip

######################################################
# GITHUB TOOLS INSTALL
######################################################
INSTALL_DIR="/opt/sec-tools"
echo "[+] Creating install directory: $INSTALL_DIR"
sudo mkdir -p $INSTALL_DIR
sudo chmod -R 755 $INSTALL_DIR
cd $INSTALL_DIR

echo "[+] Installing GitHub exploitation / OSINT tools..."

echo "[*] Maigret"
sudo git clone https://github.com/soxoj/maigret
sudo pip3 install -r maigret/requirements.txt
sudo ln -sf $INSTALL_DIR/maigret/maigret.py /usr/local/bin/maigret

echo "[*] Web-Check"
sudo git clone https://github.com/Lissy93/web-check

echo "[*] Telegram Nearby Map"
sudo git clone https://github.com/tejado/telegram-nearby-map

echo "[*] Holehe"
sudo git clone https://github.com/megadose/holehe
sudo pip3 install holehe

echo "[*] Cameradar"
sudo git clone https://github.com/Ullaakut/cameradar

echo "[*] Pupy RAT"
sudo git clone https://github.com/n1nj4sec/pupy

echo "[*] Malicious PDF"
sudo git clone https://github.com/jonaslejon/malicious-pdf

echo "[*] Ciphey"
sudo git clone https://github.com/bee-san/Ciphey
pip3 install ciphey

echo "[*] Commix"
sudo git clone https://github.com/commixproject/commix
sudo ln -sf $INSTALL_DIR/commix/commix.py /usr/local/bin/commix

######################################################
# SELINUX HARDENING
######################################################
echo "[+] Enabling SELinux enforcing..."
sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
sudo setenforce 1 || true

######################################################
# SYSCTL HARDENING
######################################################
echo "[+] Hardening sysctl..."
cat << 'EOF' | sudo tee /etc/sysctl.d/99-sear-hardening.conf
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 3
kernel.unprivileged_userns_clone = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
EOF

sudo sysctl --system

######################################################
# FIREWALL LOCKDOWN
######################################################
echo "[+] Configuring firewall (drop-all default)…"
sudo systemctl enable --now firewalld
sudo firewall-cmd --set-default-zone=drop

######################################################
# AUDITD
######################################################
echo "[+] Enabling auditd..."
sudo systemctl enable --now auditd

######################################################
# MALWARE SANDBOX (systemd-nspawn)
######################################################
echo "[+] Creating malware sandbox machine..."
sudo mkdir -p /var/lib/machines/malwarelab
sudo dnf --installroot=/var/lib/machines/malwarelab install -y bash coreutils iputils iproute
sudo systemd-nspawn -D /var/lib/machines/malwarelab --machine=malwarelab true

echo "=================================================="
echo "   ✔ ALL DONE. SYSTEM HARDENED + TOOLS INSTALLED"
echo "   Tools directory => /opt/sec-tools"
echo "=================================================="
