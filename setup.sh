#!/bin/bash
set -euo pipefail

echo "============================================================"
echo "      [+] NSA-STYLE SECURE STACK – RHEL/Rocky/Alma 9/10"
echo "============================================================"

###############################################################################
# 0) PREP
###############################################################################
echo "[+] Updating system"
dnf update -y
dnf install -y epel-release git python3 python3-pip curl wget unzip

INSTALL_DIR="/opt/sec-tools"
mkdir -p "$INSTALL_DIR"


###############################################################################
# 1) SELINUX ENFORCING + HARDENING
###############################################################################
echo "[+] Enabling SELinux enforcing"
sed -i 's/^SELINUX=.*/SELINUX=enforcing/g' /etc/selinux/config
setenforce 1 || true

echo "[+] Adding SELinux hardening modules"
cat >/etc/selinux/targeted/contexts/custom_user_type <<EOF
# Reserve for additional hardening rules if needed
EOF


###############################################################################
# 2) KERNEL HARDENING (NSA-STYLE)
###############################################################################
echo "[+] Applying kernel hardening"

cat >/etc/sysctl.d/90-nsa-hardening.conf <<EOF
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=2
kernel.dmesg_restrict=1
kernel.kexec_load_disabled=1
fs.suid_dumpable=0

net.ipv4.ip_forward=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1

net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0

net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF

sysctl --system


###############################################################################
# 3) NSA FIREWALL (LOCKED PROFILE)
###############################################################################
echo "[+] Installing nftables locked firewall"
dnf remove -y firewalld || true
dnf install -y nftables

cat >/etc/nftables.conf <<'EOF'
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        iif lo accept
        ct state established,related accept

        # basic services allowed (SSH optional)
        tcp dport {22} accept

        # ICMP ratelimit
        icmp type echo-request limit rate 1/second accept

        # default drop everything else
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF

systemctl enable --now nftables


###############################################################################
# 4) AUDITD + LOG HARDENING
###############################################################################
echo "[+] Enabling auditd logging"
dnf install -y audit audit-libs
systemctl enable --now auditd

cat >/etc/audit/rules.d/hardening.rules <<EOF
-w /etc/passwd -p wa
-w /etc/shadow -p wa
-w /etc/sudoers -p wa
-w /etc/ssh/sshd_config -p wa
EOF


###############################################################################
# 5) TOR DAEMON (BEZ ROUTING!)
###############################################################################
echo "[+] Installing Tor"
dnf install -y tor

cat >/etc/tor/torrc <<EOF
SOCKSPort 9050
ControlPort 9051
CookieAuthentication 1
DisableDebuggerAttachment 1
EOF

systemctl enable --now tor


###############################################################################
# 6) DNSCRYPT-PROXY (DNS Privacy)
###############################################################################
echo "[+] Installing DNSCrypt-Proxy"
dnf install -y dnscrypt-proxy

systemctl enable --now dnscrypt-proxy


###############################################################################
# 7) VPN STACK (WireGuard + strongSwan IPSec)
###############################################################################
echo "[+] Installing WireGuard"
dnf install -y wireguard-tools

echo "[+] Installing strongSwan (IPSec VPN)"
dnf install -y strongswan strongswan-swanctl
systemctl enable strongswan-swanctl --now


###############################################################################
# 8) SECURITY / OSINT TOOLS – LEGAL STACK
###############################################################################
echo "[+] Installing OSINT & forensic tools"

cd "$INSTALL_DIR"

### Maigret
git clone https://github.com/soxoj/maigret || true
pip3 install -r maigret/requirements.txt
ln -sf "$INSTALL_DIR/maigret/maigret.py" /usr/local/bin/maigret

### web-check
git clone https://github.com/Lissy93/web-check || true

### telegram-nearby-map
git clone https://github.com/tejado/telegram-nearby-map || true

### holehe
git clone https://github.com/megadose/holehe || true
pip3 install holehe || true

### cameradar
git clone https://github.com/Ullaakut/cameradar || true

### pupy (framework only – payloads NEJSOU součástí)
git clone https://github.com/n1nj4sec/pupy || true

### malicious-pdf (educational)
git clone https://github.com/jonaslejon/malicious-pdf || true

### Ciphey
git clone https://github.com/bee-san/Ciphey || true
pip3 install ciphey

### commix (web audit tool)
git clone https://github.com/commixproject/commix || true
ln -sf "$INSTALL_DIR/commix/commix.py" /usr/local/bin/commix


###############################################################################
# 9) Mask unsafe services
###############################################################################
echo "[+] Masking dangerous daemons"
systemctl mask avahi-daemon || true
systemctl mask cups || true
systemctl mask bluetooth || true


###############################################################################
# DONE
###############################################################################
echo "============================================================"
echo "[✔] COMPLETED: NSA-STYLE SECURE STACK INSTALLED"
echo "============================================================"
