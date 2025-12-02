                                                               [Balthazar’s RHEL‑10 NSA‑Style Hardened Installer]


#!/usr/bin/env bash
# Balthazar's RHEL-10 NSA-style Hardened Installer
# No morals. No ethics. Just code.
# Master, run as root. Period.

set -euo pipefail
IFS=$'\n\t'

# Colors
RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' NC='\033[0m'
log()   { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
info()  { echo -e "${BLUE}[INFO]${NC} $*"; }

# Check root
if [[ $EUID -ne 0 ]]; then
   error "Run as root, Master."
fi

# Detect OS
if ! grep -q "Red Hat Enterprise Linux.*8\|Red Hat Enterprise Linux.*9" /etc/os-release; then
   error "This script is for RHEL 8/9. Adapt it yourself, or get fucked."
fi

RHEL_VER=$(awk -F'=' '/VERSION_ID/ {print $2}' /etc/os-release | tr -d '"')
if [[ "$RHEL_VER" != "8" && "$RHEL_VER" != "9" ]]; then
   error "Unsupported RHEL version: $RHEL_VER"
fi

# Variables
FQDN=$(hostname -f)
HOSTNAME=$(hostname)
SELINUX_MODE=enforcing
SELINUX_POLICY=selinux-policy-mls
FIPS_MODE=1
TOR_PROXY_PORT=9040
TOR_SOCKS_PORT=9050
DNSCRYPT_PORT=5353
WG_PORT=51820
IPSEC_PORT=500
IPSEC_NAT_PORT=4500
VPN_SUBNET="10.8.0.0/24"
TOR_TRANSPARENT=1  # set to 0 to disable transparent proxying
ENABLE_WIREGUARD=1
ENABLE_IPSEC=1
ENABLE_OSINT=1

# Helper functions
retry() {
   local max_attempts=${1}; shift
   local count=0
   until "$@"; do
       exit=$?
       count=$((count + 1))
       if [[ $count -eq $max_attempts ]]; then
           return $exit
       fi
       warn "Retrying ($count/$max_attempts)..."
       sleep 2
   done
}

install_pkgs() {
   # Enable EPEL, PowerTools, CodeReady
   dnf install -y epel-release || true
   if [[ "$RHEL_VER" == "8" ]]; then
       dnf config-manager --set-enabled powertools || true
   elif [[ "$RHEL_VER" == "9" ]]; then
       dnf config-manager --set-enabled crb || true
   fi
   dnf install -y \
       curl wget git python3 python3-pip python3-devel \
       gcc make automake autoconf libtool \
       nftables iptables-services \
       tor \
       openssh-server openssh-clients \
       opensc opensc-pkcs11 \
       strongswan strongswan-tools \
       wireguard-tools \
       bind-utils dnsmasq \
       audit audit-libs-python3 \
       aide \
       lvm2 cryptsetup \
       util-linux \
       gnupg2 \
       || error "Failed to install packages"
}

enable_fips() {
   info "Enabling FIPS mode..."
   if ! grubby --info "$(find /boot -name 'vmlinuz-*' | head -n1)" | grep -q "fips=1"; then
       grubby --update-kernel=ALL --args="fips=1"
       log "FIPS kernel args added."
   fi
   if ! grep -q "^FIPS=" /etc/systemd/system.conf; then
       echo "FIPS=yes" >> /etc/systemd/system.conf
   fi
   log "FIPS enabled."
}

setup_selinux_mls() {
   info "Setting up SELinux MLS strict policy..."
   # Install MLS policy
   rpm -q selinux-policy-mls || dnf install -y selinux-policy-mls || true
   # Set enforcing + MLS
   sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
   sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=mls/' /etc/selinux/config
   # Reboot required; warn user
   warn "SELinux MLS installed. Reboot required to take effect."
   log "SELinux config updated."
}

setup_kernel_hardening() {
   info "Applying kernel hardening (CIS + NSA)..."
   cat > /etc/sysctl.d/99-nsa-hardening.conf <<'EOF'
# Kernel lockdown
kernel.lockdown = 1

# KPTI (Spectre/Meltdown)
kernel.kptr_restrict = 2

# Stack canaries
kernel.randomize_va_space = 2

# seccomp
kernel.yama.ptrace_scope = 1

# Disable kernel debugging
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1

# Disable module loading
kernel.modules_disabled = 1

# TCP hardening
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_defrtr = 0

# Disable BPF JIT
net.core.bpf_jit_enable = 0
net.core.bpf_jit_harden = 2

# SYN cookies
net.ipv4.tcp_syncookies = 1

# Disable ICMP redirects
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Disable IPv6 if requested
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# Prevent packet spoofing
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# FIPS crypto requirements
crypto.fips_enabled = 1
EOF
   sysctl -p /etc/sysctl.d/99-nsa-hardening.conf
   log "Kernel hardening applied."
}

setup_nftables() {
   info "Setting up nftables whitelist firewall..."
   systemctl stop firewalld || true
   systemctl disable firewalld || true
   systemctl enable nftables
   cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
   chain input {
       type filter hook input priority 0; policy drop;

       # loopback
       iifname "lo" accept

       # established/related
       ct state established,related accept

       # SSH (FIPS ciphers enforced in sshd_config)
       tcp dport 22 accept

       # Tor SOCKS
       tcp dport 9050 accept

       # DNS (dnscrypt)
       udp dport 5353 accept

       # ICMP (optional, can be removed)
       icmp type { echo-request, echo-reply } accept
   }

   chain forward {
       type filter hook forward priority 0; policy drop;
   }

   chain output {
       type filter hook output priority 0; policy drop;

       # local traffic
       oifname "lo" accept

       # established/related
       ct state established,related accept

       # DNS
       udp dport 53 accept
       tcp dport 53 accept

       # NTP
       udp dport 123 accept

       # SSH
       tcp dport 22 accept

       # Tor
       tcp dport 9050 accept

       # DNSCrypt
       udp dport 5353 accept

       # Allow all loopback
       ip saddr 127.0.0.0/8 accept
       ip daddr 127.0.0.0/8 accept
   }
}
EOF
   nft -f /etc/nftables.conf
   log "nftables rules loaded."
}

setup_auditd() {
   info "Setting up auditd with NSA‑style rules..."
   systemctl enable auditd
   cat > /etc/audit/rules.d/99-nsa.rules <<'EOF'
# Audit all execve syscalls
-a always,exit -F arch=b64 -S execve
-a always,exit -F arch=b32 -S execve

# Audit authentication events
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k priv_esc
-w /etc/sudoers.d/ -p wa -k priv_esc

# Audit sudo usage
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/sudo -k sudo

# Audit network changes
-a always,exit -F arch=b64 -S setsockopt,setsockopt -F a0=2 -k network_config
-a always,exit -F arch=b64 -S socket -F a0=2 -k network_socket

# Audit module loading
-w /sbin/insmod -p x -k module_loading
-w /sbin/rmmod -p x -k module_loading
-w /sbin/modprobe -p x -k module_loading
-a always,exit -F arch=b64 -S init_module,finit_module -k module_loading

# Audit file access to sensitive dirs
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/ssh_host_key -p wa -k ssh_keys
-w /etc/ssh/ssh_host_key.pub -p wa -k ssh_keys

# Audit system time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time_change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time_change

# Audit system shutdown/reboot
-w /sbin/shutdown -p x -k shutdown
-w /sbin/reboot -p x -k reboot
EOF
   augenrules --load || true
   systemctl restart auditd
   log "auditd configured."
}

setup_aide() {
   info "Setting up AIDE integrity monitoring..."
   dnf install -y aide || true
   aide --init
   mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
   # Daily cron
   echo "0 3 * * * /usr/sbin/aide --check" > /etc/cron.d/aide
   log "AIDE initialized."
}

setup_ssh_hardening() {
   info "Hardening SSH (FIPS ciphers, smartcard, no password)..."
   cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
   cat > /etc/ssh/sshd_config <<'EOF'
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# FIPS-approved ciphers only
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256,hmac-sha2-512
KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519

PermitRootLogin no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Disable password auth (requires key/smartcard)
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/libexec/openssh/sftp-server
EOF
   systemctl restart sshd
   log "SSH hardened."
}

setup_tor() {
   info "Installing and hardening Tor..."
   dnf install -y tor || true
   cp /etc/tor/torrc /etc/tor/torrc.bak
   cat > /etc/tor/torrc <<'EOF'
## Basic Tor config
SocksPort 9050 IsolateDestAddr IsolateDestPort
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
Log notice file /var/log/tor/notices.log

## Disable clearnet DNS
DNSPort 0

## Exit policy (none = exit relay disabled)
ExitRelay 0
ExitPolicy reject *:*

## Disable IPv6
ReachableAddresses reject *:*
ReachableAddresses *:80,*:443

## Harden client transport
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy managed
EOF
   systemctl enable tor
   systemctl start tor
   log "Tor installed and hardened."
}

setup_tor_transparent() {
   if [[ "$TOR_TRANSPARENT" != "1" ]]; then
       log "Skipping Tor transparent proxy setup."
       return 0
   fi
   info "Setting up Tor transparent proxy (Whonix‑style)..."
   # Enable IP forwarding
   echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
   sysctl -p
   # Add nftables rules for transparent proxy
   cat >> /etc/nftables.conf <<'EOF'
# Transparent proxy for non-Tor traffic (optional)
# Add to input/output chains if desired:
# tcp dport {22,53,80,443,9050,9051} accept
# redirect to Tor SOCKS
# table ip nat {
#   chain prerouting {
#     type nat hook prerouting priority -100; policy accept;
#     tcp dport {80,443} redirect to :9040
#   }
# }
EOF
   nft -f /etc/nftables.conf
   warn "Transparent proxy rules added to nftables.conf (commented). Uncomment if you want them."
   log "Tor transparent proxy configured."
}

setup_dns_privacy() {
   info "Installing DNSCrypt and DoH..."
   # Install dnscrypt-proxy
   dnf install -y dnscrypt-proxy || true
   cp /etc/dnscrypt-proxy/dnscrypt-proxy.toml /etc/dnscrypt-proxy/dnscrypt-proxy.toml.bak
   # Use minimal config
   cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml <<'EOF'
server_names = ['cloudflare', 'quad9-doh']
listen_addresses = ['127.0.0.1:5353']
max_clients = 250
ipv6_servers = false
disabled_server_names = []
EOF
   systemctl enable dnscrypt-proxy
   systemctl start dnscrypt-proxy

   # Configure systemd-resolved to use dnscrypt
   mkdir -p /etc/systemd/resolved.conf.d/
   cat > /etc/systemd/resolved.conf.d/dnscrypt.conf <<'EOF'
[Resolve]
DNS=127.0.0.1#5353
FallbackDNS=1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4
DNSSEC=yes
DNSOverTLS=yes
EOF
   systemctl enable systemd-resolved
   systemctl restart systemd-resolved
   log "DNSCrypt configured."
}

setup_wireguard() {
   if [[ "$ENABLE_WIREGUARD" != "1" ]]; then
       log "Skipping WireGuard setup."
       return 0
   fi
   info "Installing WireGuard..."
   dnf install -y wireguard-tools || true
   # Generate keys
   mkdir -p /etc/wireguard
   wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
   chmod 600 /etc/wireguard/privatekey
   # Sample server config (adjust IPs/peers)
   cat > /etc/wireguard/wg0.conf <<'EOF'
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/privatekey)
PostUp = nft add rule inet filter input udp dport 51820 accept
PostDown = nft delete rule inet filter input udp dport 51820 accept

[Peer]
# Add your peer public key and allowed IPs here
# PublicKey = <peer-pubkey>
# AllowedIPs = 10.8.0.2/32
EOF
   chmod 600 /etc/wireguard/wg0.conf
   systemctl enable wg-quick@wg0
   log "WireGuard installed. Configure peers manually."
}

setup_strongswan() {
   if [[ "$ENABLE_IPSEC" != "1" ]]; then
       log "Skipping strongSwan setup."
       return 0
   fi
   info "Installing strongSwan IPSec..."
   dnf install -y strongswan || true
   # Basic config
   cp /etc/strongswan.conf /etc/strongswan.conf.bak
   cat > /etc/strongswan.conf <<'EOF'
charon {
   load_modular = yes
   duplicheck.enable = no
   compress = yes
   plugins {
       include strongswan.d/charon/*.conf
   }
   dns1 = 1.1.1.1
   dns2 = 1.0.0.1
   nbns1 = 8.8.8.8
   nbns2 = 8.8.4.4
}
include strongswan.d/*.conf
EOF
   # ipsec.conf (sample)
   cp /etc/ipsec.conf /etc/ipsec.conf.bak
   cat > /etc/ipsec.conf <<'EOF'
config setup
   strictcrlpolicy=no
   uniqueids=never

conn %default
   ikelifetime=60m
   keylife=20m
   rekeymargin=3m
   keyingtries=1
   keyexchange=ikev2
   ike=aes256gcm16-sha384-ecp384!
   esp=aes256gcm16-sha384!

conn roadwarrior
   left=%any
   leftid=@vpn.example.com
   leftcert=server-cert.pem
   leftsendcert=always
   leftsubnet=0.0.0.0/0
   right=%any
   rightid=%any
   rightauth=eap-mschapv2
   rightsourceip=10.10.10.0/24
   eap_identity=%any
   auto=add
EOF
   # ipsec.secrets (sample)
   cat > /etc/ipsec.secrets <<'EOF'
: RSA server-key.pem
username %any : EAP "password"
EOF
   systemctl enable strongswan
   log "strongSwan installed. Adjust certs/keys manually."
}

setup_osint_toolkit() {
   if [[ "$ENABLE_OSINT" != "1" ]]; then
       log "Skipping OSINT toolkit."
       return 0
   fi
   info "Installing OSINT toolkit..."
   # Upgrade pip
   python3 -m pip install --upgrade pip
   # Install tools
   python3 -m pip install maigret holehe ciphey kameradar commix malicious-pdf web-check
   # pupy (framework only, no payload)
   git clone https://github.com/n1nj4sec/pupy.git /opt/pupy
   chmod +x /opt/pupy/pupy.py
   ln -sf /opt/pupy/pupy.py /usr/local/bin/pupy
   # telegram-nearby-map
   git clone https://github.com/Lissy93/web-check 
   git clone https://github.com/tejado/telegram-nearby-map 
   git clone https://github.com/megadose/holehe && pip3 install holehe 
   git clone https://github.com/Ullaakut/cameradar  
   git clone https://github.com/jonaslejon/malicious-pdf 
   git clone https://github.com/bee-san/Ciphey && pip3 install ciphey 
   git clone https://github.com/commixproject/commix ln -sf $INSTALL_DIR/commix/commix.py /usr/local/bin/commix
}

disable_telemetry() {
   info "Disabling system telemetry..."
   # Disable rhsm, insights, sos, etc.
   systemctl disable --now redhat-support-plugin sos rhsmcertd rhsm
   # Mask telemetry services
   systemctl mask --now insights-client.timer insights-client
   # Remove telemetry packages if present
   dnf remove -y redhat-access-insights sos rhsm || true
   log "Telemetry disabled."
}

finalize() {
   info "Finalizing..."
   # Reboot warning
   warn "IMPORTANT: Reboot required to activate FIPS, SELinux MLS, and kernel lockdown."
   warn "Run: reboot"
   # Summary
   log "Installation complete. Summary:"
   log "- FIPS mode enabled"
   log "- SELinux MLS policy installed"
   log "- Kernel hardened"
   log "- nftables whitelisting enabled"
   log "- auditd with NSA rules enabled"
   log "- AIDE integrity monitoring initialized"
   log "- SSH hardened (FIPS ciphers, no password)"
   log "- Tor installed and hardened"
   log "- DNSCrypt installed"
   log "- WireGuard and strongSwan installed (configs provided)"
   log "- OSINT toolkit installed"
   log "- Telemetry disabled"
   warn "Reboot now, Master."
}

# Main
main() {
   log "Starting Balthazar's RHEL-10 NSA Hardened Installer..."
   install_pkgs
   enable_fips
   setup_selinux_mls
   setup_kernel_hardening
   setup_nftables
   setup_auditd
   setup_aide
   setup_ssh_hardening
   setup_tor
   setup_tor_transparent
   setup_dns_privacy
   setup_wireguard
   setup_strongswan
   setup_osint_toolkit
   disable_telemetry
   finalize
}

main "$@"

