#========================================================
# OSSECURE-X Custom Hardened Fedora/RHEL/Rocky/Alma ISO
#========================================================

# 1) Basic configuration
lang en_US.UTF-8
keyboard us
timezone UTC
auth --useshadow --passalgo=sha512
selinux --enforcing --type=mls
firewall --enabled --service=ssh
bootloader --location=mbr --append="quiet splash selinux=1 enforcing=1 mls=1 audit=1 lockdown=confidentiality"

# 2) Disk partitioning with LUKS2 full disk encryption
autopart --type=lvm --encrypted --passphrase=changeme --luks-version=luks2 --cipher=aes-xts-plain64 --pbkdf=argon2id

#========================================================
# 3) Packages
#========================================================
%packages
@core
kernel-rt
kernel-tools
kernel-modules-extra
selinux-policy-mls
tor
torsocks
dnscrypt-proxy
dns-over-https-proxy
firewalld
audit
sshd
python3.12
python3.9
git
gcc
make
aircrack-ng
iw
wpa_supplicant
wireless-tools
hcxdumptool
hcxlabtools
sqlmap
metasploit
spiderfoot
bubblewrap
firejail
toolbox
podman
plymouth-theme-ossecure
%end

#========================================================
# 4) Post-install scripts
#========================================================
%post --erroronfail
#-------------------------------
# 4.1) SELinux MLS & FIPS
#-------------------------------
dnf install -y selinux-policy-mls
setenforce 1
fips-mode-setup --enable

#-------------------------------
# 4.2) Kernel Hardening
#-------------------------------
cat <<EOF >/etc/sysctl.d/99-ossecure.conf
kernel.kptr_restrict=2
kernel.unprivileged_bpf_disabled=1
kernel.dmesg_restrict=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
kernel.yama.ptrace_scope=2
kernel.kexec_load_disabled=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
kernel.randomize_va_space=2
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
sysctl --system

#-------------------------------
# 4.3) Systemd sandboxing defaults
#-------------------------------
mkdir -p /etc/systemd/system.conf.d
cat <<EOF >/etc/systemd/system.conf.d/99-sandboxing.conf
[Manager]
DefaultMemoryDenyWriteExecute=yes
DefaultRestrictNamespaces=yes
DefaultProtectSystem=strict
DefaultProtectHome=true
DefaultNoNewPrivileges=yes
EOF

#-------------------------------
# 4.4) Hardened RPM Macros
#-------------------------------
cat <<EOF >/etc/rpm/macros.ossecure
%_signature gpg
%_gpg_name OSSECURE-X
%__gpg /usr/bin/gpg
%_disable_source_fetch 1
%_binary_payload w6.bzip2
%_source_payload w6.bzip2
EOF

#-------------------------------
# 4.5) Monitor mode & packet injection
#-------------------------------
echo "options cfg80211 ieee80211_regdom=00" > /etc/modprobe.d/99-wifi.conf
echo "blacklist mac80211_hwsim" > /etc/modprobe.d/blacklist-hwsim.conf

#-------------------------------
# 4.6) Preinstalled amx-z0
#-------------------------------
git clone https://github.com/thewifiproject/amx-z0 /opt/amx-z0
cd /opt/amx-z0
pip3 install -r requirements.txt
chmod +x *.py

#-------------------------------
# 4.7) Split security scripts (SSH/GPG/Monero)
#-------------------------------
mkdir -p /opt/splits

cat <<'EOL' >/opt/splits/split-ssh.sh
#!/bin/bash
mkdir -p /var/splits/ssh
chmod 700 /var/splits/ssh
export SSH_AUTH_SOCK=/var/splits/ssh/ssh-agent.sock
eval $(ssh-agent -s)
ssh-add /opt/keys/id_rsa
EOL

cat <<'EOL' >/opt/splits/split-gpg.sh
#!/bin/bash
mkdir -p /var/splits/gpg
chmod 700 /var/splits/gpg
export GNUPGHOME=/var/splits/gpg
gpg --import /opt/keys/private.gpg
EOL

cat <<'EOL' >/opt/splits/split-monero.sh
#!/bin/bash
export MONERO_WALLET_DIR=/var/splits/monero
mkdir -p $MONERO_WALLET_DIR
chmod 700 $MONERO_WALLET_DIR
monero-wallet-cli --wallet-file $MONERO_WALLET_DIR/wallet --password 'changeme'
EOL

chmod +x /opt/splits/*.sh

#-------------------------------
# 4.8) Anon connection wizard
#-------------------------------
cat <<'EOL' >/usr/local/bin/anon-connect
#!/bin/bash
systemctl enable tor dnscrypt-proxy doh-proxy
systemctl start tor dnscrypt-proxy doh-proxy
iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040
echo "Transparent Tor routing + DNSCrypt enabled"
EOL
chmod +x /usr/local/bin/anon-connect

#-------------------------------
# 4.9) Igloo-style NSA lockdown
#-------------------------------
cat <<'EOL' >/usr/local/bin/igloo-lockdown.sh
#!/bin/bash
nmcli radio all off
ip link set lo up
modprobe -r usb_storage
modprobe -r uas
auditctl -e 1
setenforce 1
echo "OSSECURE-X lockdown active"
EOL
chmod +x /usr/local/bin/igloo-lockdown.sh

#-------------------------------
# 4.10) Enable Tor + DNSCrypt + DoH at boot
#-------------------------------
systemctl enable tor
systemctl enable dnscrypt-proxy
systemctl enable doh-proxy
systemctl enable firewalld
systemctl enable auditd
systemctl enable sshd

#-------------------------------
# 4.11) NFTables Tor Transparent Proxy
#-------------------------------
cat <<EOF >/etc/nftables.conf
table inet tor {
    chain prerouting {
        type nat hook prerouting priority -100;
        tcp dport != 22 redirect to 9040
    }
}
EOF
systemctl enable nftables

#-------------------------------
# 5) Qubes‑like sandbox compartments
#-------------------------------
mkdir -p /opt/sandboxes
semanage fcontext -a -t container_file_t "/opt/sandboxes(/.*)?"
restorecon -Rv /opt/sandboxes

cat <<'EOF' >/etc/firejail/default.profile
private
seccomp
caps.drop all
nofiles 1024
protocol unix,inet,inet6
apparmor none
EOF

#-------------------------------
# 6) Hidden LUKS container setup (optional)
#-------------------------------
cat <<'EOF' >/usr/local/bin/hidden-luks.sh
#!/bin/bash
DEVICE=/dev/sdb
HEADER=/root/hidden_header
cryptsetup luksFormat --type luks1 $DEVICE
dd if=/dev/urandom of=$HEADER bs=4096 count=1
cryptsetup luksHeaderBackup --header-backup-file $HEADER $DEVICE
cryptsetup open --header $HEADER $DEVICE hidden_container
mkfs.ext4 /dev/mapper/hidden_container
mkdir -p /mnt/hidden
mount /dev/mapper/hidden_container /mnt/hidden
chmod 700 /mnt/hidden
EOF
chmod +x /usr/local/bin/hidden-luks.sh

#-------------------------------
# 7) SSH hardening
#-------------------------------
sed -i 's/^#PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
echo "AllowUsers ossecure" >> /etc/ssh/sshd_config
systemctl restart sshd

#-------------------------------
# 8) Custom hardened kernel (Secure Boot ready)
#-------------------------------
mkdir -p /usr/src/kernel
cd /usr/src/kernel
# Assuming /root/custom_kernel.config is included in ISO
cp /root/custom_kernel.config .config

# Build kernel
dnf install -y ncurses-devel bc bison flex elfutils-libelf-devel openssl-devel pesign
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.7.1.tar.xz
tar xf linux-6.7.1.tar.xz
cd linux-6.7.1
cp /root/custom_kernel.config .config
make -j$(nproc) bzImage modules
make modules_install
make install

# Sign kernel modules
for mod in $(find /lib/modules/$(uname -r)/ -type f -name '*.ko'); do
    pesign --sign --key /root/secureboot.key --cert /root/secureboot.crt --in "$mod" --out "$mod"
done
grub2-mkconfig -o /boot/grub2/grub.cfg

#-------------------------------
# 9) Plymouth theme
#-------------------------------
plymouth-set-default-theme -R ossecure

%end
