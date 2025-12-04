#========================================================
# OSSECURE-X Custom Hardened Fedora/RHEL/Rocky/Alma ISO
#========================================================

#--------------------------------------------------------
# 1) Basic configuration
#--------------------------------------------------------
lang en_US.UTF-8
keyboard us
timezone UTC
auth --useshadow --passalgo=sha512
selinux --enforcing --type=mls
firewall --enabled --service=ssh
bootloader --location=mbr --append="quiet splash selinux=1 enforcing=1 mls=1 audit=1 lockdown=confidentiality"

#--------------------------------------------------------
# 2) Disk partitioning — LUKS2 FDE (Argon2id)
#--------------------------------------------------------
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
# 4) POST-INSTALL (HARDENING + TOOLS)
#========================================================
%post --erroronfail
set -x

#--------------------------------------------------------
# 4.0 Secure Boot Key Generator
#--------------------------------------------------------
mkdir -p /root/secureboot
cd /root/secureboot
openssl req -new -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -subj "/CN=OSSECURE-X SECUREBOOT/" \
  -keyout secureboot.key -out secureboot.crt

#--------------------------------------------------------
# 4.1 SELinux MLS + FIPS
#--------------------------------------------------------
dnf install -y selinux-policy-mls
setenforce 1
fips-mode-setup --enable

#--------------------------------------------------------
# 4.2 Kernel Hardening Sysctl
#--------------------------------------------------------
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

#--------------------------------------------------------
# 4.3 Default Systemd Sandboxing
#--------------------------------------------------------
mkdir -p /etc/systemd/system.conf.d
cat <<EOF >/etc/systemd/system.conf.d/99-sandboxing.conf
[Manager]
DefaultMemoryDenyWriteExecute=yes
DefaultRestrictNamespaces=yes
DefaultProtectSystem=strict
DefaultProtectHome=true
DefaultNoNewPrivileges=yes
EOF

#--------------------------------------------------------
# 4.4 RPM Hardening Macros
#--------------------------------------------------------
cat <<EOF >/etc/rpm/macros.ossecure
%_signature gpg
%_gpg_name OSSECURE-X
%__gpg /usr/bin/gpg
%_disable_source_fetch 1
%_binary_payload w6.bzip2
%_source_payload w6.bzip2
EOF

#--------------------------------------------------------
# 4.5 Preinstalled amx-z0
#--------------------------------------------------------
git clone https://github.com/thewifiproject/amx-z0 /opt/amx-z0
cd /opt/amx-z0
pip3 install -r requirements.txt
chmod +x *.py

#--------------------------------------------------------
# 4.6 Install OSINT / Hacking Tools as requested
#--------------------------------------------------------
cd /opt

# Maigret
git clone https://github.com/soxoj/maigret
pip3 install -r maigret/requirements.txt

# Web-check
git clone https://github.com/Lissy93/web-check

# Telegram Map
git clone https://github.com/tejado/telegram-nearby-map

# Holehe
git clone https://github.com/megadose/holehe
pip3 install holehe

# Cameradar
git clone https://github.com/Ullaakut/cameradar

# Ciphey
git clone https://github.com/bee-san/Ciphey
pip3 install ciphey

# Commix
git clone https://github.com/commixproject/commix

# Malicious PDF
git clone https://github.com/jonaslejon/malicious-pdf

# Pupy RAT
git clone https://github.com/n1nj4sec/pupy

# BloodHound
git clone https://github.com/BloodHoundAD/BloodHound.git

#--------------------------------------------------------
# 4.7 Split Security Scripts (SSH/GPG/Monero)
#--------------------------------------------------------
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

#--------------------------------------------------------
# 4.8 Anonymous Connection Wizard
#--------------------------------------------------------
cat <<'EOL' >/usr/local/bin/anon-connect
#!/bin/bash
systemctl enable tor dnscrypt-proxy doh-proxy
systemctl start tor dnscrypt-proxy doh-proxy
iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040
echo "Transparent Tor routing + DNSCrypt enabled"
EOL
chmod +x /usr/local/bin/anon-connect

#--------------------------------------------------------
# 4.9 NSA Igloo Lockdown
#--------------------------------------------------------
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

#--------------------------------------------------------
# 4.10 Enable services at boot
#--------------------------------------------------------
systemctl enable tor dnscrypt-proxy doh-proxy firewalld auditd sshd

#--------------------------------------------------------
# 4.11 NFTables Tor Transparent Proxy
#--------------------------------------------------------
cat <<EOF >/etc/nftables.conf
table inet tor {
  chain prerouting {
    type nat hook prerouting priority -100;
    tcp dport != 22 redirect to 9040
  }
}
EOF
systemctl enable nftables

#--------------------------------------------------------
# 5) Qubes-like Sandboxed Containers
#--------------------------------------------------------
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

#--------------------------------------------------------
# 6) Hidden LUKS Container Generator
#--------------------------------------------------------
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

#--------------------------------------------------------
# 7) SSH Hardening
#--------------------------------------------------------
sed -i 's/^#PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
echo "AllowUsers ossecure" >> /etc/ssh/sshd_config
systemctl restart sshd

#--------------------------------------------------------
# 8) Custom Kernel (NSA/DoD Hardened)
#--------------------------------------------------------
mkdir -p /usr/src/kernel
cd /usr/src/kernel

cp /root/custom_kernel.config .config

dnf install -y ncurses-devel bc bison flex elfutils-libelf-devel openssl-devel pesign

wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.7.1.tar.xz
tar xf linux-6.7.1.tar.xz
cd linux-6.7.1
cp /root/custom_kernel.config .config

make olddefconfig
make -j$(nproc)
make modules_install
make install

for mod in $(find /lib/modules/$(uname -r)/ -type f -name '*.ko'); do
  pesign --sign --key /root/secureboot/secureboot.key --cert /root/secureboot/secureboot.crt --in "$mod" --out "$mod"
done

grub2-mkconfig -o /boot/grub2/grub.cfg

#--------------------------------------------------------
# 9) Plymouth Theme
#--------------------------------------------------------
mkdir -p /usr/share/plymouth/themes/ossecure

cat <<'EOF' >/usr/share/plymouth/themes/ossecure/ossecure.plymouth
[Plymouth Theme]
Name=OSSECURE-X
Description=Hardened Secure Boot Splash
ModuleName=script

[script]
ImageDir=/usr/share/plymouth/themes/ossecure
EOF

cat <<'EOF' >/usr/share/plymouth/themes/ossecure/ossecure.script
screen_width = Window.GetWidth();
screen_height = Window.GetHeight();
logo = Image("logo.png");
logo_x = (screen_width - logo.GetWidth()) / 2;
logo_y = (screen_height - logo.GetHeight()) / 2;
Window.DrawImage(logo, logo_x, logo_y, 255);
EOF

plymouth-set-default-theme -R ossecure

%end
