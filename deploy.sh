#!/bin/bash

# DefendShield Vulnerable Server Deployment Script
# WARNING: This script intentionally makes the system insecure.

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

echo "[+] Starting Vulnerable Server Build..."

# 1. Update and Install Packages
echo "[+] Updating system and installing packages..."
apt-get update -y
apt-get install -y apache2 php libapache2-mod-php vsftpd samba telnetd net-tools docker.io docker-compose nmap vim git xinetd nfs-kernel-server libcap2-bin distcc redis-server postgresql postgresql-contrib tightvncserver snmp snmpd

# 2. User Configuration (Weak Passwords)
echo "[+] Creating users with weak credentials..."
# Create 'admin' user with password 'password123'
useradd -m -s /bin/bash admin
echo "admin:password123" | chpasswd
usermod -aG sudo admin

# Create 'dev' user with password '123456'
useradd -m -s /bin/bash dev
echo "dev:123456" | chpasswd

# Create 'guest' user with no password (if ssh allows) or weak password
useradd -m -s /bin/bash guest
echo "guest:guest" | chpasswd

# 3. Network Misconfigurations

## FTP - Anonymous Access
echo "[+] Configuring VSFTPD for anonymous access..."
cp /etc/vsftpd.conf /etc/vsftpd.conf.bak
cat <<EOF > /etc/vsftpd.conf
listen=NO
listen_ipv6=YES
anonymous_enable=YES
local_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
EOF
systemctl restart vsftpd

## Samba - Public Share
echo "[+] Configuring Samba public share..."
mkdir -p /srv/samba/public
chmod 777 /srv/samba/public
cat <<EOF >> /etc/samba/smb.conf
[public]
   path = /srv/samba/public
   browseable = yes
   read only = no
   guest ok = yes
EOF
systemctl restart smbd

## Telnet
echo "[+] Ensuring Telnet is running..."
# Telnetd usually runs via inetd/xinetd. 
systemctl enable inetd
systemctl start inetd

## NFS - Vulnerable Export
echo "[+] Configuring NFS with no_root_squash..."
mkdir -p /srv/nfs/share
chmod 777 /srv/nfs/share
echo "/srv/nfs/share *(rw,sync,no_root_squash,no_subtree_check)" >> /etc/exports
exportfs -a
systemctl restart nfs-kernel-server

## Backdoor Listener
echo "[+] Setting up a simple backdoor on port 1337..."
cat <<EOF > /etc/systemd/system/backdoor.service
[Unit]
Description=Backdoor Service
[Service]
ExecStart=/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",1337));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0); os.dup2(conn.fileno(),1); os.dup2(conn.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor.service
systemctl start backdoor.service

## Distcc - RCE Vulnerability
echo "[+] Configuring Distcc for remote access..."
sed -i 's/STARTDISTCC="false"/STARTDISTCC="true"/' /etc/default/distcc
sed -i 's/ALLOWEDNETS="127.0.0.1"/ALLOWEDNETS="0.0.0.0\/0"/' /etc/default/distcc
sed -i 's/LISTENER="127.0.0.1"/LISTENER="0.0.0.0"/' /etc/default/distcc
systemctl restart distcc

## Redis - Unauthenticated Access
echo "[+] Configuring Redis to be vulnerable..."
sed -i 's/^bind 127.0.0.1 ::1/# bind 127.0.0.1 ::1/' /etc/redis/redis.conf
sed -i 's/^protected-mode yes/protected-mode no/' /etc/redis/redis.conf
systemctl restart redis-server

## PostgreSQL - Weak Credentials & Remote Access
echo "[+] Configuring PostgreSQL..."
# Set password for 'postgres' user
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'postgres';"
# Allow remote connections
echo "host all all 0.0.0.0/0 md5" >> /etc/postgresql/*/main/pg_hba.conf
echo "listen_addresses = '*'" >> /etc/postgresql/*/main/postgresql.conf
systemctl restart postgresql

## VNC - Weak Password
echo "[+] Configuring VNC Server..."
mkdir -p /home/guest/.vnc
# Create VNC password 'password'
echo "password" | vncpasswd -f > /home/guest/.vnc/passwd
chmod 600 /home/guest/.vnc/passwd
chown -R guest:guest /home/guest/.vnc
# Start VNC as guest
su - guest -c "vncserver :1 -geometry 1280x800 -depth 24"

## SNMP - Public Community String
echo "[+] Configuring SNMP..."
sed -i 's/agentAddress  udp:127.0.0.1:161/agentAddress udp:161/' /etc/snmp/snmpd.conf
sed -i 's/rocommunity public  default/rocommunity public/' /etc/snmp/snmpd.conf
# Ensure it listens on all interfaces and accepts public
echo "rocommunity public" >> /etc/snmp/snmpd.conf
systemctl restart snmpd

## Docker API - Exposed Socket
echo "[+] Exposing Docker API (Dangerous)..."
sed -i 's/ExecStart=\/usr\/bin\/dockerd -H fd:\/\/ --containerd=\/run\/containerd\/containerd.sock/ExecStart=\/usr\/bin\/dockerd -H fd:\/\/ -H tcp:\/\/0.0.0.0:2375 --containerd=\/run\/containerd\/containerd.sock/' /lib/systemd/system/docker.service
systemctl daemon-reload
systemctl restart docker

# 4. System Misconfigurations

## SUID Binaries (Privilege Escalation vectors)
echo "[+] Setting SUID bits on common binaries..."
chmod u+s /usr/bin/find
chmod u+s /usr/bin/vim.basic 2>/dev/null || chmod u+s /usr/bin/vim
# If nmap is installed and supports interactive mode (older versions did, newer don't usually, but good for checking)
# We can try to install an older netcat or just set SUID on bash (very dangerous)
# Let's stick to 'find' and 'vim' which are classic GTFOBins.
chmod u+s /bin/cp

## Capabilities (Privilege Escalation)
echo "[+] Setting dangerous capabilities on Python..."
setcap cap_setuid+ep /usr/bin/python3

## Weak File Permissions
echo "[+] Creating weak file permissions..."
# Create a "secret" backup file that is world readable
echo "DB_PASSWORD=SuperSecretPassword!@#" > /root/db_backup.config
chmod 644 /root/db_backup.config
# Move it to a slightly accessible place or just leave in root but maybe /opt
mv /root/db_backup.config /opt/db_backup.config

# Writable /etc/passwd (Extreme vulnerability - maybe too much? Let's stick to writable cron)
# echo "[!] WARNING: Making /etc/passwd writable (optional, commented out)"
# # chmod o+w /etc/passwd

## Vulnerable Cron Job
echo "[+] Setting up vulnerable cron job..."
echo "#!/bin/bash" > /usr/local/bin/cleanup.sh
echo "rm -rf /tmp/*" >> /usr/local/bin/cleanup.sh
chmod 777 /usr/local/bin/cleanup.sh
echo "* * * * * root /usr/local/bin/cleanup.sh" >> /etc/crontab

# 5. Web Application Vulnerabilities (Host Based)

echo "[+] Deploying host-based vulnerable PHP app..."
rm /var/www/html/index.html
cat <<EOF > /var/www/html/index.php
<!DOCTYPE html>
<html>
<head><title>Vulnerable App</title></head>
<body>
<h1>Welcome to the DefendShield Vulnerable Server</h1>
<p>Try to hack me!</p>
<hr>
<h2>Ping Tool (RCE)</h2>
<form method="GET">
    IP Address: <input type="text" name="ip">
    <input type="submit" value="Ping">
</form>
<pre>
<?php
if(isset(\$_GET['ip'])) {
    \$ip = \$_GET['ip'];
    // Vulnerability: Command Injection
    system("ping -c 1 " . \$ip);
}
?>
</pre>
<hr>
<h2>User Search (SQL Injection)</h2>
<p>Note: Database not connected, but code is vulnerable if it were.</p>
<form method="GET">
    User ID: <input type="text" name="id">
    <input type="submit" value="Search">
</form>
<?php
if(isset(\$_GET['id'])) {
    \$id = \$_GET['id'];
    echo "Searching for user with ID: " . \$id;
    // Vulnerability: Reflected XSS (if input contains script tags)
}
?>
</body>
</html>
EOF
chown www-data:www-data /var/www/html/index.php
systemctl restart apache2

# 6. Web Application Vulnerabilities (Docker)

echo "[+] Deploying Dockerized Vulnerable Apps..."
# Ensure tomcat-users.xml exists
if [ ! -f "tomcat-users.xml" ]; then
    echo "[+] Creating tomcat-users.xml..."
    cat <<EOF > tomcat-users.xml
<tomcat-users>
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <role rolename="manager-jmx"/>
  <role rolename="manager-status"/>
  <user username="tomcat" password="tomcat" roles="manager-gui,manager-script,manager-jmx,manager-status"/>
</tomcat-users>
EOF
fi
# Assuming docker-compose.yml is in the same directory
if [ -f "docker-compose.yml" ]; then
    docker-compose up -d
else
    echo "[-] docker-compose.yml not found! Downloading a default one..."
    # Fallback if file missing
    cat <<DOCKER > docker-compose.yml
version: '3'
services:
  juice-shop:
    image: bkimminich/juice-shop
    container_name: juice-shop
    restart: always
    ports:
      - "3000:3000"
  dvwa:
    image: vulnerables/web-dvwa
    container_name: dvwa
    restart: always
    ports:
      - "8081:80"
    environment:
      - MYSQL_ROOT_PASSWORD=password
  mutillidae:
    image: citizenstig/nowasp
    container_name: mutillidae
    restart: always
    ports:
      - "8082:80"
    environment:
      - MYSQL_ROOT_PASSWORD=password
  tomcat:
    image: tomcat:9.0
    container_name: tomcat
    restart: always
    ports:
      - "8080:8080"
    environment:
      - TOMCAT_USERNAME=tomcat
      - TOMCAT_PASSWORD=tomcat
    volumes:
      - ./tomcat-users.xml:/usr/local/tomcat/conf/tomcat-users.xml
  elasticsearch:
    image: elasticsearch:1.4.2
    container_name: elasticsearch
    restart: always
    ports:
      - "9200:9200"
      - "9300:9300"
  jenkins:
    image: jenkins/jenkins:lts
    container_name: jenkins
    restart: always
    ports:
      - "8083:8080"
      - "50000:50000"
    environment:
      - JAVA_OPTS=-Djenkins.install.runSetupWizard=false
DOCKER
    docker-compose up -d
fi

echo "[+] Build Complete!"
echo "------------------------------------------------"
echo "Access the vulnerabilities at:"
echo " - Web (RCE/XSS): http://<IP>/"
echo " - Juice Shop: http://<IP>:3000/"
echo " - DVWA: http://<IP>:8081/"
echo " - Mutillidae: http://<IP>:8082/"
echo " - Tomcat: http://<IP>:8080/ (tomcat/tomcat)"
echo " - Jenkins: http://<IP>:8083/ (No Auth/Script Console)"
echo " - Elasticsearch: Port 9200 (RCE)"
echo " - FTP: Port 21 (Anonymous)"
echo " - SSH: Port 22 (admin/password123, dev/123456)"
echo " - SMB: Port 445 (Public share)"
echo " - Telnet: Port 23"
echo " - NFS: Port 2049 (/srv/nfs/share)"
echo " - Distcc: Port 3632 (RCE)"
echo " - Redis: Port 6379 (Unauth RCE)"
echo " - PostgreSQL: Port 5432 (postgres/postgres)"
echo " - VNC: Port 5901 (password: password)"
echo " - SNMP: Port 161 (public)"
echo " - Docker API: Port 2375 (Unauth Root)"
echo " - Backdoor: Port 1337"
echo "------------------------------------------------"
