#!/bin/bash

# Fix script for DefendShield Vulnerable Server
# Fixes Telnet service and Elasticsearch Docker image issues

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

echo "[+] Starting Fixes..."

# ------------------------------------------------------------------
# 1. Fix Telnet Service (inetd -> xinetd)
# ------------------------------------------------------------------
echo "[+] Fixing Telnet Service..."

# Ensure packages are installed
apt-get install -y xinetd telnetd

# Configure xinetd for telnet
if [ -d "/etc/xinetd.d" ]; then
    echo "[+] Creating /etc/xinetd.d/telnet configuration..."
    cat <<EOF > /etc/xinetd.d/telnet
service telnet
{
    disable = no
    flags = REUSE
    socket_type = stream
    wait = no
    user = root
    server = /usr/sbin/in.telnetd
    log_on_failure += USERID
}
EOF
fi

echo "[+] Restarting xinetd..."
systemctl stop inetd 2>/dev/null
systemctl disable inetd 2>/dev/null
systemctl enable xinetd
systemctl restart xinetd

# ------------------------------------------------------------------
# 2. Fix Elasticsearch Docker Image (Manifest Error)
# ------------------------------------------------------------------
echo "[+] Fixing Elasticsearch Docker Image..."

# Create a directory for the custom build
mkdir -p es_vuln

# Create Dockerfile to build ES 1.4.2 locally
# (This bypasses the deprecated manifest issue on Docker Hub)
cat <<EOF > es_vuln/Dockerfile
FROM openjdk:8-jre

# Download and install Elasticsearch 1.4.2
RUN wget https://download.elastic.co/elasticsearch/elasticsearch/elasticsearch-1.4.2.tar.gz && \\
    tar xzf elasticsearch-1.4.2.tar.gz && \\
    mv elasticsearch-1.4.2 /elasticsearch && \\
    rm elasticsearch-1.4.2.tar.gz

WORKDIR /elasticsearch

# Explicitly enable dynamic scripting (Vulnerability)
RUN echo 'script.disable_dynamic: false' >> /elasticsearch/config/elasticsearch.yml

# Expose ports
EXPOSE 9200 9300

# Start Elasticsearch
CMD ["/elasticsearch/bin/elasticsearch"]
EOF

# Update docker-compose.yml to use 'build' instead of 'image'
if [ -f "docker-compose.yml" ]; then
    echo "[+] Updating docker-compose.yml..."
    sed -i 's|image: elasticsearch:1.4.2|build: ./es_vuln|' docker-compose.yml
    
    echo "[+] Rebuilding and restarting containers..."
    docker-compose up -d --build
else
    echo "[-] docker-compose.yml not found! Skipping Docker fix."
fi

echo "[+] All fixes applied."
