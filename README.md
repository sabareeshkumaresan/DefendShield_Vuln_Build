# DefendShield Vulnerable Server Build

This project contains a deployment script to transform a fresh Ubuntu Server into a highly vulnerable target for penetration testing training.

**WARNING: DO NOT DEPLOY THIS ON A PUBLIC NETWORK OR A PRODUCTION ENVIRONMENT. IT IS INTENTIONALLY INSECURE.**

## Features

### 1. Network Vulnerabilities & Misconfigurations
- **Anonymous FTP**: `vsftpd` configured to allow anonymous login and uploads.
- **Insecure Telnet**: `telnetd` installed and enabled (cleartext communication).
- **Open Samba Share**: A public, writable Samba share (`/srv/samba/public`).
- **NFS Export**: `/srv/nfs/share` exported with `no_root_squash` (allows root access).
- **Backdoor**: A Python-based reverse shell listener on port 1337.
- **Distcc**: Distributed C/C++ compiler daemon (Port 3632) vulnerable to RCE.
- **Redis**: Unauthenticated Redis server (Port 6379) allowing RCE.
- **PostgreSQL**: Weak credentials (`postgres`/`postgres`) and remote access enabled.
- **VNC**: VNC Server (Port 5901) with weak password (`password`).
- **SNMP**: SNMP (Port 161) with `public` community string.
- **Docker API**: Unauthenticated Docker Socket exposed on Port 2375 (Root Access).
- **Weak SSH Credentials**: User accounts with weak passwords.

### 2. System Misconfigurations
- **SUID Binaries**: `find`, `vim`, `cp` set with SUID bit.
- **Capabilities**: `python3` has `cap_setuid+ep` set, allowing easy privilege escalation.
- **Weak File Permissions**: Sensitive files world-readable or writable.
- **Insecure Users**:
  - `admin` / `password123`
  - `dev` / `123456`
  - `guest` / `guest`
- **Cron Jobs**: A vulnerable cron job running a script that is writable by low-privilege users.

### 3. Web Application Vulnerabilities
The script installs Docker and deploys the following vulnerable apps:
- **OWASP Juice Shop**: Port 3000
- **DVWA (Damn Vulnerable Web App)**: Port 8081
- **Mutillidae II**: Port 8082
- **Apache Tomcat**: Port 8080 (Manager App vulnerable to WAR upload)
- **Elasticsearch**: Port 9200 (CVE-2014-3120 RCE)
- **Jenkins**: Port 8083 (Unauthenticated Script Console RCE)
- **Custom Vulnerable PHP App**: Hosted on the main Apache server (Port 80), featuring:
  - SQL Injection
  - Remote Code Execution (RCE)
  - Local File Inclusion (LFI)

## Usage

1. Provision a fresh Ubuntu VM (20.04 or 22.04 recommended).
2. Transfer `deploy.sh` and `docker-compose.yml` to the VM.
3. Run the script:
   ```bash
   sudo chmod +x deploy.sh
   sudo ./deploy.sh
   ```
