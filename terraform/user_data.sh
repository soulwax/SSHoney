#!/bin/bash
# File: terraform/user_data.sh
set -euo pipefail

# Update system
apt-get update
apt-get upgrade -y

# Install dependencies
apt-get install -y \
build-essential \
docker.io \
docker-compose \
awscli \
amazon-cloudwatch-agent \
fail2ban

# Configure CloudWatch agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/var/log/sshoney/*.log",
                        "log_group_name": "/aws/ec2/${project_name}",
                        "log_stream_name": "{instance_id}/sshoney"
                    }
                ]
            }
        }
    },
    "metrics": {
        "namespace": "SSHoney",
        "metrics_collected": {
            "cpu": {
                "measurement": ["cpu_usage_idle", "cpu_usage_iowait"],
                "metrics_collection_interval": 60
            },
            "mem": {
                "measurement": ["mem_used_percent"],
                "metrics_collection_interval": 60
            },
            "netstat": {
                "measurement": ["tcp_established", "tcp_time_wait"],
                "metrics_collection_interval": 60
            }
        }
    }
}
EOF

# Start CloudWatch agent
systemctl enable amazon-cloudwatch-agent
systemctl start amazon-cloudwatch-agent

# Clone and build SSHoney
cd /opt
git clone https://github.com/your-repo/sshoney.git
cd sshoney

# Build SSHoney
make CFLAGS="-std=c99 -Wall -Wextra -O2 -fstack-protector-strong -fPIE" \
LDFLAGS="-Wl,-z,relro,-z,now -pie"

# Install SSHoney
cp sshoney /usr/local/bin/
chmod +x /usr/local/bin/sshoney
setcap 'cap_net_bind_service=+ep' /usr/local/bin/sshoney

# Create sshoney user
useradd -r -s /bin/false -d /var/lib/sshoney sshoney

# Create directories
mkdir -p /etc/sshoney /var/log/sshoney /var/lib/sshoney
chown sshoney:sshoney /var/log/sshoney /var/lib/sshoney

# Configure SSHoney
cat > /etc/sshoney/config << 'EOF'
Port 22
Delay 10000
MaxLineLength 32
MaxClients 4096
LogLevel 1
BindFamily 0
EOF

# Install systemd service
cp sshoney.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable sshoney

# Configure SSH
sed -i 's/^#*Port 22/Port ${ssh_port}/' /etc/ssh/sshd_config
systemctl restart sshd

# Configure fail2ban for SSH protection
cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = ${ssh_port}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

systemctl enable fail2ban
systemctl start fail2ban

# Start SSHoney
systemctl start sshoney

# Set up monitoring with Docker
docker-compose -f /opt/sshoney/docker-compose.yml up -d prometheus grafana

echo "SSHoney deployment completed successfully!"