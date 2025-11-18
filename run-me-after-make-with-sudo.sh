make install

mv ./sshoney /usr/local/bin/

# Install service file
cp util/sshoney.service /etc/systemd/system/

# Create sshoney user (required by service)
useradd -r -s /bin/false -d /var/lib/sshoney sshoney

# Create directories
mkdir -p /var/lib/sshoney
chown sshoney:sshoney /var/lib/sshoney

# Configure for privileged ports
setcap 'cap_net_bind_service=+ep' /usr/local/bin/sshoney

# Create configuration
mkdir -p /etc/sshoney
echo "Port 22" | sudo tee /etc/sshoney/config
chown root:root /etc/sshoney/config
chmod 644 /etc/sshoney/config

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl --now enable sshoney

