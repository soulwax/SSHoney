make install
cp util/sshoney.service /etc/systemd/system/
systemctl daemon-reload
systemctl restart sshoney