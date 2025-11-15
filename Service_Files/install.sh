#!/usr/bin/env bash
set -e

echo "Installing SARX Vault Handler..."

# Copy the handler script
install -m 755 ./sarx-vault-handler /usr/local/bin/sarx-vault-handler

# Copy the desktop file
install -m 644 ./sarx-vault.desktop /usr/share/applications/sarx-vault.desktop

# Copy the MIME XML definition
install -m 644 ./sarx-vault.xml /usr/share/mime/packages/sarx-vault.xml

# Install the systemd service for RAM runner
install -m 644 ./ram-runner.service /etc/systemd/system/ram-runner.service

# Reload systemd units and enable+start the service
systemctl daemon-reload
systemctl enable --now ram-runner.service

# Update MIME and desktop database
update-mime-database /usr/share/mime
update-desktop-database /usr/share/applications

echo "SARX Vault Handler installed!"
echo "ram-runner.service installed and enabled."
echo "You can now double-click .vault files to decrypt and re-encrypt them."
