#!/usr/bin/env bash
set -e

echo "Installing SARX Vault Handler..."

# Copy the handler script
install -m 755 ./sarx-vault-handler /usr/local/bin/sarx-vault-handler

# Copy the desktop file
install -m 644 ./sarx-vault.desktop /usr/share/applications/sarx-vault.desktop

# Copy the MIME XML definition
install -m 644 ./sarx-vault.xml /usr/share/mime/packages/sarx-vault.xml

# Update MIME and desktop database
update-mime-database /usr/share/mime
update-desktop-database /usr/share/applications

echo "SARX Vault Handler installed!"
echo "You can now double-click .vault files to decrypt and re-encrypt them."