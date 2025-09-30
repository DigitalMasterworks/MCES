#!/usr/bin/env bash
set -e

echo "Installing MCES Vault Handler..."

# Copy the handler script
install -m 755 ./mces-vault-handler /usr/local/bin/mces-vault-handler

# Copy the desktop file
install -m 644 ./mces-vault.desktop /usr/share/applications/mces-vault.desktop

# Copy the MIME XML definition
install -m 644 ./mces-vault.xml /usr/share/mime/packages/mces-vault.xml

# Update MIME and desktop database
update-mime-database /usr/share/mime
update-desktop-database /usr/share/applications

echo "MCES Vault Handler installed!"
echo "You can now double-click .vault files to decrypt and re-encrypt them."