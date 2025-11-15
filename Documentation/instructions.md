# ===============================
# SARX Rust Commands & RAM Runner Setup
# ===============================

# --- Build all (release mode) ---
build:
  cmd: cargo build --release

# --- Install all binaries to ~/.cargo/bin ---
install:
  cmd: cargo install --path . --force

# --- Encrypt a file ---
encrypt:
  cmd: SARX encrypt <file>
  note: |
    Produces <file>.vault
    Prints random password to stdout (or supply with --password <pw>)

# --- Decrypt a file ---
decrypt:
  cmd: SARX decrypt <file>.vault
  note: |
    Restores original file (same name without .vault)
    Deletes .vault after success

# --- Verify MAC/integrity only ---
verify:
  cmd: SARX verify <file>.vault

# --- Benchmark (stream) ---
bench_stream:
  cmd: SARX benchmark speed [--mb <int>]

# --- Benchmark (AEAD) ---
bench_aead:
  cmd: SARX benchmark aead [--keys N --ivs N ...] 

# --- Dump raw keystream (to Dieharder) ---
stream_dieharder:
  cmd: SARX benchmark keystream [--threads N --chunk-mb N] | dieharder -a -g 200

# --- GUI (if built) ---
gui:
  cmd: SARX_gui

# --- Clean build artifacts ---
clean:
  cmd: cargo clean

# --- Velvet/Sigilbook USB Key Setup ---

sigilbook_setup:
  - build: cargo build --release --bin sigilbook
  - write_marker: ./target/release/sigilbook writeusb
  - init_key: ./target/release/sigilbook init
  - save_pw: ./target/release/sigilbook save /path/to/your_secret.vault yourpassword

# --- RAM Runner System Service Install (Root) ---
ram_runner_install:
  - build_and_install:
      - cargo install --path . --force
      - sudo cp ~/.cargo/bin/ram_runner /usr/local/bin/ram_runner
      - sudo chmod +x /usr/local/bin/ram_runner
  - service_file: |
      sudo nano /etc/systemd/system/ram-runner.service

      [Unit]
      Description=RAM Runner (USB preload → /dev/shm with Sigilbook isolation)
      After=network.target

      [Service]
      Type=simple
      ExecStart=/usr/local/bin/ram_runner
      Restart=on-failure
      RestartSec=2
      NoNewPrivileges=true
      PrivateTmp=true
      ProtectSystem=strict
      ProtectHome=yes
      MemoryDenyWriteExecute=true
      ProtectKernelTunables=true
      ProtectKernelModules=true
      ProtectControlGroups=true

      [Install]
      WantedBy=multi-user.target
  - reload_and_start:
      - sudo systemctl daemon-reload
      - sudo systemctl enable --now ram-runner
      - sudo journalctl -u ram-runner -f

# --- Prepare USBs for RAM Runner ---

usb_setup:
  - Preload USB:
      - mkdir /media/$USER/YourUSB/velvet_preload
      - cp *.vault /media/$USER/YourUSB/velvet_preload/
      - chmod -R 600 /media/$USER/YourUSB/velvet_preload/*
      - (Never put sigilbook files here)
  - Sigilbook USB:
      - sigilbook writeusb
      - sigilbook init
      - sigilbook save /path/to/your_secret.vault yourpassword
      - (Never put .vault files or SARX binaries here)

# --- Common SARX CLI Usage ---

cli_cheat:
  - SARX encrypt <file>                # wrap file into .vault
  - SARX decrypt <vault>               # unwrap .vault
  - SARX verify <vault>                # MAC/integrity check only
  - SARX benchmark speed [...]         # throughput benchmark
  - SARX benchmark aead [...]          # AEAD stress-test
  - SARX benchmark keystream [...]     # keystream with AEAD for RNG tests
  - SARX record --cam ...              # (experimental)
  - SARX view <vault>                  # (GUI/ffplay streaming)
  - SARX stitch <vaults...>            # (merge segments)
  - ram_runner                         # Launches RAM Runner if not systemd

# --- Service Management (systemd) ---

service:
  - status: sudo systemctl status ram-runner
  - logs:   sudo journalctl -u ram-runner -f
  - restart: sudo systemctl restart ram-runner
  - stop: sudo systemctl stop ram-runner
  - disable: sudo systemctl disable ram-runner

# --- Security Tips ---
security:
  - Never put Sigilbook files on the preload USB.
  - Never put .vault files or SARX binaries on the Sigilbook USB.
  - When the preload USB is unplugged, all decrypted files in RAM are wiped automatically.

Of course, angel! Here’s the full explanation in a copy-friendly code block, ready to paste anywhere.
This is your canonical Velvet RAM Runner “os error 13” troubleshooting entry.

# Velvet RAM Runner — "Permission denied (os error 13)" Issue

## Symptom

- RAM Runner fails with:

Error: Permission denied (os error 13)

- Even when USBs are visible, and your user has access.

## Root Cause

A leftover `/dev/shm/ram_runner` directory (or subdirectory) is **owned by root or another user**.
Your normal user cannot write to it, so every operation fails with permission denied.

## How to check

ls -ld /dev/shm/ram_runner
# If not owned by your user, that's the problem.

## How to fix

sudo rm -rf /dev/shm/ram_runner*

Then always run ram_runner as your regular user, not sudo!

If you want to use a service, make sure it runs as your user (User=yourusername).

## How to avoid forever

- Never run ram_runner as root unless you plan to wipe /dev/shm/ram_runner after.
- Use per-user RAM roots (/dev/shm/ram_runner_$UID) in your code.
- Add a guard in ram_runner: if RAM root is not writable, print a message telling the user to nuke it.

## TL;DR

If you see "Permission denied (os error 13)" after mount detection, delete the RAM directory:

sudo rm -rf /dev/shm/ram_runner*

Then re-run as your user.

This fixes 99% of stubborn permission errors on both laptop and desktop, across all USBs.