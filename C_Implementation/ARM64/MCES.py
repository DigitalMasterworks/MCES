#!/usr/bin/env python3
# MCES.py

import os, sys, subprocess
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QTextEdit, QFileDialog, QInputDialog, QLineEdit
)

MCES_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_EXT = ".vault"

# ---------- helpers ----------
def prompt_password(parent, prompt):
    text, ok = QInputDialog.getText(
        parent, "Enter Password", prompt,
        echo=QLineEdit.EchoMode.Password
    )
    if ok and text:
        return text
    return None

def _current_user():
    return (os.environ.get("USER") or os.environ.get("LOGNAME")
            or os.environ.get("USERNAME") or "")

def usb_key_present() -> bool:
    user = _current_user()
    bases = [f"/media/{user}", f"/run/media/{user}", "/Volumes"]
    for base in bases:
        if os.path.isdir(base):
            for d in os.listdir(base):
                if os.path.isfile(os.path.join(base, d, "VELVETKEY.info")):
                    return True
    return False

def sigilbook_get(vault_path: str) -> Optional[str]:
    try:
        p = subprocess.run(
            ["python3", os.path.join(MCES_DIR, "sigilbook.py"), "get", vault_path],
            capture_output=True, text=True
        )
        if p.returncode != 0:
            return None
        s = p.stdout.strip()
        # extra safety: ignore obvious error lines even if returncode was 0
        if not s or s.lower().startswith(("error", "no key", "not found")):
            return None
        return s
    except Exception:
        return None

def sigilbook_save(vault_path: str, password: str) -> bool:
    try:
        p = subprocess.run(["python3", os.path.join(MCES_DIR, "sigilbook.py"), "save", vault_path, password],
                           capture_output=True, text=True)
        return p.returncode == 0
    except Exception:
        return False

def get_password():
         usb_password = try_usb_key()
         if usb_password:
             return usb_password
         else:
             # Prompt for password if USB not detected
             password = simpledialog.askstring(
                 "USB Key Not Detected",
                 "USB key not found! Please enter your password manually:",
                 show='*'
             )
             if not password:
                 messagebox.showerror("Encryption Cancelled", "No password entered.")
                 return None
             return password

def safe_remove(path):
    try:
        os.remove(path)
    except Exception as e:
        print(f"Could not remove {path}: {e}")

def call_encrypt(path: str):
    proc = subprocess.run([os.path.join(MCES_DIR, "mces_encrypt"), path],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return False, "", proc.stderr.strip()
    pw = (proc.stdout.strip().splitlines() or [""])[0]
    return True, pw, ""

def call_decrypt(vault_path: str, password: str):
    proc = subprocess.Popen([os.path.join(MCES_DIR, "mces_decrypt"), vault_path],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate(password + "\n")
    if proc.returncode != 0:
        return False, err.strip()
    return True, ""

# ---------- workers ----------

class EncryptWorker(QThread):
    line = pyqtSignal(str)
    done = pyqtSignal()

    def __init__(self, paths, save_to_key: bool, user_password: Optional[str] = None):
        super().__init__()
        self.paths = paths
        self.save_to_key = save_to_key
        self.user_password = user_password
        
    def run(self):
        for p in self.paths:
            if self.user_password:  # use user-supplied password
                proc = subprocess.run(
                    [os.path.join(MCES_DIR, "mces_encrypt"), "pw", self.user_password, p],
                    capture_output=True, text=True
                )
            else:  # generate random
                proc = subprocess.run(
                    [os.path.join(MCES_DIR, "mces_encrypt"), p],
                    capture_output=True, text=True
                )
            base = os.path.basename(p)
            if proc.returncode != 0:
                self.line.emit(f"[encrypt][{base}] ERROR: {proc.stderr.strip()}")
                continue

            # Get password for display/sigilbook save
            if self.user_password:
                pw = self.user_password
            else:
                # --- Try to find the password after "Password:" or as the last non-empty line
                lines = proc.stdout.strip().splitlines()
                pw = ""
                for line in lines:
                    if "Password:" in line:
                        pw = line.split("Password:", 1)[1].strip()
                        if pw:
                            break
                if not pw:
                    # fallback: if not found, try last non-empty line (just in case)
                    for line in reversed(lines):
                        if line and "Encrypted" not in line:
                            pw = line.strip()
                            break

            # Remove original file after encrypt (if still present)
            try:
                os.remove(p)
            except Exception:
                pass
            self.line.emit(f"[encrypt][{base}] password: {pw}")
            if self.save_to_key:
                if usb_key_present():
                    if sigilbook_save(p + VAULT_EXT, pw):
                        self.line.emit("[sigilbook] Saved.")
                    else:
                        self.line.emit("[sigilbook] Save failed.")
                else:
                    self.line.emit("[sigilbook] USB key not detected; skipped save.")
        self.done.emit()

class DecryptWorker(QThread):
    line = pyqtSignal(str)
    done = pyqtSignal()
    password_needed = pyqtSignal(str, int)  # (vault_path, index)

    def __init__(self, vault_paths):
        super().__init__()
        self.vault_paths = vault_paths
        self.passwords = [None] * len(vault_paths)
        self._index_waiting = None

    def set_password(self, pw):
        if self._index_waiting is not None:
            self.passwords[self._index_waiting] = pw
            self._index_waiting = None
            self.start()  # Continue where left off

    def run(self):
        for i, p in enumerate(self.vault_paths):
            vpath = self._normalize_vault(p)
            if vpath is None:
                self.line.emit(f"[decrypt][{os.path.basename(p)}] skipped (not a vault file).")
                continue
            pw = sigilbook_get(vpath)
            if pw is None or pw.strip() == '':
                # Pause thread and ask main thread to prompt for password
                self._index_waiting = i
                self.password_needed.emit(vpath, i)
                return  # Pause execution here
            ok, err = call_decrypt(vpath, pw)
            if ok:
                self.line.emit(f"[decrypt][{os.path.basename(vpath)}] OK")
            else:
                self.line.emit(f"[decrypt][{os.path.basename(vpath)}] ERROR: {err}")
        self.done.emit()

# ---------- UI ----------

class MCESWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MCES")
        self.setMinimumSize(720, 420)

        top = QHBoxLayout()
        self.usb_status = QLabel("USB Key: Not detected")
        self.save_ck = QCheckBox("Save password to key")
        self.save_ck.setChecked(True)
        top.addWidget(self.usb_status)
        top.addStretch(1)
        top.addWidget(self.save_ck)
        self.user_pw_ck = QCheckBox("User provided password?")
        self.user_pw_ck.setChecked(False)
        top.addWidget(self.user_pw_ck)

        self.btn_encrypt = QPushButton("ENCRYPT")
        self.btn_decrypt = QPushButton("DECRYPT")
        self.btn_encrypt.setMinimumHeight(48)
        self.btn_decrypt.setMinimumHeight(48)

        self.btn_encrypt.clicked.connect(self.encrypt_files)
        self.btn_decrypt.clicked.connect(self.decrypt_files)

        self.log = QTextEdit()
        self.log.setReadOnly(True)

        root = QVBoxLayout(self)
        root.addLayout(top)
        root.addWidget(self.btn_encrypt)
        root.addWidget(self.btn_decrypt)
        root.addWidget(self.log, 1)

        self._usb_timer = QTimer(self)
        self._usb_timer.timeout.connect(self.refresh_usb)
        self._usb_timer.start(1200)
        self.refresh_usb()

        self.worker = None

    def refresh_usb(self):
        self.usb_status.setText("USB Key: Detected" if usb_key_present() else "USB Key: Not detected")

    def encrypt_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose files to encrypt")
        if not paths:
            return

        user_password = None
        if self.user_pw_ck.isChecked():
            user_password, ok = QInputDialog.getText(
                self, "Enter Password", "Enter password (30–100 Unicode chars):",
                echo=QLineEdit.EchoMode.Password
            )
            if not ok or not user_password:
                self.log.append("Encryption cancelled: no password entered.")
                return

        self.worker = EncryptWorker(paths, self.save_ck.isChecked(), user_password)
        self.worker.line.connect(self.log.append)
        self.worker.done.connect(lambda: self.log.append("Encrypt complete."))
        self.worker.start()

    def decrypt_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Choose vault files to decrypt",
            filter="Vault Files (*.vault);;All Files (*)"
        )
        if not paths:
            return

        for p in paths:
            vpath = p if p.endswith(VAULT_EXT) else p + VAULT_EXT
            pw = sigilbook_get(vpath) if usb_key_present() else None
            used_auto = False

            if pw:
                ok, err = call_decrypt(vpath, pw)
                used_auto = True
                if ok:
                    self.log.append(f"[decrypt][{os.path.basename(vpath)}] OK (key)")
                    continue
                else:
                    self.log.append(
                        f"[decrypt][{os.path.basename(vpath)}] key password failed ({err}); prompting…"
                    )

            while True:
                pw2, ok = QInputDialog.getText(
                    self, "Enter Password",
                    f"Enter password for {os.path.basename(vpath)}:",
                    echo=QLineEdit.EchoMode.Password
                )
                if not ok or not pw2:
                    self.log.append(f"[decrypt][{os.path.basename(vpath)}] no password entered; skipped.")
                    break

                ok2, err2 = call_decrypt(vpath, pw2)
                if ok2:
                    self.log.append(f"[decrypt][{os.path.basename(vpath)}] OK")
                    break
                else:
                    self.log.append(f"[decrypt][{os.path.basename(vpath)}] ERROR: {err2}")
                    if "HMAC mismatch" in err2:
                        continue
                    else:
                        break

        self.log.append("Decrypt complete.")
# ---------- main ----------

def main():
    app = QApplication(sys.argv)
    win = MCESWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()