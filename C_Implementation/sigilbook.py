#!/usr/bin/env python3
import os, sys, json, secrets, hashlib, getpass, unicodedata, shutil
from pathlib import Path
from datetime import datetime
import blake3
import hmac

# === CONFIG ===
ACTIVE_USB_FILE = os.path.expanduser("~/.velvet_last_usb")
USB_KEY_FILENAME = "VELVET_SIGILBOOK.sigil"    # the DB file written on USB
USB_DETECT_LABEL = "VELVETKEY.info"            # marker file for detection
MAGIC = b"SIGL"
VERSION = 1

def get_vault_paths():
    user = getpass.getuser()
    media_dirs = [f"/media/{user}", f"/run/media/{user}"]
    active_uuid = None
    if os.path.exists(ACTIVE_USB_FILE):
        with open(ACTIVE_USB_FILE) as f:
            active_uuid = f.read().strip()
    for base in media_dirs:
        if os.path.isdir(base):
            for d in os.listdir(base):
                mp = os.path.join(base, d)
                marker = os.path.join(mp, USB_DETECT_LABEL)
                if os.path.isfile(marker):
                    with open(marker) as f:
                        marker_info = json.load(f)
                    if not active_uuid or marker_info.get("uuid") == active_uuid:
                        # Lock-in now if unset
                        if not active_uuid:
                            with open(ACTIVE_USB_FILE, "w") as f2:
                                f2.write(marker_info.get("uuid", ""))
                        return {
                            "BASE_DIR": mp,
                            "SEED_PATH": os.path.join(mp, ".sigil.seed"),
                            "DB_PATH": os.path.join(mp, "VELVET_SIGILBOOK.sigil"),
                            "MARKER_PATH": marker,
                        }
    print("No Velvet USB detected!")
    sys.exit(1)
    
def make_header(salt):
    return MAGIC + bytes([VERSION, len(salt)]) + salt

def parse_header(data):
    if len(data) < 6 or data[:4] != MAGIC or data[4] != VERSION:
        raise Exception("Bad header")
    slen = data[5]
    if len(data) < 6 + slen:
        raise Exception("Header too short for salt")
    salt = data[6:6+slen]
    header = data[:6+slen]
    return salt, header, 6 + slen
    
def b3_tag(key32: bytes, header: bytes, ct: bytes) -> bytes:
    h = blake3.blake3(key=key32)
    h.update(b"SIGILBOOK-MAC-v1")
    h.update(header)
    h.update(len(ct).to_bytes(8, "little"))
    h.update(ct)
    return h.digest()  # 32 bytes
    
def atomic_write(path, data):
    tmp = str(path) + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    parent = os.path.dirname(path)
    dirfd = os.open(parent, os.O_DIRECTORY)
    os.fsync(dirfd)
    os.close(dirfd)
    os.chmod(path, 0o600)

def plymouth_message(msg):
    print(f"[{datetime.now()}] {msg}")

def load_db(db_path, master_key):
    try:
        with open(db_path, "rb") as f:
            buf = f.read()
        # --- Parse header
        salt, header, off = parse_header(buf)
        tag_file = buf[off:off+32]
        ct = buf[off+32:]
        seed = derive_seed(master_key)
        tag_calc = b3_tag(seed, header, ct)
        if not hmac.compare_digest(tag_file, tag_calc):
            raise Exception("sigilbook MAC mismatch (tamper/corruption detected!)")
        decrypted = xor_keystream(ct, seed)
        return json.loads(decrypted.decode('utf-8'))
    except FileNotFoundError:
        return {"entries": []}
    except Exception as e:
        print(f"ERROR: {e}")
        return {"entries": []}
        
def load_master_key():
    paths = get_vault_paths()
    if os.path.exists(paths["SEED_PATH"]):
        return open(paths["SEED_PATH"], "rb").read()
    else:
        seed = secrets.token_bytes(64)
        with open(paths["SEED_PATH"], "wb") as f:
            f.write(seed)
        os.chmod(paths["SEED_PATH"], 0o600)
        return seed

# ==== Encryption/Decryption ====
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
def derive_seed(key_bytes):
    salt = b"MCES2DU"
    return hashlib.scrypt(key_bytes, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
def xor_keystream(data: bytes, seed: bytes) -> bytes:
    output = bytearray(len(data))
    length = len(data)
    counter = 0
    i = 0
    while i < length:
        ctr_bytes = counter.to_bytes(8, 'little')
        block = hashlib.sha256(seed + ctr_bytes).digest()
        block_size = min(len(block), length - i)
        for j in range(block_size):
            output[i+j] = data[i+j] ^ block[j]
        i += block_size
        counter += 1
    return bytes(output)

def get_file_hash(filepath):
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(1024*1024)
                if not chunk: break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        stat = os.stat(filepath)
        info = f"{filepath}:{stat.st_size}:{stat.st_mtime}".encode()
        return hashlib.sha256(info).hexdigest()


# ==== USB Detection and DB Paths ====
def get_usb_db_path():
    # Try to load the UUID of the “adopted” Velvet USB
    active_uuid = None
    if os.path.exists(ACTIVE_USB_FILE):
        with open(ACTIVE_USB_FILE) as f:
            active_uuid = f.read().strip()
    user = getpass.getuser()
    media_dirs = [f"/media/{user}", f"/run/media/{user}"]
    for base in media_dirs:
        if os.path.isdir(base):
            for d in os.listdir(base):
                mp = os.path.join(base, d)
                marker = os.path.join(mp, USB_DETECT_LABEL)
                if os.path.isfile(marker):
                    with open(marker) as f2:
                        marker_info = json.load(f2)
                    if not active_uuid or marker_info.get("uuid") == active_uuid:
                        return os.path.join(mp, USB_KEY_FILENAME)
    return None

def forget_usb_key():
    if os.path.exists(ACTIVE_USB_FILE):
        os.remove(ACTIVE_USB_FILE)
        print("Forgot active Velvet USB.")

def save_db(db_path, primary_data, master_key):
    # --- Prepare salt & seed
    salt = secrets.token_bytes(16)
    seed = derive_seed(master_key)
    header = make_header(salt)
    ct = xor_keystream(json.dumps(primary_data, indent=2).encode('utf-8'), seed)
    tag = b3_tag(seed, header, ct)
    # --- Wire format: header || tag || ct
    wire = header + tag + ct
    atomic_write(db_path, wire)

def find_password_entry(primary_data, file_hash):
    for entry in primary_data.get("entries", []):
        if entry.get("file_hash") == file_hash:
            return entry
    return None

def add_password_entry(primary_data, file_hash, password, path=None):
    entry = find_password_entry(primary_data, file_hash)
    if entry:
        entry["password"] = password
        if path and path not in entry.get("paths", []):
            entry.setdefault("paths", []).append(path)
    else:
        primary_data["entries"].append({
            "file_hash": file_hash,
            "password": password,
            "paths": [path] if path else []
        })

# ==== Local/USB DB Handling ====
def sync_local_to_usb(master_key):
    usb_db = get_usb_db_path()
    if not usb_db or not os.path.exists(LOCAL_HOLD_PATH):
        return
    plymouth_message("Syncing local holding DB to USB...")
    # Load both, merge, prefer USB on conflicts
    local_data = load_db(LOCAL_HOLD_PATH, master_key)
    usb_data = load_db(usb_db, master_key)
    file_hashes = set()
    for e in usb_data.get("entries", []):
        file_hashes.add(e["file_hash"])
    for e in local_data.get("entries", []):
        if e["file_hash"] not in file_hashes:
            usb_data["entries"].append(e)
    save_db(usb_db, usb_data, master_key)
    os.remove(LOCAL_HOLD_PATH)
    plymouth_message("Local holding DB synced and deleted.")

def pick_db_path(master_key):
    usb_db = get_usb_db_path()
    if usb_db:
        sync_local_to_usb(master_key)
        return usb_db
    else:
        return str(LOCAL_HOLD_PATH)

def save_password(filepath, password):
    master_key = load_master_key()
    usb_db = get_usb_db_path()
    if not usb_db:
        print("No Velvet USB detected! Cannot save password.")
        sys.exit(1)
    db_path = usb_db
    primary_data = load_db(db_path, master_key)
    file_hash = get_file_hash(filepath)
    add_password_entry(primary_data, file_hash, password, path=filepath)
    save_db(db_path, primary_data, master_key)
    plymouth_message(f"Password for {filepath} saved to sigilbook at {db_path}.")


def get_password(filepath):
    master_key = load_master_key()
    usb_db = get_usb_db_path()
    if not usb_db:
        print("No velvet USB detected! Cannot unlock passwords.")
        sys.exit(1)
    primary_data = load_db(usb_db, master_key)
    file_hash = get_file_hash(filepath)
    entry = find_password_entry(primary_data, file_hash)
    if entry:
        return entry["password"]
    return None


def describe_usb(mp):
    import re
    # Step 1: Find the device node for this mountpoint
    devpath = None
    with open("/proc/mounts", "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == mp:
                devpath = parts[0]
                break
    if not devpath:
        return f"{mp} [Unknown Device]"

    # Step 2: Use lsblk to get info for this device node
    try:
        import subprocess, json as _json
        lsblk = subprocess.check_output(
            ["lsblk", "-o", "NAME,MOUNTPOINT,LABEL,UUID,SIZE,MODEL,RM,RO", "-J"], text=True
        )
        data = _json.loads(lsblk)
        # Normalize device name (e.g. '/dev/sdb1' -> 'sdb1')
        devname = re.sub(r"^/dev/", "", devpath)
        # Search all blockdevices and children for devname
        def find_info(devlist):
            for dev in devlist:
                if dev["name"] == devname:
                    return dev
                for child in dev.get("children", []):
                    if child["name"] == devname:
                        return child
            return None
        info = find_info(data["blockdevices"])
        if info:
            return (f"{mp} [{devpath}] | Label: {info.get('label','')} | UUID: {info.get('uuid','')} | "
                    f"Size: {info.get('size','')} | Model: {info.get('model','')} | RM: {info.get('rm','')} | RO: {info.get('ro','')}")
        else:
            return f"{mp} [{devpath}]"
    except Exception as e:
        return f"{mp} [{devpath}]"

def write_usb_key():
    import subprocess, json
    drives = []
    user = getpass.getuser()
    media_dirs = [f"/media/{user}", f"/run/media/{user}"]
    for base in media_dirs:
        if os.path.isdir(base):
            for d in os.listdir(base):
                mp = os.path.join(base, d)
                drives.append(mp)
    if not drives:
        print("No USB drives detected!")
        return
    print("\nDetected USB drives:")
    for idx, d in enumerate(drives):
        print(f"{idx+1}. {d}")
    while True:
        try:
            sel = int(input("\nWhich USB do you want to write Velvet key marker to? [number]: "))
            if 1 <= sel <= len(drives):
                break
        except Exception:
            pass
        print("Invalid selection.")
    chosen = drives[sel-1]
    # --- Get UUID ---
    devpath = None
    with open("/proc/mounts") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == chosen:
                devpath = parts[0]
    uuid = None
    if devpath:
        devname = os.path.basename(devpath)
        lsblk = subprocess.check_output(
            ["lsblk", "-o", "NAME,UUID", "-J"], text=True
        )
        lsblk = json.loads(lsblk)
        def search(devs):
            for dev in devs:
                if dev["name"] == devname:
                    return dev.get("uuid")
                if "children" in dev:
                    res = search(dev["children"])
                    if res: return res
            return None
        uuid = search(lsblk["blockdevices"])
    info_path = os.path.join(chosen, USB_DETECT_LABEL)
    info = {
        "created": datetime.now().isoformat(),
        "mountpoint": chosen,
        "uuid": uuid,
        "note": "This file marks the USB as a Velvet Key device for sigilbook."
    }
    with open(info_path, "w") as f:
        json.dump(info, f, indent=2)
    os.chmod(info_path, 0o600)
    print(f"\nVelvet key marker written to {info_path} with UUID {uuid}!\n")

def detect_usb_key():
    user = getpass.getuser()
    media_dirs = [f"/media/{user}", f"/run/media/{user}"]
    found = False
    for base in media_dirs:
        if os.path.isdir(base):
            for d in os.listdir(base):
                mp = os.path.join(base, d)
                marker = os.path.join(mp, USB_DETECT_LABEL)
                if os.path.isfile(marker):
                    with open(marker) as f:
                        marker_info = json.load(f)
                    print(f"\nVelvet USB detected at: {mp}")
                    print("Marker Info:")
                    for k, v in marker_info.items():
                        print(f"  {k}: {v}")
                    # --- LOCK IN USB ---
                    with open(ACTIVE_USB_FILE, "w") as f2:
                        f2.write(marker_info.get("uuid", ""))
                    print(f"\n[Velvet] Now using USB with UUID: {marker_info.get('uuid','')} for all password ops.\n")
                    found = True
    if not found:
        print("No Velvet USB detected!")
        
def find_velvet_usb_by_uuid(target_uuid):
    import subprocess, json
    user = getpass.getuser()
    media_dirs = [f"/media/{user}", f"/run/media/{user}"]
    for base in media_dirs:
        if os.path.isdir(base):
            for d in os.listdir(base):
                mp = os.path.join(base, d)
                marker = os.path.join(mp, USB_DETECT_LABEL)
                if os.path.isfile(marker):
                    with open(marker) as f:
                        marker_info = json.load(f)
                    if marker_info.get("uuid") == target_uuid:
                        return mp
    return None

# ==== CLI ====
def main():
    if len(sys.argv) > 1 and sys.argv[1] == "writeusb":
        write_usb_key()
    elif len(sys.argv) > 1 and sys.argv[1] == "detect":
        detect_usb_key()
    elif len(sys.argv) > 2 and sys.argv[1] == "get":
        print(get_password(sys.argv[2]))
    elif len(sys.argv) > 3 and sys.argv[1] == "save":
        save_password(sys.argv[2], sys.argv[3])
        print("ok")
    elif len(sys.argv) > 1 and sys.argv[1] == "forget":
        forget_usb_key()
    else:
        print("Usage:\n"
              "  python3 sigilbook.py writeusb      # Write velvet key marker to a USB\n"
              "  python3 sigilbook.py detect        # Detect Velvet USB and show marker info\n"
              "  python3 sigilbook.py get <vaultfile>\n"
              "  python3 sigilbook.py save <vaultfile> <password>\n")

if __name__ == "__main__":
    main()

