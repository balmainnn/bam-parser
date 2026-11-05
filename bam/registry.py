import os
try:
    import winreg
except ImportError:
    winreg = None
from .timestamps import decode_filetime, iso_local
KEY = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
def enumerate_bam():
    rows, issues = [], []
    if os.name != "nt": return rows, ["BAM registry parsing is Windows-only."]
    try:
        root = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        key = winreg.OpenKey(root, KEY, 0, winreg.KEY_READ)
    except OSError as e: return rows, [f"Cannot open HKLM\\{KEY}: {e}"]
    try:
        i = 0
        while True:
            try: sid = winreg.EnumKey(key, i); i += 1
            except OSError: break
            try: sk = winreg.OpenKey(key, sid, 0, winreg.KEY_READ)
            except OSError as e: issues.append(f"{sid}: {e}"); continue
            try:
                j = 0
                while True:
                    try: name, data, typ = winreg.EnumValue(sk, j); j += 1
                    except OSError: break
                    try:
                        if typ != winreg.REG_BINARY: raise ValueError("not REG_BINARY")
                        dt = decode_filetime(data)
                        if dt is None: raise ValueError("zero FILETIME")
                        rows.append({"sid":sid, "raw_registry_path":name, "bam_value_type":typ,
                                     "raw_value_hex":bytes(data).hex(), "executed_utc":dt,
                                     "executed_local":iso_local(dt)})
                    except Exception as e: issues.append(f"{sid} {name!r}: {e}")
            finally: winreg.CloseKey(sk)
    finally:
        winreg.CloseKey(key); winreg.CloseKey(root)
    return rows, issues
