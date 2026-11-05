import ctypes, os
from ctypes import wintypes
def query_dos_devices():
    if os.name != "nt": return {}
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = k.QueryDosDeviceW
    fn.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    fn.restype = wintypes.DWORD
    out = {}
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        b = ctypes.create_unicode_buffer(32768)
        if fn(c + ":", b, len(b)):
            target = b.value.split("\\x00", 1)[0]
            if target: out[target.rstrip("\\")] = c + ":"
    return out
def convert_device_path(path, mapping=None):
    if not isinstance(path, str): return path
    mapping = query_dos_devices() if mapping is None else mapping
    for dev, drive in sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True):
        dev = dev.rstrip("\\")
        if path.casefold() == dev.casefold(): return drive + "\\"
        if path.casefold().startswith((dev + "\\").casefold()): return drive + path[len(dev):]
    return path
