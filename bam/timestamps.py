from datetime import datetime, timedelta, timezone
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
def decode_filetime(data):
    if not isinstance(data, (bytes, bytearray)) or len(data) < 8:
        raise ValueError("Expected at least 8 bytes for FILETIME")
    ticks = int.from_bytes(data[:8], "little")
    return None if ticks == 0 else EPOCH + timedelta(microseconds=ticks / 10)
def iso_local(dt):
    return dt.astimezone().isoformat(timespec="seconds") if dt else None
