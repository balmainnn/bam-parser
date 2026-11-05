import json, os, subprocess
from datetime import datetime, timezone
def _dt(s):
    try: return datetime.fromisoformat(s.replace("Z","+00:00")).astimezone(timezone.utc)
    except Exception: return None
def get_latest_logons():
    if os.name != "nt": return {}, ["Security log is Windows-only."]
    ps = r'''
$ErrorActionPreference='Stop'
$ev=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 12000
$out=foreach($e in $ev){[xml]$x=$e.ToXml();$d=@{};foreach($v in $x.Event.EventData.Data){$d[[string]$v.Name]=[string]$v.'#text'}
[pscustomobject]@{Time=$e.TimeCreated.ToUniversalTime().ToString('o');Sid=$d['TargetUserSid'];Type=$d['LogonType']}}
ConvertTo-Json -InputObject @($out) -Compress
'''
    try:
        p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",ps],
            capture_output=True,text=True,timeout=45,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        if p.returncode: return {}, ["Security log query failed: "+(p.stderr or p.stdout)[:400]]
        data=json.loads(p.stdout or "[]"); data=[data] if isinstance(data,dict) else data
        latest={}
        for e in data:
            sid=e.get("Sid"); dt=_dt(e.get("Time"))
            if sid and sid!="S-1-0-0" and dt and e.get("Type") in ("2","7","10","11","12","13"):
                if sid not in latest or dt>latest[sid]: latest[sid]=dt
        return latest, []
    except Exception as e: return {}, [f"Security log unavailable: {e}"]
def compare_logon(executed, sid, latest):
    t=latest.get(sid)
    if t is None: return "Unknown","No applicable retained 4624 event for this SID."
    if executed>=t: return "Yes","BAM timestamp is at/after latest matching 4624 event observed."
    return "No","A later matching 4624 event was observed; timestamp predates it."
