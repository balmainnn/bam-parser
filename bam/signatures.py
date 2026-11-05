import json, os, subprocess
def check_authenticode(path):
    if not os.path.isfile(path): return {"status":"Deleted","publisher":None,"issuer":None,"message":"File does not exist."}
    if os.name!="nt": return {"status":"UnknownError","publisher":None,"issuer":None,"message":"Windows required."}
    ps=r'''
param([string]$Target)
try{$s=Get-AuthenticodeSignature -LiteralPath $Target -ErrorAction Stop;$sub=$null;$iss=$null
if($s.SignerCertificate){$sub=$s.SignerCertificate.Subject;$iss=$s.SignerCertificate.Issuer}
[pscustomobject]@{Status=[string]$s.Status;Message=[string]$s.StatusMessage;Subject=$sub;Issuer=$iss}|ConvertTo-Json -Compress
}catch{[pscustomobject]@{Status='UnknownError';Message=$_.Exception.Message}|ConvertTo-Json -Compress}
'''
    try:
        command = "& { " + ps + " } -Target " + "'" + path.replace("'", "''") + "'"
        p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",command],
            capture_output=True,text=True,timeout=30,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        if p.returncode: raise RuntimeError((p.stderr or p.stdout)[:300])
        d=json.loads(p.stdout.strip()); raw=d.get("Status","")
        status={"Valid":"Valid","NotSigned":"NotSigned","HashMismatch":"HashMismatch",
                "NotTrusted":"NotTrusted","UnknownError":"UnknownError","Incompatible":"UnknownError"}.get(raw,"UnknownError")
        return {"status":status,"publisher":d.get("Subject"),"issuer":d.get("Issuer"),"message":d.get("Message")}
    except Exception as e: return {"status":"UnknownError","publisher":None,"issuer":None,"message":str(e)}
