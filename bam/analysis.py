import os
from .paths import convert_device_path
from .logons import compare_logon
from .signatures import check_authenticode
from .journal import investigate_usn
def analyze_record(rec, latest, detector):
    r=dict(rec); path=convert_device_path(rec["raw_registry_path"]); r["converted_path"]=path
    r["file_exists"]=os.path.isfile(path); r["file_status"]="Present" if r["file_exists"] else "Deleted"
    r["logon_instance"],r["logon_note"]=compare_logon(rec["executed_utc"],rec["sid"],latest)
    if r["file_exists"]:
        r["signature"]=check_authenticode(path); r["detections"],r["detection_backend"]=detector.scan(path)
    else:
        r["signature"]={"status":"Deleted","publisher":None,"issuer":None,"message":"Missing file"}
        r["detections"],r["detection_backend"]=[],detector.backend
    r["journal"]={"available":False,"strength":"Not queried","findings":[],
                  "limitations":["Queried on row selection; filename-only best effort."]}
    return r
