import csv
FIELDS=["executed_local","raw_registry_path","converted_path","sid","logon_instance","file_status",
        "signature_status","publisher","issuer","detections","detection_backend"]
def export_csv(rows,path):
    with open(path,"w",newline="",encoding="utf-8-sig") as f:
        w=csv.DictWriter(f,fieldnames=FIELDS); w.writeheader()
        for r in rows:
            s=r.get("signature") or {}
            w.writerow({"executed_local":r.get("executed_local"),"raw_registry_path":r.get("raw_registry_path"),
             "converted_path":r.get("converted_path"),"sid":r.get("sid"),"logon_instance":r.get("logon_instance"),
             "file_status":r.get("file_status"),"signature_status":s.get("status"),"publisher":s.get("publisher"),
             "issuer":s.get("issuer"),"detections":"; ".join(r.get("detections") or []),
             "detection_backend":r.get("detection_backend")})
