import html
from datetime import datetime, timezone
def export_html(rows,path,issues=None):
    e=lambda x:html.escape("" if x is None else str(x))
    body=[]
    for r in rows:
        s=r.get("signature") or {}; j=r.get("journal") or {}
        body.append("<tr>"+"".join("<td>"+e(x)+"</td>" for x in [
          r.get("executed_local"),r.get("raw_registry_path"),r.get("converted_path"),r.get("sid"),
          r.get("logon_instance"),r.get("file_status"),s.get("status"),s.get("publisher"),s.get("issuer"),
          ", ".join(r.get("detections") or []),"; ".join(j.get("findings",[]))+" | "+"; ".join(j.get("limitations",[]))])+"</tr>")
    doc="""<!doctype html><html><head><meta charset="utf-8"><title>BAM Parser Report</title>
<style>body{font:13px Segoe UI,Arial;background:#171b22;color:#e7edf5;margin:28px}h1{color:#8bb9e8}
table{border-collapse:collapse;width:100%;font-size:11px}th,td{border:1px solid #394454;padding:7px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#263241}tr:nth-child(even){background:#202833}.note{background:#222c38;padding:14px;margin:16px 0}</style></head><body>"""
    doc+="<h1>BAM Parser — Forensic Report</h1><p>Generated UTC: "+e(datetime.now(timezone.utc).isoformat())+"</p>"
    doc+="<div class='note'>BAM is not proof of user intent. Logon results depend on retained 4624 events. YARA matches are investigative leads. USN basename matches are weak and do not prove replacement.</div>"
    doc+="<h2>Issues</h2><p>"+e("; ".join(issues or []))+"</p><h2>Records</h2><table><tr>"
    doc+="".join("<th>"+x+"</th>" for x in ["Last executed","Original BAM path","Converted path","SID","Logon instance","File","Signature","Publisher","Issuer","Matched rules","USN findings / limitations"])
    doc+="</tr>"+"".join(body)+"</table></body></html>"
    with open(path,"w",encoding="utf-8") as f:f.write(doc)
