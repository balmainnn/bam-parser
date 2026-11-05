import json
from datetime import datetime, timezone
def _safe(r):
    return {k:(v.isoformat() if k=="executed_utc" and v else (str(v) if k=="executed_utc" else v))
            for k,v in r.items()}
def export_json(rows,path,issues=None):
    data={"application":"BAM Parser","generated_utc":datetime.now(timezone.utc).isoformat(),
          "records":[_safe(r) for r in rows],"analysis_issues":issues or [],
          "limitations":["Logon attribution is heuristic.","YARA matches are leads, not proof.",
                         "USN results are filename-only weak correlations, not proof of replacement."]}
    with open(path,"w",encoding="utf-8") as f: json.dump(data,f,indent=2,ensure_ascii=False,default=str)
