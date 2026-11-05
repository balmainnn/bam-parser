import os, subprocess
def investigate_usn(path):
    r={"available":False,"strength":"None","findings":[],"limitations":[
       "Read-only fsutil text search by basename only; no file-reference-number correlation.",
       "A same-name hit is weak evidence and does not prove replacement, deletion or recreation."]}
    if os.name!="nt" or not os.path.isfile(path):
        r["limitations"].append("Target is not an existing local Windows file."); return r
    drive=os.path.splitdrive(os.path.abspath(path))[0]
    if not drive: r["limitations"].append("Cannot determine local volume."); return r
    flags=getattr(subprocess,"CREATE_NO_WINDOW",0)
    try:
        q=subprocess.run(["fsutil","usn","queryjournal",drive],capture_output=True,text=True,timeout=15,creationflags=flags)
        if q.returncode: r["limitations"].append("Journal query unavailable: "+(q.stderr or q.stdout)[:300]); return r
        r["available"]=True
        p=subprocess.run(["fsutil","usn","readjournal",drive,"csv"],capture_output=True,text=True,timeout=45,creationflags=flags)
        if p.returncode: r["limitations"].append("Journal read unavailable: "+(p.stderr or p.stdout)[:300]); return r
        base=os.path.basename(path).casefold()
        hits=[line[:1000] for line in p.stdout.splitlines() if base and base in line.casefold()]
        r["findings"]=hits[-100:]
        if hits: r["strength"]="Weak filename-only"; r["limitations"].append("Hits may refer to a different file sharing the basename.")
        else: r["limitations"].append("No basename hit in returned journal text; absence is not established.")
    except Exception as e: r["limitations"].append(f"USN query failed or timed out: {e}")
    return r
