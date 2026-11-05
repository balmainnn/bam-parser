import logging, tkinter as tk
from tkinter import ttk, filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor
from bam.registry import enumerate_bam
from bam.logons import get_latest_logons
from bam.analysis import analyze_record
from bam.journal import investigate_usn
from detection.engine import DetectionEngine
from exports.json_export import export_json
from exports.csv_export import export_csv
from exports.html_export import export_html
from .table import EvidenceTable
from .details import DetailsPanel
log=logging.getLogger(__name__)
class BAMParserApp(tk.Tk):
 def __init__(self):
  super().__init__();self.title("BAM Parser — Windows Forensic Workbench");self.geometry("1500x850");self.minsize(1050,650);self.configure(bg="#171b22")
  self.style=ttk.Style(self)
  try:self.style.theme_use("clam")
  except tk.TclError:pass
  self.style.configure(".",background="#202833",foreground="#dce5ef",fieldbackground="#1b222c")
  self.style.configure("TFrame",background="#171b22");self.style.configure("TLabel",background="#171b22",foreground="#dce5ef")
  self.style.configure("TButton",background="#2b3a4b",foreground="#eaf2fb",padding=6)
  self.style.configure("Treeview",background="#1b222c",foreground="#dce5ef",fieldbackground="#1b222c",rowheight=26)
  self.style.configure("Treeview.Heading",background="#293544",foreground="#dce5ef",padding=7)
  self.records=[];self.issues=[];self.map={};self.pool=ThreadPoolExecutor(max_workers=3);self.detector=DetectionEngine();self._build()
  self.protocol("WM_DELETE_WINDOW",self.close);self.after(200,self.refresh)
 def _build(self):
  top=ttk.Frame(self,padding=10);top.pack(fill="x")
  ttk.Button(top,text="↻ Refresh BAM",command=self.refresh).pack(side="left")
  ttk.Button(top,text="Export JSON",command=lambda:self.export("json")).pack(side="right",padx=3)
  ttk.Button(top,text="Export CSV",command=lambda:self.export("csv")).pack(side="right",padx=3)
  ttk.Button(top,text="HTML Report",command=lambda:self.export("html")).pack(side="right",padx=3)
  self.status=tk.StringVar(value="Ready");ttk.Label(top,textvariable=self.status).pack(side="left",padx=14)
  bar=ttk.Frame(self,padding=(10,2,10,8));bar.pack(fill="x")
  ttk.Label(bar,text="Search").pack(side="left");self.q=tk.StringVar();ttk.Entry(bar,textvariable=self.q,width=38).pack(side="left",padx=7)
  self.q.trace_add("write",lambda *_:self.populate())
  self.u=tk.BooleanVar();self.f=tk.BooleanVar();self.l=tk.BooleanVar()
  for label,var in [("Show only unsigned/invalid",self.u),("Show only generic-flagged",self.f),("Current logon instance only",self.l)]:
   ttk.Checkbutton(bar,text=label,variable=var,command=self.populate).pack(side="left",padx=7)
  pw=ttk.Panedwindow(self,orient="vertical");pw.pack(fill="both",expand=True,padx=10,pady=8)
  tf=ttk.Frame(pw);self.table=EvidenceTable(tf,self.selected,self.copy_path)
  sy=ttk.Scrollbar(tf,orient="vertical",command=self.table.yview);sx=ttk.Scrollbar(tf,orient="horizontal",command=self.table.xview)
  self.table.configure(yscrollcommand=sy.set,xscrollcommand=sx.set);self.table.grid(row=0,column=0,sticky="nsew")
  sy.grid(row=0,column=1,sticky="ns");sx.grid(row=1,column=0,sticky="ew");tf.rowconfigure(0,weight=1);tf.columnconfigure(0,weight=1)
  df=ttk.Frame(pw);ttk.Label(df,text="FORENSIC DETAILS").pack(anchor="w",pady=4);self.details=DetailsPanel(df);self.details.pack(fill="both",expand=True)
  pw.add(tf,weight=4);pw.add(df,weight=2)
 def refresh(self):
  self.status.set("Reading BAM registry and Security log…");self.pool.submit(self._refresh_worker)
 def _refresh_worker(self):
  try:
   rows,issues=enumerate_bam();latest,li=get_latest_logons();issues+=li;out=[]
   for rec in rows:
    try:out.append(analyze_record(rec,latest,self.detector))
    except Exception as e:
     log.exception("Record analysis failed")
     r=dict(rec);r.update(converted_path=rec["raw_registry_path"],file_status="Unknown",logon_instance="Unknown",
       logon_note=str(e),signature={"status":"UnknownError"},detections=[],detection_backend=self.detector.backend,
       journal={"strength":"Not queried","findings":[],"limitations":[str(e)]});out.append(r)
   self.after(0,lambda:self.done(out,issues,latest))
  except Exception as e:
   log.exception("Refresh failed");self.after(0,lambda:self.status.set("Refresh failed: "+str(e)))
 def done(self,rows,issues,latest):
  self.records=rows;self.issues=issues;self.latest=latest;self.populate()
  self.status.set(f"{len(rows)} BAM records · {len(issues)} issue(s) · Detection: {self.detector.backend}")
 def populate(self):
  for i in self.table.get_children():self.table.delete(i)
  self.map.clear();q=self.q.get().casefold()
  for n,r in enumerate(self.records):
   sig=(r.get("signature") or {}).get("status","UnknownError");det=r.get("detections") or []
   if self.u.get() and sig not in ("NotSigned","HashMismatch","NotTrusted","UnknownError","Deleted"):continue
   if self.f.get() and not det:continue
   if self.l.get() and r.get("logon_instance")!="Yes":continue
   hay=" ".join([r.get("converted_path",""),r.get("raw_registry_path",""),r.get("sid",""),
      (r.get("signature") or {}).get("publisher") or ""," ".join(det)]).casefold()
   if q and q not in hay:continue
   vals=(r.get("executed_local",""),r.get("converted_path",""),sig,(r.get("signature") or {}).get("publisher") or "",
      r.get("logon_instance","Unknown"),", ".join(det),r.get("sid",""),r.get("file_status",""))
   tags=("suspicious",) if det or r.get("journal",{}).get("findings") else (("deleted",) if sig=="Deleted" else (("valid",) if sig=="Valid" else (("unsigned",) if sig!="UnknownError" else ())))
   iid=self.table.insert("","end",values=vals,tags=tags);self.map[iid]=n
 def selected(self):
  sel=self.table.selection()
  if not sel:return
  n=self.map.get(sel[0])
  if n is None:return
  r=self.records[n];self.details.show(r,busy=True)
  if r.get("file_exists") and r.get("journal",{}).get("strength")=="Not queried":
   self.status.set("Best-effort USN journal inspection running…");self.pool.submit(self.journal_worker,n,r["converted_path"])
 def journal_worker(self,n,path):
  j=investigate_usn(path);self.after(0,lambda:self.journal_done(n,j))
 def journal_done(self,n,j):
  if n<len(self.records):
   self.records[n]["journal"]=j;sel=self.table.selection()
   if sel and self.map.get(sel[0])==n:self.details.show(self.records[n])
   self.status.set("USN inspection: "+j.get("strength","completed"))
 def copy_path(self,iid):
  n=self.map.get(iid)
  if n is not None:self.clipboard_clear();self.clipboard_append(self.records[n].get("converted_path",""));self.status.set("Converted path copied.")
 def export(self,kind):
  if not self.records:messagebox.showinfo("BAM Parser","No records to export.");return
  ext={"json":".json","csv":".csv","html":".html"}[kind]
  path=filedialog.asksaveasfilename(defaultextension=ext,initialfile="bam_forensic_report"+ext,
      filetypes=[(kind.upper(),"*"+ext),("All files","*.*")])
  if not path:return
  try:
   {"json":export_json,"csv":export_csv,"html":export_html}[kind](self.records,path,*([self.issues] if kind!="csv" else []))
   self.status.set("Exported "+path);messagebox.showinfo("Export complete","Report saved to:\n"+path)
  except Exception as e:log.exception("Export failed");messagebox.showerror("Export failed",str(e))
 def close(self):
  self.pool.shutdown(wait=False,cancel_futures=True);self.destroy()
