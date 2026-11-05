import tkinter as tk
from tkinter import ttk
class DetailsPanel(ttk.Frame):
    def __init__(self,master):
        super().__init__(master,padding=8)
        self.t=tk.Text(self,bg="#1b222c",fg="#dce5ef",insertbackground="white",wrap="word",
                       relief="flat",font=("Consolas",9),height=12,padx=10,pady=8)
        self.t.pack(fill="both",expand=True);self.t.configure(state="disabled")
    def show(self,r,busy=False):
        s=r.get("signature") or {};j=r.get("journal") or {}
        lines=[f"SID: {r.get('sid')}",f"Executed local: {r.get('executed_local')}",
          f"Executed UTC: {r.get('executed_utc')}",f"Raw BAM path/value: {r.get('raw_registry_path')}",
          f"Converted path: {r.get('converted_path')}",f"Raw value hex: {r.get('raw_value_hex')}",
          f"File status: {r.get('file_status')}",f"Logon instance: {r.get('logon_instance')} — {r.get('logon_note')}",
          "",f"Authenticode: {s.get('status')}",f"Publisher: {s.get('publisher')}",
          f"Certificate issuer: {s.get('issuer')}",f"Signature detail: {s.get('message')}",
          "",f"Detection backend: {r.get('detection_backend')}",
          "Matched rules: "+(", ".join(r.get("detections") or []) or "None"),
          "Generic matches are leads, not proof of malware or cheating.","",
          "USN journal: "+str(j.get("strength","Not queried"))]
        if busy:lines.append("Journal query running…")
        lines += ["USN: "+x for x in j.get("findings",[])]
        lines += ["Limitation: "+x for x in j.get("limitations",[])]
        self.t.configure(state="normal");self.t.delete("1.0","end");self.t.insert("1.0","\n".join(lines));self.t.configure(state="disabled")
