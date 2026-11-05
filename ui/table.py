from tkinter import ttk
COLS=("executed","path","signature","publisher","logon","detections","sid","file")
HEAD={"executed":"Last executed","path":"Converted path","signature":"Digital signature","publisher":"Publisher",
      "logon":"Logon instance","detections":"Generic detections","sid":"User SID","file":"File status"}
class EvidenceTable(ttk.Treeview):
    def __init__(self,master,on_select,on_copy):
        super().__init__(master,columns=COLS,show="headings",selectmode="browse")
        self.on_select=on_select; self.on_copy=on_copy; self.reverse={}
        widths=[150,360,115,180,105,240,230,85]
        for c,w in zip(COLS,widths):
            self.heading(c,text=HEAD[c],command=lambda col=c:self.sort_by(col)); self.column(c,width=w,minwidth=70)
        self.tag_configure("suspicious",background="#512d35",foreground="#ffe4e7")
        self.tag_configure("deleted",foreground="#aeb7c3"); self.tag_configure("unsigned",foreground="#e5bd82")
        self.tag_configure("valid",foreground="#a8d5bd")
        self.bind("<<TreeviewSelect>>",lambda e:self.on_select())
        self.bind("<Control-Button-1>",self.copy_click)
    def copy_click(self,event):
        iid=self.identify_row(event.y)
        if iid:self.selection_set(iid);self.on_copy(iid);return "break"
    def sort_by(self,col):
        rev=not self.reverse.get(col,False);self.reverse[col]=rev
        vals=[(self.set(i,col),i) for i in self.get_children("")]
        try: vals.sort(key=lambda x:float(x[0]),reverse=rev)
        except ValueError: vals.sort(key=lambda x:x[0].casefold(),reverse=rev)
        for n,(_,iid) in enumerate(vals):self.move(iid,"",n)
