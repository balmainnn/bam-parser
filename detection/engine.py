import logging, os
from pathlib import Path
RULE_DIR=Path(__file__).resolve().parent/"rules"
class DetectionEngine:
    def __init__(self):
        self.compiled=None; self.backend="Fallback"; self.errors=[]
        try:
            import yara
            paths=sorted(RULE_DIR.glob("*.yar*"))
            if paths: self.compiled=yara.compile(filepaths={f"r{i}":str(p) for i,p in enumerate(paths)}); self.backend="yara-python"
        except Exception as e: self.errors.append(str(e)); logging.warning("YARA unavailable/compile failure: %s",e)
    def scan(self,path):
        if not os.path.isfile(path): return [],"File unavailable"
        if self.compiled:
            try: return sorted({m.rule for m in self.compiled.match(path,timeout=20)}),"yara-python"
            except Exception as e: logging.warning("YARA scan failed: %s",e)
        return self._fallback(path),"Fallback"
    def _fallback(self,path):
        # Conservative byte-string fallback, not a YARA emulator.
        sig={
        "Generic_A_Autoclicker_Basic":[b"click interval",b"autoclick",b"auto click"],
        "Generic_A2_Autoclicker_API":[b"mouse_event",b"sendinput",b"click interval"],
        "Generic_A3_CSharp_Autoclicker":[b"mscoree.dll",b"system.windows.forms",b"mousebuttons"],
        "Generic_B_Protector_NonDotNet_A":[b"themida",b"winlicense",b"oreans technologies"],
        "Generic_B2_Protector_NonDotNet_B":[b".themida",b".winlice"],
        "Generic_B3_Protector_NonDotNet_C":[b"vmprotect",b"vmp0"],
        "Generic_B4_Protector_NonDotNet_D":[b"enigma protector",b"armadillo"],
        "Generic_B5_Protector_NonDotNet_E":[b"aspack",b"asprotect"],
        "Generic_B6_Protector_NonDotNet_F":[b"upx0",b"upx1",b"petite"],
        "Generic_B7_Protector_NonDotNet_G":[b"molebox",b"pecompact",b"fsg!"],
        "Generic_C_DotNet_Protection_Basic":[b"mscoree.dll",b"confuserex",b"eazfuscator"],
        "Generic_D_DotNet_Protection_Advanced":[b"confuser.core",b"antitamper",b"antidump"],
        "Generic_E_DotNet_Python_Protection":[b"pyz-00.pyz",b"pyinstaller",b"python311.dll"],
        "Generic_F_Packed_Advanced_A":[b"upx0",b"upx1",b"upx!"],
        "Generic_F2_Packed_Advanced_B":[b".mpress1",b".mpress2",b"mpress"],
        "Generic_F3_Packed_Advanced_C":[b"pecompact",b"fsg!",b"pec2"],
        "Generic_F4_Packed_Advanced_D":[b"aspack",b"asprotect",b"aplib"],
        "Generic_F5_Packed_Advanced_E":[b"themida",b"vmprotect",b"winlicense"],
        "Generic_F6_Packed_Heavy":[b"upx!",b"mpress",b"kkrunchy"],
        "Generic_F7_Packed_Extreme":[b"oreans technologies",b"themida",b"vmprotect",b"code virtualizer"],
        "Generic_G_Suspicious_Injector_A":[b"openprocess",b"virtualallocex",b"writeprocessmemory",b"createremotethread"],
        "Generic_G2_Suspicious_Injector_B":[b"ntopenprocess",b"ntwritevirtualmemory",b"ntcreatethreadex"],
        "Generic_G3_Suspicious_Injector_C":[b"loadlibrarya",b"getprocaddress",b"createremotethread"],
        "Generic_G4_Suspicious_Injector_D":[b"manualmap",b"reflectiveloader",b"processhollowing"],
        "Specific_A_Selected_Free_Minecraft_Cheat_Indicators":[b"liquidbounce",b"wurst",b"meteor client",b"rise client",b"killaura"],
        "Specific_B_Selected_Paid_Minecraft_Cheat_Indicators":[b"vape",b"slinky",b"drip",b"entropy",b"clickgui"]}
        try:
            with open(path,"rb") as f: data=f.read(64*1024*1024).lower()
            return [name for name,needles in sig.items() if sum(n in data for n in needles)>=2]
        except Exception as e: logging.warning("Fallback read failed: %s",e); return []
