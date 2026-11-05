# BAM Parser

Read-only Windows 10/11 BAM forensic triage desktop application. Requires Python 3.11+.
Run `py -3.11 -m pip install -r requirements.txt` (YARA is optional), then `run.bat`.
Run elevated for the broadest registry, Security log, Authenticode and journal access.

## Features
- Read-only enumeration of `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`.
- BAM FILETIME decoding, original value path retention, SID enumeration and malformed-value handling.
- Device path conversion through `QueryDosDeviceW`; no guessed drive letters.
- Security event 4624-based logon comparison, with Unknown when no applicable event can be established.
- Authenticode via PowerShell `Get-AuthenticodeSignature`.
- 26 modular YARA rules; standard-library fallback if yara-python is absent.
- Best-effort USN text search using `fsutil usn readjournal`; results are filename-only weak matches, not proof of replacement.
- Dark Tkinter UI, filtering, sortable columns, details panel, Ctrl+left-click path copy, background workers.
- JSON, CSV and HTML reports.

## Forensic limitations
BAM is not proof of user intent. 4624 availability depends on audit policy, permissions and retention; Yes/No are comparisons against observed retained events, not definitive session attribution. Authenticode trust is local-machine dependent. YARA/fallback hits are investigative leads, not proof of malware or cheating. Slinky/Vape-related static strings do not identify a product conclusively. The USN implementation deliberately does not claim file-reference correlation: same-name journal hits are weak evidence only; it cannot prove replacement/recreation or absence of activity. No registry, evidence file, event log, audit policy or USN journal is modified.

## Usage
Click Refresh BAM; search/filter; select a row for details and best-effort USN query; export JSON/CSV/HTML. Add YARA rules under `detection/rules/` with unique rule identifiers and metadata. No server or paid API is used.
