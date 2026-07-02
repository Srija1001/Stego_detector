"""
Steganography Detector — Unified GUI
Supports: Images (PNG/JPG/BMP/TIFF/WEBP)
          Documents (PDF/DOCX/PPTX/XLSX/TXT/CSV/HTML/XML/MD/RTF/ODT/ODS/ODP)
          Audio (WAV/MP3/FLAC/OGG/M4A/AAC/AIFF)
          Video (MP4/AVI/MKV/MOV/WMV/FLV/WEBM)
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import sys
import json
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from PIL import Image, ImageTk
from analysis.detector import StegoAnalyzer
from analysis.doc_detector import (
    analyze_document, is_image,
    SUPPORTED_EXTENSIONS, AUDIO_EXTENSIONS, VIDEO_EXTENSIONS, IMAGE_EXTENSIONS,
)
from utils.report import generate_batch_report
from utils.visualizer import (
    make_histogram_figure, make_lsb_figure,
    make_risk_figure, fig_to_pil,
)

# ── Colours ──────────────────────────────────────────────────────────────────
BG      = "#0d1117"
PANEL   = "#161b22"
PANEL2  = "#1f2937"
BORDER  = "#30363d"
ACCENT  = "#00d4aa"
ACCENT2 = "#ff6b6b"
ACCENT3 = "#ffd93d"
TEXT    = "#e6edf3"
SUBTEXT = "#8b949e"
RED     = "#ff4444"
GREEN   = "#00d4aa"

FONT_MONO  = ("Courier New", 9)
FONT_BODY  = ("Segoe UI", 9)
FONT_H2    = ("Segoe UI", 11, "bold")
FONT_SMALL = ("Segoe UI", 8)

IMAGE_EXTS = "*.png *.jpg *.jpeg *.bmp *.tiff *.tif *.webp"
DOC_EXTS   = "*.pdf *.docx *.doc *.pptx *.ppt *.xlsx *.xls *.txt *.csv *.html *.htm *.xml *.md *.rtf *.odt *.odp *.ods"
AUDIO_EXTS = "*.wav *.mp3 *.flac *.ogg *.m4a *.aac *.aiff"
VIDEO_EXTS = "*.mp4 *.avi *.mkv *.mov *.wmv *.flv *.webm"

FILE_ICON = {
    ".png":"🖼️",".jpg":"🖼️",".jpeg":"🖼️",".bmp":"🖼️",".tiff":"🖼️",".webp":"🖼️",
    ".pdf":"📄",".docx":"📝",".doc":"📝",".odt":"📝",
    ".pptx":"📊",".ppt":"📊",".odp":"📊",
    ".xlsx":"📈",".xls":"📈",".ods":"📈",
    ".txt":"📃",".csv":"📃",".md":"📃",".html":"🌐",".htm":"🌐",
    ".xml":"🌐",".rtf":"📃",
    ".wav":"🎵",".mp3":"🎵",".flac":"🎵",".ogg":"🎵",
    ".m4a":"🎵",".aac":"🎵",".aiff":"🎵",
    ".mp4":"🎬",".avi":"🎬",".mkv":"🎬",".mov":"🎬",
    ".wmv":"🎬",".flv":"🎬",".webm":"🎬",
}

def _icon(path):
    return FILE_ICON.get(os.path.splitext(path)[1].lower(), "📁")

def _pil_to_tk(img, max_w=1100, max_h=420):
    img.thumbnail((max_w, max_h), Image.LANCZOS)
    return ImageTk.PhotoImage(img)

def _risk_colour(level):
    return {"HIGH": RED, "MEDIUM": ACCENT3,
            "LOW": GREEN, "CLEAN": GREEN}.get(level, SUBTEXT)

def _kind_from_ext(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in IMAGE_EXTENSIONS:  return "image"
    if ext in AUDIO_EXTENSIONS:  return "audio"
    if ext in VIDEO_EXTENSIONS:  return "video"
    return "document"


# ════════════════════════════════════════════════════════════════════════════════
class App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Steganography Detector  ·  Universal Forensic Analyzer")
        self.geometry("1300x860")
        self.minsize(1050, 700)
        self.configure(bg=BG)
        self._style()

        self.files        = []
        self.current_idx  = None
        self._tk_images   = []

        self._build_ui()

    # ── Styles ───────────────────────────────────────────────────────────────
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=TEXT,
                    fieldbackground=PANEL, bordercolor=BORDER, font=FONT_BODY)
        s.configure("TFrame",  background=BG)
        s.configure("TLabel",  background=BG, foreground=TEXT)
        s.configure("TButton", background=PANEL, foreground=TEXT,
                    relief="flat", padding=(10,5))
        s.map("TButton",
              background=[("active", ACCENT)],
              foreground=[("active", BG)])
        s.configure("TNotebook", background=PANEL, bordercolor=BORDER)
        s.configure("TNotebook.Tab", background=PANEL, foreground=SUBTEXT,
                    padding=(14,7))
        s.map("TNotebook.Tab",
              background=[("selected", BG)],
              foreground=[("selected", ACCENT)])
        s.configure("TProgressbar", background=ACCENT,
                    troughcolor=PANEL, thickness=5)
        s.configure("TScrollbar", background=PANEL,
                    troughcolor=BG, arrowcolor=SUBTEXT)
        s.configure("Treeview", background=PANEL, foreground=TEXT,
                    fieldbackground=PANEL, rowheight=26)
        s.configure("Treeview.Heading", background=BG,
                    foreground=ACCENT, font=("Segoe UI",8,"bold"))
        s.map("Treeview",
              background=[("selected", PANEL2)],
              foreground=[("selected", ACCENT)])

    # ── UI Layout ─────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=PANEL, height=52)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="⬡", bg=PANEL, fg=ACCENT,
                 font=("Segoe UI",20)).pack(side="left", padx=(14,4))
        tk.Label(hdr, text="STEGO DETECTOR", bg=PANEL, fg=TEXT,
                 font=("Segoe UI",13,"bold")).pack(side="left")
        tk.Label(hdr, text="  Images · Documents · Audio · Video",
                 bg=PANEL, fg=SUBTEXT, font=FONT_BODY).pack(side="left", padx=10)

        # Status bar
        self.status_var = tk.StringVar(value="Ready — add files to begin")
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", side="bottom")
        tk.Label(self, textvariable=self.status_var, bg=PANEL, fg=SUBTEXT,
                 font=FONT_SMALL, anchor="w", padx=12, pady=4).pack(
                     fill="x", side="bottom")

        # Main pane
        paned = tk.PanedWindow(self, orient="horizontal",
                               bg=BORDER, sashwidth=4, bd=0)
        paned.pack(fill="both", expand=True)

        left = tk.Frame(paned, bg=BG, width=310)
        paned.add(left, minsize=260)
        self._build_left(left)

        right = tk.Frame(paned, bg=BG)
        paned.add(right, minsize=650)
        self._build_right(right)

    # ── Left panel ────────────────────────────────────────────────────────────
    def _build_left(self, p):
        self._section(p, "ADD FILES")

        # Row 1: Images + Docs
        r1 = tk.Frame(p, bg=BG)
        r1.pack(fill="x", padx=8, pady=(0,3))
        self._btn(r1, "🖼  Images",  ACCENT,    BG, self._add_images).pack(
            side="left", fill="x", expand=True, padx=(0,3))
        self._btn(r1, "📄  Docs",    ACCENT2,   BG, self._add_docs  ).pack(
            side="left", fill="x", expand=True)

        # Row 2: Audio + Video
        r2 = tk.Frame(p, bg=BG)
        r2.pack(fill="x", padx=8, pady=(0,5))
        self._btn(r2, "🎵  Audio",  "#a78bfa",  BG, self._add_audio).pack(
            side="left", fill="x", expand=True, padx=(0,3))
        self._btn(r2, "🎬  Video",  "#38bdf8",  BG, self._add_video).pack(
            side="left", fill="x", expand=True)

        # File list
        lf = tk.Frame(p, bg=PANEL, highlightthickness=1,
                      highlightbackground=BORDER)
        lf.pack(fill="both", expand=True, padx=8, pady=(0,6))

        self.file_list = ttk.Treeview(
            lf, columns=("risk","score"),
            show="tree headings", selectmode="browse", height=12)
        self.file_list.heading("#0",    text="File",  anchor="w")
        self.file_list.heading("risk",  text="Risk",  anchor="center")
        self.file_list.heading("score", text="Score", anchor="center")
        self.file_list.column("#0",    width=148, anchor="w")
        self.file_list.column("risk",  width=58,  anchor="center")
        self.file_list.column("score", width=50,  anchor="center")

        sb = ttk.Scrollbar(lf, orient="vertical",
                           command=self.file_list.yview)
        self.file_list.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.file_list.pack(fill="both", expand=True)
        self.file_list.bind("<<TreeviewSelect>>", self._on_select)

        # Actions
        self._section(p, "ACTIONS")
        self.progress = ttk.Progressbar(p, mode="indeterminate")
        self.progress.pack(fill="x", padx=8, pady=(0,4))

        self.run_btn = self._btn(
            p, "▶  Analyse All Files", ACCENT, BG, self._run_all,
            font=("Segoe UI",10,"bold"), pady=9, state="disabled")
        self.run_btn.pack(fill="x", padx=8, pady=(0,4))

        self.export_btn = self._btn(
            p, "⬇  Export PDF Report", PANEL, TEXT,
            self._export_pdf, state="disabled")
        self.export_btn.pack(fill="x", padx=8, pady=(0,3))

        self._btn(p, "✕  Remove Selected", PANEL, SUBTEXT,
                  self._remove_selected).pack(fill="x", padx=8, pady=(0,3))
        self._btn(p, "✕  Clear All", PANEL, SUBTEXT,
                  self._clear_all).pack(fill="x", padx=8, pady=(0,8))

        # Verdict
        self._section(p, "CURRENT FILE VERDICT")
        vf = tk.Frame(p, bg=PANEL, highlightthickness=1,
                      highlightbackground=BORDER)
        vf.pack(fill="x", padx=8, pady=(0,8))
        self.verdict_lbl = tk.Label(
            vf, text="—", bg=PANEL, fg=SUBTEXT,
            font=("Segoe UI",12,"bold"),
            wraplength=230, justify="center", pady=10)
        self.verdict_lbl.pack(fill="x")
        self.risk_lbl = tk.Label(
            vf, text="", bg=PANEL, fg=SUBTEXT,
            font=FONT_SMALL, pady=4)
        self.risk_lbl.pack(fill="x")

    def _btn(self, parent, text, bg, fg, cmd,
             font=None, pady=6, state="normal"):
        return tk.Button(parent, text=text, bg=bg, fg=fg,
                         relief="flat", activebackground=ACCENT,
                         activeforeground=BG,
                         font=font or FONT_BODY, cursor="hand2",
                         pady=pady, state=state, command=cmd)

    def _section(self, parent, text):
        f = tk.Frame(parent, bg=BG)
        f.pack(fill="x", padx=8, pady=(10,3))
        tk.Label(f, text=text, bg=BG, fg=ACCENT,
                 font=("Segoe UI",7,"bold")).pack(side="left")
        tk.Frame(f, bg=BORDER, height=1).pack(
            side="left", fill="x", expand=True, padx=(6,0))

    # ── Right panel ───────────────────────────────────────────────────────────
    def _build_right(self, p):
        self.nb = ttk.Notebook(p)
        self.nb.pack(fill="both", expand=True)

        self.tab_summary = tk.Frame(self.nb, bg=BG)
        self.tab_visual  = tk.Frame(self.nb, bg=BG)
        self.tab_detail  = tk.Frame(self.nb, bg=BG)
        self.tab_raw     = tk.Frame(self.nb, bg=BG)

        self.nb.add(self.tab_summary, text="  📋 Summary  ")
        self.nb.add(self.tab_visual,  text="  📊 Visual Analysis  ")
        self.nb.add(self.tab_detail,  text="  🔍 Detailed Results  ")
        self.nb.add(self.tab_raw,     text="  {} Raw JSON  ")

        self._show_welcome()
        self._build_raw_tab()
        self._placeholder(self.tab_visual,
            "Select and analyse a file to see visual analysis")
        self._placeholder(self.tab_detail,
            "Select and analyse a file to see detailed results")

    def _placeholder(self, tab, msg):
        for w in tab.winfo_children():
            w.destroy()
        tk.Label(tab, text=msg, bg=BG, fg=SUBTEXT,
                 font=FONT_BODY).pack(expand=True)

    def _show_welcome(self):
        for w in self.tab_summary.winfo_children():
            w.destroy()
        f = tk.Frame(self.tab_summary, bg=BG)
        f.pack(fill="both", expand=True)

        tk.Label(f, text="⬡", bg=BG, fg=ACCENT,
                 font=("Segoe UI",44)).pack(pady=(36,8))
        tk.Label(f, text="Add files  →  Analyse  →  View Results",
                 bg=BG, fg=TEXT, font=("Segoe UI",13)).pack()
        tk.Label(f,
            text="Supports every common file format for steganography detection",
            bg=BG, fg=SUBTEXT, font=FONT_BODY).pack(pady=4)

        features = [
            ("🖼  Images",             "PNG · JPG · BMP · TIFF · WEBP",
             "LSB planes, RS analysis, Chi-square, Histogram, DCT, Message extraction"),
            ("📄  PDF",                "PDF",
             "Invisible text, embedded JS/files, metadata anomalies"),
            ("📝  Word Documents",     "DOCX · DOC · ODT",
             "Hidden text, white text, VBA macros, custom XML"),
            ("📊  Presentations",      "PPTX · PPT · ODP",
             "Hidden slides, off-canvas shapes, speaker notes stego"),
            ("📈  Spreadsheets",       "XLSX · XLS · ODS",
             "Hidden sheets/rows/cols, invisible cells, macros"),
            ("📃  Text Files",         "TXT · CSV · HTML · XML · MD · RTF",
             "Zero-width chars, trailing spaces, homoglyphs, null bytes"),
            ("🎵  Audio",              "WAV · MP3 · FLAC · OGG · M4A · AIFF",
             "LSB entropy, excess metadata, appended data, noise floor"),
            ("🎬  Video",              "MP4 · AVI · MKV · MOV · WMV · FLV · WEBM",
             "Appended data, size/duration anomaly, metadata, MKV attachments"),
        ]
        gf = tk.Frame(f, bg=PANEL, highlightthickness=1,
                      highlightbackground=BORDER)
        gf.pack(padx=30, pady=10, fill="x")

        for icon_name, exts, desc in features:
            row = tk.Frame(gf, bg=PANEL)
            row.pack(fill="x", padx=12, pady=3)
            tk.Label(row, text=icon_name, bg=PANEL, fg=ACCENT,
                     font=("Segoe UI",9,"bold"), width=22,
                     anchor="w").pack(side="left")
            tk.Label(row, text=exts, bg=PANEL, fg=TEXT,
                     font=("Segoe UI",8), width=28,
                     anchor="w").pack(side="left")
            tk.Label(row, text=desc, bg=PANEL, fg=SUBTEXT,
                     font=FONT_SMALL, anchor="w").pack(side="left")

    def _build_raw_tab(self):
        for w in self.tab_raw.winfo_children():
            w.destroy()
        f = tk.Frame(self.tab_raw, bg=BG)
        f.pack(fill="both", expand=True)
        tk.Label(f, text="Raw Analysis JSON — selected file",
                 bg=BG, fg=ACCENT, font=FONT_H2).pack(
                     anchor="w", padx=16, pady=(10,4))
        tf = tk.Frame(f, bg=PANEL, highlightthickness=1,
                      highlightbackground=BORDER)
        tf.pack(fill="both", expand=True, padx=16, pady=(0,10))
        self.raw_text = tk.Text(
            tf, bg=PANEL, fg=TEXT, font=FONT_MONO,
            relief="flat", bd=0, state="disabled", wrap="none")
        sby = ttk.Scrollbar(tf, orient="vertical",
                            command=self.raw_text.yview)
        sbx = ttk.Scrollbar(tf, orient="horizontal",
                            command=self.raw_text.xview)
        self.raw_text.configure(
            yscrollcommand=sby.set, xscrollcommand=sbx.set)
        sby.pack(side="right",  fill="y")
        sbx.pack(side="bottom", fill="x")
        self.raw_text.pack(fill="both", expand=True)

    # ── File loading ──────────────────────────────────────────────────────────
    def _add_images(self):
        paths = filedialog.askopenfilenames(
            title="Select Image Files",
            filetypes=[("Images", IMAGE_EXTS), ("All Files", "*.*")])
        self._add_paths(paths)

    def _add_docs(self):
        paths = filedialog.askopenfilenames(
            title="Select Document Files",
            filetypes=[
                ("All Documents", DOC_EXTS),
                ("PDF",  "*.pdf"),
                ("Word", "*.docx *.doc *.odt"),
                ("PowerPoint", "*.pptx *.ppt *.odp"),
                ("Excel", "*.xlsx *.xls *.ods"),
                ("Text", "*.txt *.csv *.md *.html *.htm *.xml *.rtf"),
                ("All Files", "*.*"),
            ])
        self._add_paths(paths)

    def _add_audio(self):
        paths = filedialog.askopenfilenames(
            title="Select Audio Files",
            filetypes=[("Audio", AUDIO_EXTS), ("All Files", "*.*")])
        self._add_paths(paths)

    def _add_video(self):
        paths = filedialog.askopenfilenames(
            title="Select Video Files",
            filetypes=[("Video", VIDEO_EXTS), ("All Files", "*.*")])
        self._add_paths(paths)

    def _add_paths(self, paths):
        if not paths:
            return
        existing = {f["path"] for f in self.files}
        added = 0
        for p in paths:
            if p in existing:
                continue
            ext = os.path.splitext(p)[1].lower()
            all_supported = IMAGE_EXTENSIONS | SUPPORTED_EXTENSIONS
            if ext not in all_supported:
                messagebox.showwarning(
                    "Unsupported File",
                    f"'{os.path.basename(p)}' has unsupported extension '{ext}'.\n"
                    f"Skipping this file.")
                continue
            kind = _kind_from_ext(p)
            self.files.append({
                "path": p, "kind": kind,
                "overall": {}, "results": {},
                "extraction": None, "doc_results": None,
                "iid": None,
            })
            iid = self.file_list.insert(
                "", "end",
                text=f"{_icon(p)} {os.path.basename(p)}",
                values=("—", "—"))
            self.files[-1]["iid"] = iid
            added += 1

        if added:
            self.run_btn.configure(state="normal")
            self._set_status(
                f"{len(self.files)} file(s) loaded — ready to analyse")

    def _remove_selected(self):
        sel = self.file_list.selection()
        if not sel:
            return
        iid = sel[0]
        self.files = [f for f in self.files if f.get("iid") != iid]
        self.file_list.delete(iid)
        self.current_idx = None
        if not self.files:
            self.run_btn.configure(state="disabled")
            self.export_btn.configure(state="disabled")
            self._show_welcome()
        self._set_status(f"{len(self.files)} file(s) remaining")

    def _clear_all(self):
        self.files = []
        self.current_idx = None
        for iid in self.file_list.get_children():
            self.file_list.delete(iid)
        self.run_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.verdict_lbl.configure(text="—", fg=SUBTEXT)
        self.risk_lbl.configure(text="")
        self._show_welcome()
        self._placeholder(self.tab_visual,
            "Select and analyse a file to see visual analysis")
        self._placeholder(self.tab_detail,
            "Select and analyse a file to see detailed results")
        self.raw_text.configure(state="normal")
        self.raw_text.delete("1.0", "end")
        self.raw_text.configure(state="disabled")
        self._set_status("Ready — add files to begin")

    def _on_select(self, _=None):
        sel = self.file_list.selection()
        if not sel:
            return
        iid = sel[0]
        for i, f in enumerate(self.files):
            if f.get("iid") == iid:
                self.current_idx = i
                if f["overall"]:
                    self._show_result(i)
                break

    def _set_status(self, msg):
        self.status_var.set(msg)
        self.update_idletasks()

    # ── Analysis ──────────────────────────────────────────────────────────────
    def _run_all(self):
        if not self.files:
            return
        self.run_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.progress.start(10)
        self._set_status("Analysing…")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        total = len(self.files)
        for i, f in enumerate(self.files):
            self.after(0, lambda i=i: self._set_status(
                f"Analysing {i+1}/{total}: "
                f"{os.path.basename(self.files[i]['path'])}"))
            try:
                if f["kind"] == "image":
                    az = StegoAnalyzer(f["path"])
                    ov = az.run_all()
                    ov["kind"] = "image"
                    f["analyzer"]   = az
                    f["results"]    = az.results
                    f["overall"]    = ov
                    f["extraction"] = az.extract_lsb_message(max_chars=2000)
                else:
                    doc_res         = analyze_document(f["path"])
                    f["doc_results"] = doc_res
                    f["overall"]     = self._doc_to_overall(doc_res, f["kind"])
                    f["results"]     = {}
                    f["extraction"]  = None
            except Exception as e:
                # Store error so we can show it in the UI
                f["error"] = str(e)
                f["overall"] = {
                    "kind": f["kind"], "risk_level": "LOW",
                    "risk_score": 0, "verdict": f"Error: {e}",
                    "positive_count": 0, "total_tests": 0,
                    "detected_checks": [], "summary": str(e),
                    "analyzer_type": "Error", "file_type": "",
                    "file_hash": "", "file_size_bytes": 0, "checks": {},
                }

            self.after(0, lambda i=i: self._update_row(i))

        self.after(0, self._on_done)

    def _doc_to_overall(self, doc_res, kind):
        level = doc_res["risk_level"]
        verdicts = {
            "HIGH":   "Steganographic content LIKELY present",
            "MEDIUM": "Steganographic content POSSIBLY present",
            "LOW":    "Suspicious indicators detected",
            "CLEAN":  "No steganographic content detected",
        }
        return {
            "kind":            kind,
            "risk_level":      level,
            "risk_score":      doc_res["total_score"] / 100.0,
            "verdict":         verdicts.get(level, "Unknown"),
            "positive_count":  len(doc_res["detected_checks"]),
            "total_tests":     len(doc_res["checks"]),
            "detected_checks": doc_res["detected_checks"],
            "summary":         doc_res["summary"],
            "analyzer_type":   doc_res.get("analyzer_type", kind.title()),
            "file_type":       doc_res["file_type"],
            "file_hash":       doc_res["file_hash"],
            "file_size_bytes": doc_res["file_size_bytes"],
            "checks":          doc_res["checks"],
        }

    def _update_row(self, idx):
        f     = self.files[idx]
        ov    = f["overall"]
        level = ov.get("risk_level","?")
        score = ov.get("risk_score", 0)
        iid   = f.get("iid")
        if iid:
            self.file_list.item(
                iid, values=(level, f"{score*100:.0f}%"))
        # Auto-select first completed
        if self.current_idx is None:
            self.current_idx = idx
            if iid:
                self.file_list.selection_set(iid)
            self._show_result(idx)

    def _on_done(self):
        self.progress.stop()
        self.run_btn.configure(state="normal")
        self.export_btn.configure(state="normal")
        done = sum(1 for f in self.files if f["overall"])
        high = sum(1 for f in self.files
                   if f["overall"].get("risk_level") == "HIGH")
        self._set_status(
            f"Analysis complete — {done}/{len(self.files)} files  "
            f"·  {high} HIGH risk")
        if self.current_idx is not None:
            self._show_result(self.current_idx)

    # ── Display ───────────────────────────────────────────────────────────────
    def _show_result(self, idx):
        f  = self.files[idx]
        ov = f["overall"]
        if not ov:
            return

        level = ov["risk_level"]
        col   = _risk_colour(level)
        self.verdict_lbl.configure(
            text=f"{level} RISK\n{ov['verdict']}", fg=col)
        self.risk_lbl.configure(
            text=(f"Score: {ov['risk_score']*100:.0f}%  ·  "
                  f"{ov['positive_count']}/{ov['total_tests']} positive"),
            fg=SUBTEXT)

        self._build_summary(idx)
        self._build_visual(idx)
        self._build_detail(idx)
        self._build_raw(idx)

    # ── Summary tab ───────────────────────────────────────────────────────────
    def _build_summary(self, idx):
        f  = self.files[idx]
        ov = f["overall"]
        for w in self.tab_summary.winfo_children():
            w.destroy()

        canvas = tk.Canvas(self.tab_summary, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(self.tab_summary, orient="vertical",
                           command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)
        inner = tk.Frame(canvas, bg=BG)
        win = canvas.create_window((0,0), window=inner, anchor="nw")
        inner.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
            lambda e: canvas.itemconfig(win, width=canvas.winfo_width()))
        canvas.bind_all("<MouseWheel>",
            lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        level   = ov["risk_level"]
        col     = _risk_colour(level)
        kind    = ov.get("kind","")
        ftype   = ov.get("analyzer_type", ov.get("file_type",""))
        fname   = os.path.basename(f["path"])

        # Top colour strip + header
        tk.Frame(inner, bg=col, height=4).pack(fill="x")
        hdr = tk.Frame(inner, bg=PANEL, highlightthickness=1,
                       highlightbackground=BORDER)
        hdr.pack(fill="x", padx=14, pady=(10,6))
        tk.Label(hdr, text=f"  {level} RISK", bg=PANEL, fg=col,
                 font=("Segoe UI",18,"bold")).pack(side="left", padx=10, pady=8)
        tk.Label(hdr, text=ov["verdict"], bg=PANEL, fg=TEXT,
                 font=FONT_BODY).pack(side="left", padx=8)
        tk.Label(hdr, text=f"{fname}  [{ftype}]", bg=PANEL, fg=SUBTEXT,
                 font=FONT_SMALL).pack(side="right", padx=10)

        # Stats boxes
        sf = tk.Frame(inner, bg=BG)
        sf.pack(fill="x", padx=14, pady=6)
        score = ov["risk_score"] * 100
        pos   = ov["positive_count"]
        tot   = ov["total_tests"]
        fsize = ov.get("file_size_bytes",0)

        if kind == "image":
            sz      = ov.get("image_size",("?","?"))
            payload = ov.get("estimated_payload_pct",0)
            stats   = [
                ("Risk Score",     f"{score:.0f}%",          col),
                ("Tests Positive", f"{pos}/{tot}",            TEXT),
                ("Est. Payload",   f"{payload:.2f}%",         ACCENT3),
                ("Resolution",     f"{sz[0]}×{sz[1]}",        SUBTEXT),
                ("File Size",      f"{fsize/1024:.1f} KB",    SUBTEXT),
            ]
        else:
            stats = [
                ("Risk Score",     f"{score:.0f}%",           col),
                ("Tests Positive", f"{pos}/{tot}",            TEXT),
                ("File Type",      ov.get("file_type","?"),   SUBTEXT),
                ("File Size",      f"{fsize/1024:.1f} KB",    SUBTEXT),
                ("Analyzer",       ftype,                     SUBTEXT),
            ]

        for label, val, vc in stats:
            box = tk.Frame(sf, bg=PANEL, highlightthickness=1,
                           highlightbackground=BORDER)
            box.pack(side="left", padx=(0,6), pady=4, ipadx=10, ipady=8)
            tk.Label(box, text=val, bg=PANEL, fg=vc,
                     font=("Segoe UI",14,"bold")).pack()
            tk.Label(box, text=label, bg=PANEL, fg=SUBTEXT,
                     font=FONT_SMALL).pack()

        # Detection cards
        tk.Label(inner, text="Detection Results", bg=BG, fg=ACCENT,
                 font=FONT_H2).pack(anchor="w", padx=14, pady=(8,4))
        cards = tk.Frame(inner, bg=BG)
        cards.pack(fill="x", padx=14, pady=4)

        if kind == "image":
            self._image_summary_cards(cards, f)
        else:
            checks = ov.get("checks", {})
            for key, check in checks.items():
                self._card(
                    cards,
                    key.replace("_"," ").title(),
                    check.get("detected", False),
                    check.get("info",""),
                    f"Score contribution: {check.get('score',0)}")

        # SHA-256 hash
        fhash = ov.get("file_hash","")
        # ── Hidden Content Panel ────────────────────────────────────
        hidden_content = self._collect_hidden_content(f, kind)
        if hidden_content:
            tk.Label(inner, text="Hidden Content Extracted",
                     bg=BG, fg=RED,
                     font=FONT_H2).pack(anchor="w", padx=14, pady=(8,4))
            for item in hidden_content:
                hc_frame = tk.Frame(inner, bg=PANEL, highlightthickness=1,
                                    highlightbackground=RED)
                hc_frame.pack(fill="x", padx=14, pady=3)
                tk.Frame(hc_frame, bg=RED, width=5).pack(side="left", fill="y")
                hc_inner = tk.Frame(hc_frame, bg=PANEL)
                hc_inner.pack(side="left", fill="both", expand=True, padx=10, pady=8)
                hdr_row = tk.Frame(hc_inner, bg=PANEL)
                hdr_row.pack(fill="x")
                tk.Label(hdr_row, text=item["label"], bg=PANEL, fg=RED,
                         font=("Segoe UI",10,"bold")).pack(side="left")
                tk.Label(hdr_row, text=item["meta"], bg=PANEL, fg=SUBTEXT,
                         font=FONT_SMALL).pack(side="right")
                tf2 = tk.Frame(hc_inner, bg=BG, highlightthickness=1,
                               highlightbackground=BORDER)
                tf2.pack(fill="x", pady=(4,0))
                txt2 = tk.Text(tf2, bg=BG, fg=ACCENT, font=FONT_MONO,
                               relief="flat", bd=0, wrap="word",
                               height=min(8, max(2, item["content"].count("\n")+3)))
                sb2  = ttk.Scrollbar(tf2, orient="vertical", command=txt2.yview)
                txt2.configure(yscrollcommand=sb2.set)
                sb2.pack(side="right", fill="y")
                txt2.pack(fill="both", expand=True, padx=6, pady=6)
                txt2.insert("1.0", item["content"])
                txt2.configure(state="disabled")
        elif level in ("HIGH", "MEDIUM"):
            # Warn that extraction found nothing readable
            no_hc = tk.Frame(inner, bg=PANEL, highlightthickness=1,
                             highlightbackground=BORDER)
            no_hc.pack(fill="x", padx=14, pady=(8,4))
            tk.Label(no_hc,
                     text="⚠  Statistical anomalies detected but no readable hidden text could be extracted.\n"
                          "The payload may use a password, non-standard encoding, or a different embedding algorithm.",
                     bg=PANEL, fg=ACCENT3, font=FONT_SMALL,
                     anchor="w", justify="left", padx=10, pady=8).pack(fill="x")

        if fhash:
            hf = tk.Frame(inner, bg=PANEL, highlightthickness=1,
                          highlightbackground=BORDER)
            hf.pack(fill="x", padx=14, pady=(6,12))
            tk.Label(hf, text=f"SHA-256: {fhash}",
                     bg=PANEL, fg=SUBTEXT, font=FONT_SMALL,
                     anchor="w").pack(fill="x", padx=10, pady=6)

    def _collect_hidden_content(self, f, kind):
        """Collect all extracted hidden content for display. Returns list of dicts.
        Works generically across ALL file types (image, document, audio, video):
        any check that produced readable decoded content gets surfaced here,
        so a new check added later shows up automatically without GUI changes."""
        items = []

        # ── Friendly labels/metadata for known checks (falls back to a
        #    readable auto-generated label for anything not listed here) ──
        LABELS = {
            "hidden_text":        ("Hidden Text (Vanish/Invisible)", "Text runs marked hidden in the document"),
            "white_text":         ("White-Coloured Text", "Text rendered in white (invisible on white background)"),
            "zero_width_chars":   ("Zero-Width Character Message", "Decoded from binary zero-width-character encoding"),
            "notes_stego":        ("Speaker Notes Steganography", "Decoded from hidden characters in PPTX speaker notes"),
            "hidden_slides":      ("Hidden Slide Content", "Text found on slide(s) hidden from normal playback"),
            "offcanvas_shapes":   ("Off-Canvas Shape Text", "Text in shape(s) positioned outside the visible slide area"),
            "hidden_sheets":      ("Hidden Spreadsheet Sheet", "Cell content found in a hidden Excel sheet"),
            "hidden_rows_cols":   ("Hidden Rows/Columns", "Cell content found in hidden rows or columns"),
            "white_or_tiny_cells":("White/Tiny-Font Cells", "Cell content rendered invisible via white font or tiny size"),
            "invisible_text":     ("Invisible PDF Text", "Text rendered invisible (white or near-zero size) in the PDF"),
            "raw_stream_scan":    ("PDF Zero-Width Message", "Decoded from binary zero-width-character encoding in the PDF"),
            "lsb_randomness":     ("LSB Hidden Message (Audio PCM)", "Decoded from the least-significant bits of audio samples"),
            "appended_data":      ("Appended Data", "Raw bytes found after the file's normal end-of-data marker"),
            "unknown_chunks":     ("Non-Standard Chunk Content", "Content found inside a non-standard container chunk"),
            "junk_chunk_content": ("AVI JUNK Chunk Content", "Readable content found inside an AVI padding chunk"),
        }

        if kind == "image":
            ext = f.get("extraction") or {}
            if ext.get("extraction_attempted"):
                best  = ext.get("best_result", {})
                likely = best.get("likely_message", False)
                if likely:
                    text = best.get("text", "").strip()
                    if text:
                        items.append({
                            "label": f"LSB Hidden Message  [{ext.get('best_channel','?')} channel]",
                            "meta":  (f"Printable: {best.get('printable_ratio',0):.1%}  |  "
                                      f"{best.get('length',0)} chars  |  "
                                      f"{'Null-terminated ✓' if best.get('null_terminated') else 'No null terminator'}"),
                            "content": text,
                        })
        else:
            doc_res = f.get("doc_results") or {}
            checks  = doc_res.get("checks", {})

            for key, check in checks.items():
                if not isinstance(check, dict) or not check.get("detected"):
                    continue
                content = (check.get("decoded_content") or check.get("full_content") or "").strip()
                # Strip placeholder "all dots" non-decodes
                if not content or not content.strip("."):
                    continue
                label, meta_default = LABELS.get(
                    key, (key.replace("_", " ").title(), "Hidden content extracted from this file"))
                items.append({
                    "label": label,
                    "meta":  meta_default,
                    "content": content,
                })

        return items

    def _image_summary_cards(self, parent, f):
        tests = [
            ("lsb",         "LSB Analysis",
             lambda r: f"Avg correlation: {r.get('avg_correlation',0):.4f}"),
            ("chi_square",  "Chi-Square Test",
             lambda r: f"Avg p-value: {r.get('average_p_value',1):.4f}"),
            ("rs_analysis", "RS Analysis",
             lambda r: f"Payload estimate: {r.get('average_payload_estimate',0)*100:.2f}%"),
            ("histogram",   "Histogram Analysis",
             lambda r: f"Norm diff: {r.get('avg_norm_diff',0):.4f}"),
            ("dct",         "DCT/FFT Analysis",
             lambda r: f"HF ratio: {r.get('high_frequency_ratio',0):.4f}"),
        ]
        for key, name, metric_fn in tests:
            r = f["results"].get(key, {})
            self._card(parent, name,
                       r.get("detected", False),
                       metric_fn(r) if r else "—",
                       r.get("description",""))

        # Message extraction
        ext = f.get("extraction") or {}
        if ext.get("extraction_attempted"):
            best   = ext.get("best_result",{})
            likely = best.get("likely_message", False)
            null_tag = "  [Null-terminated ✓]" if best.get("null_terminated") else ""
            preview  = best.get("text","")[:300] if likely else "No readable message found"
            self._card(
                parent, "LSB Message Extraction",
                likely,
                (f"Best channel: {ext.get('best_channel','—')}  "
                 f"Printable: {best.get('printable_ratio',0):.1%}  "
                 f"Length: {best.get('length',0)} chars{null_tag}"),
                preview)

    def _card(self, parent, name, detected, metric, desc=""):
        col  = RED if detected else GREEN
        card = tk.Frame(parent, bg=PANEL, highlightthickness=1,
                        highlightbackground=BORDER)
        card.pack(fill="x", pady=2)
        tk.Frame(card, bg=col, width=4).pack(side="left", fill="y")
        cont = tk.Frame(card, bg=PANEL)
        cont.pack(side="left", fill="both", expand=True, padx=10, pady=7)
        top = tk.Frame(cont, bg=PANEL)
        top.pack(fill="x")
        tk.Label(top, text=name, bg=PANEL, fg=TEXT,
                 font=("Segoe UI",10,"bold")).pack(side="left")
        tk.Label(top, text="DETECTED" if detected else "CLEAN",
                 bg=PANEL, fg=col,
                 font=("Segoe UI",9,"bold")).pack(side="right")
        if metric:
            tk.Label(cont, text=str(metric)[:300], bg=PANEL, fg=ACCENT3,
                     font=FONT_MONO, anchor="w").pack(fill="x")
        if desc:
            tk.Label(cont, text=str(desc)[:500], bg=PANEL, fg=SUBTEXT,
                     font=FONT_SMALL, wraplength=800,
                     anchor="w", justify="left").pack(fill="x")

    # ── Visual tab ────────────────────────────────────────────────────────────
    def _build_visual(self, idx):
        f    = self.files[idx]
        kind = f["overall"].get("kind","")
        for w in self.tab_visual.winfo_children():
            w.destroy()

        if kind == "image":
            self._visual_image(f)
        elif kind == "audio":
            self._visual_audio(f)
        elif kind == "video":
            self._visual_video(f)
        else:
            tk.Label(self.tab_visual,
                text=("Visual analysis is available for:\n"
                      "• Images → LSB planes + histograms\n"
                      "• Audio  → waveform + LSB stream\n"
                      "• Video  → frame thumbnails\n\n"
                      "See 'Detailed Results' tab for this file's findings."),
                bg=BG, fg=SUBTEXT, font=FONT_BODY,
                justify="left").pack(expand=True)

    def _visual_image(self, f):
        canvas = tk.Canvas(self.tab_visual, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(self.tab_visual, orient="vertical",
                           command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)
        inner = tk.Frame(canvas, bg=BG)
        win = canvas.create_window((0,0), window=inner, anchor="nw")
        inner.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
            lambda e: canvas.itemconfig(win, width=canvas.winfo_width()))

        def _show(fig, title):
            if fig is None:
                return
            tk.Label(inner, text=title, bg=BG, fg=ACCENT,
                     font=FONT_H2).pack(anchor="w", padx=14, pady=(12,4))
            try:
                pil    = fig_to_pil(fig)
                tk_img = _pil_to_tk(pil)
                self._tk_images.append(tk_img)
                tk.Label(inner, image=tk_img, bg=BG).pack(
                    padx=14, anchor="w")
            except Exception as e:
                tk.Label(inner, text=f"Render error: {e}",
                         bg=BG, fg=ACCENT2, font=FONT_BODY).pack(padx=14)

        try:
            _show(make_lsb_figure(f["analyzer"].np_image),
                  "LSB Bit Planes  (white = bit 1, black = bit 0)")
        except Exception as e:
            tk.Label(inner, text=f"LSB error: {e}",
                     bg=BG, fg=SUBTEXT, font=FONT_BODY).pack(padx=14)
        try:
            _show(make_histogram_figure(f["results"]),
                  "Pixel-Value Histograms  (equalised pairs = suspicious)")
        except Exception as e:
            tk.Label(inner, text=f"Histogram error: {e}",
                     bg=BG, fg=SUBTEXT, font=FONT_BODY).pack(padx=14)
        try:
            _show(make_risk_figure(f["overall"]),
                  "Detection Results per Test")
        except Exception as e:
            tk.Label(inner, text=f"Risk chart error: {e}",
                     bg=BG, fg=SUBTEXT, font=FONT_BODY).pack(padx=14)

    def _visual_audio(self, f):
        tk.Label(self.tab_visual, text="Audio Analysis Visualisation",
                 bg=BG, fg=ACCENT, font=FONT_H2).pack(
                     anchor="w", padx=14, pady=(12,4))
        try:
            import librosa
            import numpy as np
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            samples, sr = librosa.load(
                f["path"], sr=None, mono=True, duration=60)
            fig, axes = plt.subplots(2, 1, figsize=(11, 5), dpi=96)
            fig.patch.set_facecolor("#0d1117")

            # Waveform
            times = np.linspace(0, len(samples)/sr, len(samples))
            axes[0].plot(times, samples, color="#00d4aa",
                        linewidth=0.5, alpha=0.85)
            axes[0].set_facecolor("#161b22")
            axes[0].set_title(
                "Waveform", color="#e6edf3", fontsize=9, pad=4)
            axes[0].set_xlabel("Time (s)", color="#e6edf3", fontsize=7)
            axes[0].set_ylabel("Amplitude", color="#e6edf3", fontsize=7)
            axes[0].tick_params(colors="#e6edf3", labelsize=7)
            for sp in axes[0].spines.values():
                sp.set_edgecolor("#30363d")

            # LSB bit stream
            int_s = (samples * 32767).astype(int)
            lsbs  = (int_s[:2000] & 1).astype(float)
            axes[1].plot(lsbs, color="#ffd93d",
                        linewidth=0.8, drawstyle="steps-mid")
            axes[1].set_facecolor("#161b22")
            axes[1].set_title(
                "LSB Stream — first 2000 samples  "
                "(highly random pattern = suspicious)",
                color="#e6edf3", fontsize=9, pad=4)
            axes[1].set_xlabel("Sample index",
                               color="#e6edf3", fontsize=7)
            axes[1].set_ylabel("LSB value", color="#e6edf3", fontsize=7)
            axes[1].tick_params(colors="#e6edf3", labelsize=7)
            for sp in axes[1].spines.values():
                sp.set_edgecolor("#30363d")

            fig.tight_layout()
            from utils.visualizer import fig_to_pil
            pil    = fig_to_pil(fig)
            tk_img = _pil_to_tk(pil)
            self._tk_images.append(tk_img)
            tk.Label(self.tab_visual, image=tk_img,
                     bg=BG).pack(padx=14, anchor="w")

        except Exception as e:
            tk.Label(self.tab_visual,
                text=f"Could not render audio visualisation:\n{e}",
                bg=BG, fg=SUBTEXT, font=FONT_BODY).pack(padx=14, pady=20)

    def _visual_video(self, f):
        tk.Label(self.tab_visual, text="Video Frame Samples",
                 bg=BG, fg=ACCENT, font=FONT_H2).pack(
                     anchor="w", padx=14, pady=(12,4))
        tk.Label(self.tab_visual,
            text="6 frames sampled evenly from the video. "
                 "See 'Detailed Results' tab for steganography indicators.",
            bg=BG, fg=SUBTEXT, font=FONT_SMALL).pack(
                anchor="w", padx=14, pady=(0,8))
        try:
            import cv2
            from PIL import Image as PILImg
            cap   = cv2.VideoCapture(f["path"])
            total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 1
            row_f = tk.Frame(self.tab_visual, bg=BG)
            row_f.pack(padx=14, pady=4)
            for i in range(6):
                cap.set(cv2.CAP_PROP_POS_FRAMES,
                        int(total * i / 6))
                ret, frame = cap.read()
                if not ret:
                    continue
                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                pil = PILImg.fromarray(rgb)
                pil.thumbnail((190,120), PILImg.LANCZOS)
                tk_img = ImageTk.PhotoImage(pil)
                self._tk_images.append(tk_img)
                tk.Label(row_f, image=tk_img, bg=BG,
                         highlightthickness=1,
                         highlightbackground=BORDER).pack(
                             side="left", padx=4)
            cap.release()
        except Exception as e:
            tk.Label(self.tab_visual,
                text=f"Could not extract frames:\n{e}",
                bg=BG, fg=SUBTEXT, font=FONT_BODY).pack(padx=14)

    # ── Detail tab ────────────────────────────────────────────────────────────
    def _build_detail(self, idx):
        f    = self.files[idx]
        kind = f["overall"].get("kind","")
        for w in self.tab_detail.winfo_children():
            w.destroy()

        if kind == "image":
            self._detail_image(f)
        else:
            self._detail_doc(f)

    def _detail_image(self, f):
        ext = f.get("extraction") or {}
        tk.Label(self.tab_detail,
                 text="LSB Message Extraction Detail",
                 bg=BG, fg=ACCENT, font=FONT_H2).pack(
                     anchor="w", padx=14, pady=(12,4))

        if not ext.get("extraction_attempted"):
            tk.Label(self.tab_detail,
                     text="No extraction data available.",
                     bg=BG, fg=SUBTEXT, font=FONT_BODY).pack(padx=14)
            return

        best   = ext.get("best_result",{})
        likely = best.get("likely_message", False)
        col    = RED if likely else GREEN

        # Banner
        banner = tk.Frame(self.tab_detail, bg=PANEL,
                          highlightthickness=1, highlightbackground=BORDER)
        banner.pack(fill="x", padx=14, pady=(0,8))
        tk.Frame(banner, bg=col, width=4).pack(side="left", fill="y")
        bf = tk.Frame(banner, bg=PANEL)
        bf.pack(side="left", padx=10, pady=10)
        tk.Label(bf,
            text=("HIDDEN MESSAGE DETECTED"
                  if likely else "NO READABLE MESSAGE FOUND"),
            bg=PANEL, fg=col,
            font=("Segoe UI",11,"bold")).pack(anchor="w")
        tk.Label(bf,
            text=(f"Best channel: {ext.get('best_channel','—')}   "
                  f"Printable ratio: {best.get('printable_ratio',0):.1%}   "
                  f"Characters: {best.get('length',0)}"),
            bg=PANEL, fg=SUBTEXT, font=FONT_SMALL).pack(anchor="w")

        # Per-channel table
        tbl = tk.Frame(self.tab_detail, bg=PANEL,
                       highlightthickness=1, highlightbackground=BORDER)
        tbl.pack(fill="x", padx=14, pady=(0,8))
        headers = ["Channel","Length","Printable %","Null-Term","Message Found","Preview"]
        widths  = [16,10,12,10,14,28]
        for ci,(h,w) in enumerate(zip(headers,widths)):
            tk.Label(tbl, text=h, bg=PANEL, fg=ACCENT,
                     font=("Segoe UI",8,"bold"), width=w,
                     anchor="center").grid(row=0,column=ci,padx=4,pady=4)

        for ri,(ch,dat) in enumerate(
                ext.get("channels",{}).items(), 1):
            lm      = dat.get("likely_message", False)
            bg_row  = BG if ri%2==0 else PANEL
            preview = dat.get("text","")[:40].replace("\n"," ")
            null_t  = "✓" if dat.get("null_terminated") else "—"
            vals    = [ch, str(dat.get("length",0)),
                       f"{dat.get('printable_ratio',0):.1%}",
                       null_t,
                       "YES" if lm else "NO", preview]
            for ci,(val,w) in enumerate(zip(vals,widths)):
                fc = RED if (ci==4 and lm) else GREEN if ci==4 else (
                     ACCENT if (ci==3 and null_t=="✓") else TEXT)
                tk.Label(tbl, text=val, bg=bg_row, fg=fc,
                         font=FONT_MONO if ci in(0,5) else FONT_SMALL,
                         width=w,
                         anchor="center" if ci<5 else "w").grid(
                             row=ri,column=ci,padx=4,pady=2)

        # Extracted text — show best channel full content
        tk.Label(self.tab_detail,
                 text=f"Extracted Content  (best channel: {ext.get('best_channel','?')}):",
                 bg=BG, fg=ACCENT, font=FONT_H2).pack(
                     anchor="w", padx=14, pady=(4,4))
        tf = tk.Frame(self.tab_detail, bg=PANEL,
                      highlightthickness=1, highlightbackground=BORDER)
        tf.pack(fill="both", expand=True, padx=14, pady=(0,12))
        txt_fg = ACCENT if likely else SUBTEXT
        txt = tk.Text(tf, bg=PANEL, fg=txt_fg, font=FONT_MONO,
                      relief="flat", bd=0, wrap="word")
        sbt = ttk.Scrollbar(tf, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sbt.set)
        sbt.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        content = (best.get("text","") or "(no readable content)")
        txt.insert("1.0", content)
        txt.configure(state="disabled")

    def _detail_doc(self, f):
        doc_res = f.get("doc_results") or {}
        if not doc_res:
            # Show error if there was one
            err = f.get("error","No detailed results available.")
            tk.Label(self.tab_detail, text=err,
                     bg=BG, fg=ACCENT2, font=FONT_BODY,
                     wraplength=700, justify="left").pack(
                         expand=True, padx=20)
            return

        tk.Label(self.tab_detail,
                 text=f"Detailed Analysis — {doc_res.get('analyzer_type','')}",
                 bg=BG, fg=ACCENT, font=FONT_H2).pack(
                     anchor="w", padx=14, pady=(12,4))

        # Summary banner
        level = doc_res["risk_level"]
        col   = _risk_colour(level)
        banner = tk.Frame(self.tab_detail, bg=PANEL,
                          highlightthickness=1, highlightbackground=BORDER)
        banner.pack(fill="x", padx=14, pady=(0,8))
        tk.Frame(banner, bg=col, width=4).pack(side="left", fill="y")
        bf = tk.Frame(banner, bg=PANEL)
        bf.pack(side="left", padx=10, pady=10)
        tk.Label(bf, text=doc_res["summary"], bg=PANEL, fg=col,
                 font=("Segoe UI",10,"bold"),
                 wraplength=800, anchor="w").pack(fill="x")
        tk.Label(bf,
            text=(f"Score: {doc_res['total_score']}/100   "
                  f"Risk: {level}   "
                  f"SHA-256: {doc_res['file_hash'][:24]}…"),
            bg=PANEL, fg=SUBTEXT, font=FONT_SMALL).pack(anchor="w")

        # Scrollable check cards
        canvas = tk.Canvas(self.tab_detail, bg=BG, highlightthickness=0)
        sb2 = ttk.Scrollbar(self.tab_detail, orient="vertical",
                            command=canvas.yview)
        canvas.configure(yscrollcommand=sb2.set)
        sb2.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True, padx=14, pady=(0,12))
        inner = tk.Frame(canvas, bg=BG)
        win = canvas.create_window((0,0), window=inner, anchor="nw")
        inner.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
            lambda e: canvas.itemconfig(win, width=canvas.winfo_width()))

        for key, check in doc_res["checks"].items():
            detected = check.get("detected", False)
            sc = RED if detected else GREEN
            card = tk.Frame(inner, bg=PANEL, highlightthickness=1,
                            highlightbackground=BORDER)
            card.pack(fill="x", pady=2)
            tk.Frame(card, bg=sc, width=4).pack(side="left", fill="y")
            cont = tk.Frame(card, bg=PANEL)
            cont.pack(side="left", fill="both", expand=True,
                      padx=10, pady=7)

            top = tk.Frame(cont, bg=PANEL)
            top.pack(fill="x")
            tk.Label(top, text=key.replace("_"," ").title(),
                     bg=PANEL, fg=TEXT,
                     font=("Segoe UI",10,"bold")).pack(side="left")
            tk.Label(top,
                     text="DETECTED" if detected else "CLEAN",
                     bg=PANEL, fg=sc,
                     font=("Segui",9,"bold")).pack(side="right")

            tk.Label(cont, text=check.get("info",""),
                     bg=PANEL, fg=ACCENT3 if detected else SUBTEXT,
                     font=FONT_MONO, anchor="w").pack(fill="x")

            # Decoded hidden content, if this check extracted any
            decoded = check.get("decoded_content","")
            if decoded and decoded.strip().strip('.'):
                tk.Label(cont, text="Extracted content:",
                         bg=PANEL, fg=RED, font=("Segoe UI",8,"bold"),
                         anchor="w").pack(fill="x", pady=(4,0))
                dtf = tk.Frame(cont, bg=BG, highlightthickness=1,
                              highlightbackground=BORDER)
                dtf.pack(fill="x", pady=(2,2))
                dtxt = tk.Text(dtf, bg=BG, fg=ACCENT, font=FONT_MONO,
                               relief="flat", bd=0, wrap="word",
                               height=min(6, max(2, decoded.count("\n")+2)))
                dsb  = ttk.Scrollbar(dtf, orient="vertical", command=dtxt.yview)
                dtxt.configure(yscrollcommand=dsb.set)
                dsb.pack(side="right", fill="y")
                dtxt.pack(fill="both", expand=True, padx=5, pady=5)
                dtxt.insert("1.0", decoded)
                dtxt.configure(state="disabled")

            # Sub-details
            for sub in ("found","suspicious_keys","zero_width",
                        "homoglyphs","samples","sheets",
                        "parts","indices"):
                val = check.get(sub)
                if val:
                    txt = json.dumps(val, ensure_ascii=False)[:300]
                    tk.Label(cont, text=f"  {sub}: {txt}",
                             bg=PANEL, fg=SUBTEXT, font=FONT_SMALL,
                             wraplength=800, anchor="w",
                             justify="left").pack(fill="x")

    # ── Raw JSON tab ──────────────────────────────────────────────────────────
    def _build_raw(self, idx):
        f = self.files[idx]
        if f["kind"] == "image":
            out = {
                "kind":    "image",
                "file":    f["path"],
                "time":    datetime.now().isoformat(),
                "overall": f["overall"],
                "extraction": {
                    k: {ik:iv for ik,iv in v.items() if ik != "text"}
                    for k,v in
                    (f["extraction"] or {}).get("channels",{}).items()
                },
                "details": {
                    k: {ik:iv for ik,iv in v.items()
                        if ik not in ("magnitude_spectrum","histogram")}
                    for k,v in f["results"].items()
                },
            }
        else:
            out = {
                "kind":        f["kind"],
                "file":        f["path"],
                "time":        datetime.now().isoformat(),
                "overall":     f["overall"],
                "doc_results": f.get("doc_results") or {},
            }
        text = json.dumps(out, indent=2, default=str)
        self.raw_text.configure(state="normal")
        self.raw_text.delete("1.0", "end")
        self.raw_text.insert("1.0", text)
        self.raw_text.configure(state="disabled")

    # ── PDF Export ────────────────────────────────────────────────────────────
    def _export_pdf(self):
        done = [f for f in self.files if f["overall"]]
        if not done:
            messagebox.showwarning("No Results",
                                   "Run analysis first.")
            return
        default = (
            f"stego_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        path = filedialog.asksaveasfilename(
            title="Save PDF Report",
            defaultextension=".pdf",
            initialfile=default,
            filetypes=[("PDF Files","*.pdf"),("All Files","*.*")])
        if not path:
            return
        try:
            batch = []
            for f in done:
                ov = dict(f["overall"])
                # Ensure image-specific keys exist for report.py
                if f["kind"] != "image":
                    ov.setdefault("image_size",(0,0))
                    ov.setdefault("image_format", ov.get("file_type","?"))
                    ov.setdefault("image_mode","N/A")
                    ov.setdefault("estimated_payload_pct",0)
                    ov.setdefault("detections",
                        {k:v.get("detected",False)
                         for k,v in
                         f.get("doc_results",{}).get("checks",{}).items()})
                batch.append({
                    "image_path":       f["path"],
                    "analysis_results": f.get("results",{}),
                    "overall":          ov,
                    "extraction":       f.get("extraction"),
                })
            generate_batch_report(batch, path)
            messagebox.showinfo(
                "Report Saved",
                f"PDF report saved to:\n{path}\n\n"
                f"{len(done)} file(s) included.")
        except Exception as e:
            messagebox.showerror("Export Error",
                                 f"Could not save PDF:\n{e}")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    app.mainloop()
