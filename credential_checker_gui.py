#!/usr/bin/env python3
"""
Credential Breach Checker - Python GUI
Checks email/password combinations against HaveIBeenPwned API + breach databases.
Run: python3 credential_checker_gui.py
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading, queue, csv, os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from modules.credential_checker import (
    check_password_pwned, check_email_breached,
    check_single_credential, check_credentials_bulk, check_password_strength
)

class CredentialCheckerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Credential Breach Checker - Threat Intel Platform")
        self.root.geometry("1100x750")
        self.root.minsize(900, 600)
        self.colors = {
            'bg': '#0a0e14', 'bg2': '#11161d', 'bg3': '#1a202c',
            'fg': '#e1e4e8', 'fg2': '#8b949e', 'accent': '#58a6ff',
            'critical': '#ff4444', 'high': '#ff8c00', 'medium': '#ffc107',
            'low': '#4caf50', 'success': '#00c853', 'failure': '#ff1744',
            'border': '#252d3a',
        }
        self.root.configure(bg=self.colors['bg'])
        self._build_ui()
        self.result_queue = queue.Queue()
        self._process_queue()

    def _build_ui(self):
        main = tk.Frame(self.root, bg=self.colors['bg'])
        main.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
        notebook = ttk.Notebook(main)
        notebook.pack(fill=tk.BOTH, expand=True)

        tab1 = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(tab1, text="  Single Check  ")
        self._build_single_check(tab1)

        tab2 = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(tab2, text="  Bulk Check  ")
        self._build_bulk_check(tab2)

        tab3 = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(tab3, text="  Strength Analyzer  ")
        self._build_strength_analyzer(tab3)

        sf = tk.Frame(main, bg=self.colors['bg2'], height=30)
        sf.pack(fill=tk.X, side=tk.BOTTOM)
        sf.pack_propagate(False)
        self.status_label = tk.Label(sf, text="Ready", bg=self.colors['bg2'],
                                      fg=self.colors['fg2'], font=('Inter', 10), anchor='w')
        self.status_label.pack(side=tk.LEFT, padx=12, pady=4, fill=tk.X, expand=True)
        self.progress = ttk.Progressbar(sf, mode='indeterminate', length=120)
        self.progress.pack(side=tk.RIGHT, padx=12, pady=4)

    def _build_single_check(self, parent):
        c = tk.Frame(parent, bg=self.colors['bg'])
        c.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        tk.Label(c, text="Single Credential Check", font=('Inter', 20, 'bold'),
                 fg=self.colors['fg'], bg=self.colors['bg']).pack(anchor='w', pady=(0, 4))
        tk.Label(c, text="Check if an email/password has been compromised in data breaches",
                 font=('Inter', 11), fg=self.colors['fg2'], bg=self.colors['bg']).pack(anchor='w', pady=(0, 20))

        form = tk.Frame(c, bg=self.colors['bg3'], highlightbackground=self.colors['border'],
                        highlightthickness=1, padx=20, pady=20)
        form.pack(fill=tk.X)

        tk.Label(form, text="Email Address", fg=self.colors['fg2'], bg=self.colors['bg3'],
                 font=('Inter', 11, 'bold')).pack(anchor='w')
        self.email_entry = tk.Entry(form, bg=self.colors['bg'], fg=self.colors['fg'],
                                     font=('Inter', 13), insertbackground=self.colors['fg'], relief=tk.FLAT)
        self.email_entry.pack(fill=tk.X, pady=(4, 12), ipady=6)

        tk.Label(form, text="Password (optional - checked via k-anonymity)", fg=self.colors['fg2'],
                 bg=self.colors['bg3'], font=('Inter', 11, 'bold')).pack(anchor='w')
        self.pass_entry = tk.Entry(form, bg=self.colors['bg'], fg=self.colors['fg'],
                                    font=('Inter', 13), insertbackground=self.colors['fg'],
                                    show="*", relief=tk.FLAT)
        self.pass_entry.pack(fill=tk.X, pady=(4, 12), ipady=6)

        self.show_pass = tk.BooleanVar()
        tk.Checkbutton(form, text="Show password", variable=self.show_pass,
                       command=lambda: self.pass_entry.config(show="" if self.show_pass.get() else "*"),
                       bg=self.colors['bg3'], fg=self.colors['fg2'],
                       selectcolor=self.colors['bg'], activebackground=self.colors['bg3'],
                       activeforeground=self.colors['fg'], font=('Inter', 10)).pack(anchor='w', pady=(0, 8))

        bf = tk.Frame(form, bg=self.colors['bg3'])
        bf.pack(fill=tk.X, pady=(8, 0))
        self.check_btn = tk.Button(bf, text="Check Credential", command=self._run_single_check,
                                    bg=self.colors['accent'], fg='#fff', font=('Inter', 12, 'bold'),
                                    relief=tk.FLAT, cursor='hand2', padx=24, pady=8)
        self.check_btn.pack(side=tk.LEFT)
        tk.Button(bf, text="Clear", command=self._clear_single, bg=self.colors['bg'],
                  fg=self.colors['fg2'], font=('Inter', 11), relief=tk.FLAT, cursor='hand2',
                  padx=16, pady=8).pack(side=tk.LEFT, padx=8)

        self.single_result_frame = tk.Frame(c, bg=self.colors['bg'])
        self.single_result_frame.pack(fill=tk.BOTH, expand=True, pady=(16, 0))

    def _clear_single(self):
        self.email_entry.delete(0, tk.END)
        self.pass_entry.delete(0, tk.END)
        for w in self.single_result_frame.winfo_children():
            w.destroy()

    def _run_single_check(self):
        email = self.email_entry.get().strip()
        password = self.pass_entry.get().strip() or None
        if not email:
            messagebox.showwarning("Missing Input", "Please enter an email address.")
            return
        self.check_btn.config(state=tk.DISABLED, text="Checking...")
        self.progress.start()
        self.status_label.config(text=f"Checking {email}...")
        threading.Thread(target=self._single_check_thread, args=(email, password), daemon=True).start()

    def _single_check_thread(self, email, password):
        try:
            result = check_single_credential(email, password)
            self.result_queue.put(('single', result))
        except Exception as e:
            self.result_queue.put(('error', str(e)))

    def _display_single_result(self, result):
        for w in self.single_result_frame.winfo_children():
            w.destroy()
        status = result.get('status', 'FAILURE')
        bg_color = self.colors['low'] if status == 'SUCCESS' else self.colors['critical']
        banner = tk.Frame(self.single_result_frame, bg=bg_color)
        banner.pack(fill=tk.X, pady=(0, 12))
        tk.Label(banner, text=f"{status}: {status}", font=('Inter', 20, 'bold'),
                 fg='#fff', bg=bg_color).pack(pady=14)

        df = tk.Frame(self.single_result_frame, bg=self.colors['bg3'],
                      highlightbackground=self.colors['border'], highlightthickness=1)
        df.pack(fill=tk.X, pady=(0, 8))
        for label, value in [
            ("Email", result.get('email', '')),
            ("Email Breached", "YES" if result.get('email_breached') else "NO"),
            ("Password Pwned", f"YES ({result.get('password_count', 0):,} times)" if result.get('password_pwned') else "NO"),
            ("Risk Level", result.get('risk_level', 'unknown').upper()),
            ("Checked At", result.get('checked_at', '')),
        ]:
            row = tk.Frame(df, bg=self.colors['bg3'])
            row.pack(fill=tk.X, padx=16, pady=4)
            tk.Label(row, text=label, fg=self.colors['fg2'], bg=self.colors['bg3'],
                     font=('Inter', 11, 'bold'), width=18, anchor='w').pack(side=tk.LEFT)
            fg = self.colors['fg']
            if 'YES' in str(value): fg = self.colors['failure']
            if str(value) == 'NO': fg = self.colors['success']
            tk.Label(row, text=str(value), fg=fg, bg=self.colors['bg3'],
                     font=('Inter', 11), wraplength=500, anchor='w').pack(side=tk.LEFT)

        rf = tk.Frame(self.single_result_frame, bg=self.colors['bg3'],
                      highlightbackground=self.colors['border'], highlightthickness=1)
        rf.pack(fill=tk.X, pady=(0, 8))
        tk.Label(rf, text="Recommendation", fg=self.colors['fg2'], bg=self.colors['bg3'],
                 font=('Inter', 11, 'bold')).pack(anchor='w', padx=16, pady=(10, 4))
        tk.Label(rf, text=result.get('recommendation', ''), fg=self.colors['fg'],
                 bg=self.colors['bg3'], font=('Inter', 11), wraplength=700, justify=tk.LEFT).pack(
                     anchor='w', padx=16, pady=(0, 10))

        if result.get('email_breaches'):
            bf = tk.Frame(self.single_result_frame, bg=self.colors['bg3'],
                          highlightbackground=self.colors['border'], highlightthickness=1)
            bf.pack(fill=tk.X)
            tk.Label(bf, text=f"Breaches ({len(result['email_breaches'])})",
                     fg=self.colors['failure'], bg=self.colors['bg3'],
                     font=('Inter', 11, 'bold')).pack(anchor='w', padx=16, pady=(10, 4))
            for breach in result.get('email_details', []):
                tk.Label(bf, text=f"  * {breach.get('name', '?')} - {breach.get('date', '?')}",
                         fg=self.colors['fg2'], bg=self.colors['bg3'],
                         font=('Inter', 10)).pack(anchor='w', padx=16)
            tk.Label(bf, text="", bg=self.colors['bg3']).pack()

    def _build_bulk_check(self, parent):
        c = tk.Frame(parent, bg=self.colors['bg'])
        c.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        tk.Label(c, text="Bulk Credential Check", font=('Inter', 20, 'bold'),
                 fg=self.colors['fg'], bg=self.colors['bg']).pack(anchor='w', pady=(0, 4))
        tk.Label(c, text="Check multiple credentials (email:password, one per line)",
                 font=('Inter', 11), fg=self.colors['fg2'], bg=self.colors['bg']).pack(anchor='w', pady=(0, 16))

        inf = tk.Frame(c, bg=self.colors['bg3'], highlightbackground=self.colors['border'], highlightthickness=1)
        inf.pack(fill=tk.BOTH, expand=False, pady=(0, 12))
        tk.Label(inf, text="Credentials (email:password)", fg=self.colors['fg2'],
                 bg=self.colors['bg3'], font=('Inter', 11, 'bold')).pack(anchor='w', padx=16, pady=(10, 4))

        self.bulk_text = scrolledtext.ScrolledText(inf, height=8, wrap=tk.WORD,
                                                     bg=self.colors['bg'], fg=self.colors['fg'],
                                                     font=('Cascadia Code', 11),
                                                     insertbackground=self.colors['fg'], relief=tk.FLAT)
        self.bulk_text.pack(fill=tk.X, padx=16, pady=(0, 10))

        bf = tk.Frame(inf, bg=self.colors['bg3'])
        bf.pack(fill=tk.X, padx=16, pady=(0, 12))
        self.bulk_check_btn = tk.Button(bf, text="Check All", command=self._run_bulk_check,
                                         bg=self.colors['accent'], fg='#fff', font=('Inter', 12, 'bold'),
                                         relief=tk.FLAT, cursor='hand2', padx=24, pady=8)
        self.bulk_check_btn.pack(side=tk.LEFT)
        tk.Button(bf, text="Load Sample", command=self._load_sample,
                  bg=self.colors['bg'], fg=self.colors['fg2'], font=('Inter', 11),
                  relief=tk.FLAT, cursor='hand2', padx=16, pady=8).pack(side=tk.LEFT, padx=8)
        tk.Button(bf, text="Load CSV", command=self._load_csv,
                  bg=self.colors['bg'], fg=self.colors['fg2'], font=('Inter', 11),
                  relief=tk.FLAT, cursor='hand2', padx=16, pady=8).pack(side=tk.LEFT, padx=8)

        self.bulk_stats_frame = tk.Frame(c, bg=self.colors['bg'])
        self.bulk_stats_frame.pack(fill=tk.X, pady=(0, 8))

        tc = tk.Frame(c, bg=self.colors['bg3'], highlightbackground=self.colors['border'], highlightthickness=1)
        tc.pack(fill=tk.BOTH, expand=True)
        hf = tk.Frame(tc, bg=self.colors['bg2'])
        hf.pack(fill=tk.X)
        for col, w in [("Email", 30), ("Status", 12), ("Risk", 12), ("Pwd Pwned", 14), ("Breaches", 8), ("Recommendation", 50)]:
            tk.Label(hf, text=col, fg=self.colors['fg2'], bg=self.colors['bg2'],
                     font=('Inter', 10, 'bold'), width=w, anchor='w', padx=8, pady=6).pack(side=tk.LEFT)

        self.brf = tk.Frame(tc, bg=self.colors['bg3'])
        self.brf.pack(fill=tk.BOTH, expand=True)
        canvas = tk.Canvas(self.brf, bg=self.colors['bg3'], highlightthickness=0)
        sb = ttk.Scrollbar(self.brf, orient=tk.VERTICAL, command=canvas.yview)
        self.bulk_inner = tk.Frame(canvas, bg=self.colors['bg3'])
        self.bulk_inner.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.create_window((0, 0), window=self.bulk_inner, anchor='nw')
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    def _load_sample(self):
        sample = "user@yahoo.com:password123\njohn.doe@gmail.com:MyS3cur3!Pass\nadmin@company.com:admin2024\njane@outlook.com:P@ssw0rd!\ntest@example.com:qwerty123"
        self.bulk_text.delete('1.0', tk.END)
        self.bulk_text.insert('1.0', sample)

    def _load_csv(self):
        fp = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv"), ("Text", "*.txt")])
        if not fp: return
        with open(fp, 'r') as f:
            reader = csv.reader(f)
            lines = []
            for row in reader:
                if len(row) >= 2: lines.append(f"{row[0].strip()}:{row[1].strip()}")
                elif len(row) >= 1: lines.append(row[0].strip())
            self.bulk_text.delete('1.0', tk.END)
            self.bulk_text.insert('1.0', '\n'.join(lines))

    def _run_bulk_check(self):
        raw = self.bulk_text.get('1.0', tk.END).strip()
        if not raw:
            messagebox.showwarning("No Input", "Please enter credentials.")
            return
        lines = [l.strip() for l in raw.split('\n') if l.strip()]
        creds = []
        for line in lines:
            parts = line.split(':', 1)
            creds.append({'email': parts[0].strip(), 'password': parts[1].strip() if len(parts) > 1 else None})
        self.bulk_check_btn.config(state=tk.DISABLED, text=f"Checking {len(creds)}...")
        self.progress.start()
        for w in self.bulk_stats_frame.winfo_children(): w.destroy()
        for w in self.bulk_inner.winfo_children(): w.destroy()
        threading.Thread(target=self._bulk_thread, args=(creds,), daemon=True).start()

    def _bulk_thread(self, creds):
        try:
            results = check_credentials_bulk(creds)
            self.result_queue.put(('bulk', results))
        except Exception as e:
            self.result_queue.put(('error', str(e)))

    def _display_bulk_results(self, results):
        for w in self.bulk_stats_frame.winfo_children(): w.destroy()
        comp = sum(1 for r in results if r.get('status') == 'FAILURE')
        safe = len(results) - comp
        for v, l, c in [(f"FAIL: {comp}", "Compromised", self.colors['failure']),
                         (f"OK: {safe}", "Safe", self.colors['success']),
                         (f"Total: {len(results)}", "Total", self.colors['accent'])]:
            stat = tk.Frame(self.bulk_stats_frame, bg=self.colors['bg3'],
                            highlightbackground=self.colors['border'], highlightthickness=1)
            stat.pack(side=tk.LEFT, padx=(0, 8), ipadx=20, ipady=8)
            tk.Label(stat, text=v, fg=c, bg=self.colors['bg3'], font=('Inter', 18, 'bold')).pack()
            tk.Label(stat, text=l, fg=self.colors['fg2'], bg=self.colors['bg3'], font=('Inter', 10)).pack()

        for w in self.bulk_inner.winfo_children(): w.destroy()
        for i, r in enumerate(results):
            bg = self.colors['bg3'] if i % 2 == 0 else self.colors['bg2']
            row = tk.Frame(self.bulk_inner, bg=bg)
            row.pack(fill=tk.X)
            st = r.get('status', 'FAILURE')
            sc = self.colors['success'] if st == 'SUCCESS' else self.colors['failure']
            risk = r.get('risk_level', 'unknown')
            rc = {'critical': self.colors['critical'], 'high': self.colors['high'],
                  'medium': self.colors['medium'], 'low': self.colors['low']}.get(risk, self.colors['fg2'])
            for txt, clr, w in [
                (r.get('email', '')[:30], self.colors['fg'], 30),
                (st, sc, 12), (risk.upper(), rc, 12),
                ("YES" if r.get('password_pwned') else "NO",
                 self.colors['failure'] if r.get('password_pwned') else self.colors['success'], 14),
                (str(len(r.get('email_breaches', []))), self.colors['fg2'], 8),
                (r.get('recommendation', '')[:60], self.colors['fg2'], 50),
            ]:
                tk.Label(row, text=txt, fg=clr, bg=bg, font=('Inter', 10),
                         width=w, anchor='w', padx=8, pady=4).pack(side=tk.LEFT)

    def _build_strength_analyzer(self, parent):
        c = tk.Frame(parent, bg=self.colors['bg'])
        c.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        tk.Label(c, text="Password Strength Analyzer", font=('Inter', 20, 'bold'),
                 fg=self.colors['fg'], bg=self.colors['bg']).pack(anchor='w', pady=(0, 4))
        tk.Label(c, text="Analyze password entropy, complexity, and common patterns",
                 font=('Inter', 11), fg=self.colors['fg2'], bg=self.colors['bg']).pack(anchor='w', pady=(0, 20))

        inf = tk.Frame(c, bg=self.colors['bg3'], highlightbackground=self.colors['border'],
                       highlightthickness=1, padx=20, pady=20)
        inf.pack(fill=tk.X)
        tk.Label(inf, text="Enter Password", fg=self.colors['fg2'], bg=self.colors['bg3'],
                 font=('Inter', 11, 'bold')).pack(anchor='w')
        pf = tk.Frame(inf, bg=self.colors['bg3'])
        pf.pack(fill=tk.X, pady=(6, 0))
        self.analyze_entry = tk.Entry(pf, bg=self.colors['bg'], fg=self.colors['fg'],
                                       font=('Inter', 14), insertbackground=self.colors['fg'],
                                       show="*", relief=tk.FLAT)
        self.analyze_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)
        self.analyze_entry.bind('<KeyRelease>', lambda e: self._analyze_password())
        self.show_az = tk.BooleanVar()
        tk.Checkbutton(pf, text="Show", variable=self.show_az,
                       command=lambda: self.analyze_entry.config(show="" if self.show_az.get() else "*"),
                       bg=self.colors['bg3'], fg=self.colors['fg2'],
                       selectcolor=self.colors['bg'], activebackground=self.colors['bg3'],
                       activeforeground=self.colors['fg'], font=('Inter', 10)).pack(side=tk.RIGHT, padx=8)

        self.analyze_result_frame = tk.Frame(c, bg=self.colors['bg'])
        self.analyze_result_frame.pack(fill=tk.BOTH, expand=True, pady=(16, 0))

    def _analyze_password(self):
        pwd = self.analyze_entry.get()
        for w in self.analyze_result_frame.winfo_children(): w.destroy()
        if not pwd: return

        result = check_password_strength(pwd)
        score = result.get('score', 0)
        strength = result.get('strength', 'Unknown')
        cmap = {'Very Strong': self.colors['success'], 'Strong': '#4caf50',
                'Moderate': self.colors['medium'], 'Weak': self.colors['high'],
                'Very Weak': self.colors['critical']}
        bar_color = cmap.get(strength, self.colors['fg2'])

        mf = tk.Frame(self.analyze_result_frame, bg=self.colors['bg3'],
                      highlightbackground=self.colors['border'], highlightthickness=1)
        mf.pack(fill=tk.X, pady=(0, 12))
        tk.Label(mf, text="Strength Score", fg=self.colors['fg2'], bg=self.colors['bg3'],
                 font=('Inter', 11, 'bold')).pack(anchor='w', padx=16, pady=(10, 4))
        bar_bg = tk.Frame(mf, bg=self.colors['bg'], height=24)
        bar_bg.pack(fill=tk.X, padx=16, pady=(4, 8))
        bar_fill = tk.Frame(bar_bg, bg=bar_color, height=24)
        bar_fill.place(relx=0, rely=0, relwidth=score/100, relheight=1)

        sf2 = tk.Frame(mf, bg=self.colors['bg3'])
        sf2.pack(fill=tk.X, padx=16, pady=(0, 10))
        tk.Label(sf2, text=f"{strength} ({score}/100)", fg=bar_color,
                 bg=self.colors['bg3'], font=('Inter', 18, 'bold')).pack(side=tk.LEFT)
        tk.Label(sf2, text=f"Entropy: ~{result.get('entropy_bits', 0)} bits",
                 fg=self.colors['fg2'], bg=self.colors['bg3'], font=('Inter', 11)).pack(side=tk.RIGHT)

        df = tk.Frame(self.analyze_result_frame, bg=self.colors['bg3'],
                      highlightbackground=self.colors['border'], highlightthickness=1)
        df.pack(fill=tk.X)
        for l, v in [("Length", f"{result.get('length', 0)} chars"), ("Entropy", f"~{result.get('entropy_bits', 0)} bits")]:
            row = tk.Frame(df, bg=self.colors['bg3'])
            row.pack(fill=tk.X, padx=16, pady=4)
            tk.Label(row, text=l, fg=self.colors['fg2'], bg=self.colors['bg3'],
                     font=('Inter', 11, 'bold'), width=16, anchor='w').pack(side=tk.LEFT)
            tk.Label(row, text=v, fg=self.colors['fg'], bg=self.colors['bg3'],
                     font=('Inter', 11)).pack(side=tk.LEFT)

        fb = result.get('feedback', [])
        if fb:
            ff = tk.Frame(self.analyze_result_frame, bg=self.colors['bg3'],
                          highlightbackground=self.colors['border'], highlightthickness=1)
            ff.pack(fill=tk.X, pady=(12, 0))
            tk.Label(ff, text="Recommendations", fg=self.colors['fg2'], bg=self.colors['bg3'],
                     font=('Inter', 11, 'bold')).pack(anchor='w', padx=16, pady=(10, 4))
            for f in fb:
                icon = "OK" if "good" in f.lower() else "WARN"
                color = self.colors['success'] if "good" in f.lower() else self.colors['high']
                tk.Label(ff, text=f"  {icon}: {f}", fg=color, bg=self.colors['bg3'],
                         font=('Inter', 10)).pack(anchor='w', padx=16)
            tk.Label(ff, text="", bg=self.colors['bg3']).pack()

    def _process_queue(self):
        try:
            while True:
                mt, data = self.result_queue.get_nowait()
                if mt == 'single':
                    self._display_single_result(data)
                    self.status_label.config(text="Single check complete")
                elif mt == 'bulk':
                    self._display_bulk_results(data)
                    self.status_label.config(text=f"Bulk check complete: {len(data)} checked")
                elif mt == 'error':
                    messagebox.showerror("Error", str(data))
                self.progress.stop()
                self.check_btn.config(state=tk.NORMAL, text="Check Credential")
                self.bulk_check_btn.config(state=tk.NORMAL, text="Check All")
        except queue.Empty:
            pass
        self.root.after(200, self._process_queue)

    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    CredentialCheckerGUI().run()
