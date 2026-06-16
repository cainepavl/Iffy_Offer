"""
gui.py
------
Tkinter GUI for Iffy Offer.

Layout (top to bottom):
  ┌─────────────────────────────────────────────┐
  │  BS_DTect                      [☀ / ☾ mode] │  ← title bar frame
  │  ─────────────────────────────────────────  │  ← separator
  ├─────────────────────────────────────────────┤
  │  Company Name: [___________________________]│  ← input frame
  │  Sender Email: [___________________________]│
  │  Raw Headers (optional — paste & submit):   │
  │  ┌─────────────────────────────────────────┐│
  │  │                                         ││  ← header text area
  │  └─────────────────────────────────────────┘│
  │                 [ Analyze Email ]            │  ← action button
  ├─────────────────────────────────────────────┤
  │  Results:                                   │  ← results frame (scrollable)
  │  ▌ [✓] Check name       detail text   (+0) │
  │  ▌ [✗] Check name       detail text  (-30) │
  │  ─────────────────────────────────────────  │
  │  VERDICT: Yikes!  (score: –45)               │  ← verdict panel
  └─────────────────────────────────────────────┘

Dark/light mode:
  A palette dict defines every color used in the UI.
  Switching modes re-applies the palette to every widget without rebuilding.

Threading:
  DNS and WHOIS lookups can each take several seconds.
  Analysis runs in a background thread so the GUI stays responsive.
  Results are passed back to the main thread via a queue and polled with after().
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue

from checks.domain    import extract_domain, is_free_provider, is_ats_platform, check_domain_vs_company
from checks.dns_check import check_mx_records, check_spf_record, check_dmarc_record
from checks.whois_check import get_domain_age
from checks.header    import parse_headers, check_display_name_mismatch, check_reply_to_mismatch
from scorer           import build_score


# ---------------------------------------------------------------------------
# Colour palettes
# ---------------------------------------------------------------------------

DARK_PALETTE = {
    'bg':           '#1e1e2e',
    'surface':      '#2a2a3d',
    'surface2':     '#313244',
    'border':       '#45475a',
    'text':         '#cdd6f4',
    'text_dim':     '#a6adc8',
    'accent':       '#89b4fa',
    'accent_hover': '#b4d0ff',
    'ok':           '#a6e3a1',
    'warning':      '#f9e2af',
    'fail':         '#f38ba8',
    'unknown':      '#cba6f7',
    'verdict_low':  '#a6e3a1',
    'verdict_med':  '#f9e2af',
    'verdict_high': '#f38ba8',
    'disclaimer':   '#6c7086',
    'btn_bg':       '#89b4fa',
    'btn_fg':       '#1e1e2e',
    'clear_btn_bg': '#fab387',   # peach — warm contrast to the blue Analyze button
    'clear_btn_fg': '#1e1e2e',
    'mode_btn_bg':  '#313244',
    'mode_btn_fg':  '#cdd6f4',
}

LIGHT_PALETTE = {
    'bg':           '#eff1f5',
    'surface':      '#ffffff',
    'surface2':     '#e6e9ef',
    'border':       '#ccd0da',
    'text':         '#4c4f69',
    'text_dim':     '#6c6f85',
    'accent':       '#1e66f5',
    'accent_hover': '#0a4ccf',
    'ok':           '#40a02b',
    'warning':      '#df8e1d',
    'fail':         '#d20f39',
    'unknown':      '#8839ef',
    'verdict_low':  '#40a02b',
    'verdict_med':  '#df8e1d',
    'verdict_high': '#d20f39',
    'disclaimer':   '#8c8fa1',
    'btn_bg':       '#1e66f5',
    'btn_fg':       '#ffffff',
    'clear_btn_bg': '#fe640b',   # orange — warm contrast to the blue Analyze button
    'clear_btn_fg': '#ffffff',
    'mode_btn_bg':  '#ccd0da',
    'mode_btn_fg':  '#4c4f69',
}

STATUS_ICONS = {
    'ok':      '✓',
    'warning': '⚠',
    'fail':    '✗',
    'unknown': '?',
    'info':    'i',
}


class IffyOfferApp:
    """Main application class. Owns the root Tk window and all widgets."""

    def __init__(self, root: tk.Tk):
        self.root    = root
        self.palette = DARK_PALETTE
        self.mode    = 'dark'

        self._result_queue: queue.Queue = queue.Queue()
        # Detail labels stored so we can update wraplength when the window resizes
        self._detail_labels: list = []

        self._build_ui()
        self._apply_theme()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        """Create all widgets. Called once at startup."""
        self.root.title('Iffy Offer — Job Offer Email Checker')
        self.root.geometry('960x780')
        self.root.resizable(True, True)
        self.root.minsize(740, 580)

        self.root_frame = tk.Frame(self.root)
        self.root_frame.pack(fill='both', expand=True)

        self._build_title_bar()
        self._build_input_section()
        self._build_action_button()
        self._build_results_section()

    def _build_title_bar(self):
        """Top bar: app name left, subtitle centre-left, mode toggle right."""
        self.title_frame = tk.Frame(self.root_frame)
        self.title_frame.pack(fill='x', padx=16, pady=(14, 6))

        self.title_label = tk.Label(
            self.title_frame,
            text='Iffy Offer',
            font=('Helvetica', 22, 'bold'),
        )
        self.title_label.pack(side='left')

        self.subtitle_label = tk.Label(
            self.title_frame,
            text='Job Offer Email Legitimacy Checker',
            font=('Helvetica', 11),
        )
        self.subtitle_label.pack(side='left', padx=(10, 0), pady=(7, 0))

        self.mode_btn = tk.Button(
            self.title_frame,
            text='☀  Light Mode',
            font=('Helvetica', 10),
            relief='flat',
            cursor='hand2',
            padx=10,
            pady=4,
            command=self._toggle_mode,
        )
        self.mode_btn.pack(side='right', padx=4)

        # 1-px separator line below the title bar
        self.title_sep = tk.Frame(self.root_frame, height=1)
        self.title_sep.pack(fill='x', padx=16, pady=(0, 6))

    def _build_input_section(self):
        """Company name, email address, and optional raw header inputs."""
        self.input_frame = tk.LabelFrame(
            self.root_frame,
            text='  Email Details  ',
            font=('Helvetica', 10, 'bold'),
            padx=16,
            pady=12,
        )
        self.input_frame.pack(fill='x', padx=16, pady=6)

        # Row 0: Company name
        tk.Label(self.input_frame, text='Company Name:', font=('Helvetica', 10, 'bold')).grid(
            row=0, column=0, sticky='w', pady=6)
        self.company_var = tk.StringVar()
        self.company_entry = tk.Entry(
            self.input_frame, textvariable=self.company_var,
            font=('Helvetica', 11), width=50, relief='flat', bd=5,
        )
        self.company_entry.grid(row=0, column=1, sticky='ew', padx=(10, 0), pady=6)

        # Row 1: Sender email
        tk.Label(self.input_frame, text='Sender Email:', font=('Helvetica', 10, 'bold')).grid(
            row=1, column=0, sticky='w', pady=6)
        self.email_var = tk.StringVar()
        self.email_entry = tk.Entry(
            self.input_frame, textvariable=self.email_var,
            font=('Helvetica', 11), width=50, relief='flat', bd=5,
        )
        self.email_entry.grid(row=1, column=1, sticky='ew', padx=(10, 0), pady=6)

        # Row 2: Raw headers label + hint
        tk.Label(
            self.input_frame,
            text='Raw Headers (optional):',
            font=('Helvetica', 10, 'bold'),
        ).grid(row=2, column=0, sticky='nw', pady=(10, 2))

        tk.Label(
            self.input_frame,
            text='Paste the full header block from "Show Original" / "View Source" in your email client.',
            font=('Helvetica', 8),
            wraplength=440,
            justify='left',
        ).grid(row=2, column=1, sticky='w', padx=(10, 0), pady=(10, 2))

        # Row 3: Header text area
        self.header_text = scrolledtext.ScrolledText(
            self.input_frame,
            font=('Courier', 9),
            height=6,
            width=60,
            relief='flat',
            bd=2,
            wrap='none',
        )
        self.header_text.grid(row=3, column=0, columnspan=2, sticky='ew', pady=(0, 4))

        self.input_frame.columnconfigure(1, weight=1)

    def _build_action_button(self):
        """The Analyze button sits between inputs and results."""
        self.btn_frame = tk.Frame(self.root_frame)
        self.btn_frame.pack(fill='x', padx=16, pady=8)

        self.clear_btn = tk.Button(
            self.btn_frame,
            text='  Clear  ',
            font=('Helvetica', 13, 'bold'),
            relief='flat',
            cursor='hand2',
            padx=18,
            pady=10,
            command=self._clear_all,
        )
        self.clear_btn.pack(side='left', padx=(0, 8))

        self.analyze_btn = tk.Button(
            self.btn_frame,
            text='  Analyze Email  ',
            font=('Helvetica', 13, 'bold'),
            relief='flat',
            cursor='hand2',
            padx=24,
            pady=10,
            command=self._start_analysis,
        )
        self.analyze_btn.pack(side='left')

        self.status_label = tk.Label(
            self.btn_frame,
            text='',
            font=('Helvetica', 10, 'italic'),
        )
        self.status_label.pack(side='left', padx=14)

    def _build_results_section(self):
        """Scrollable results area and verdict panel at the bottom."""
        self.results_outer = tk.LabelFrame(
            self.root_frame,
            text='  Results  ',
            font=('Helvetica', 10, 'bold'),
            padx=8,
            pady=8,
        )
        self.results_outer.pack(fill='both', expand=True, padx=16, pady=(4, 0))

        self.canvas = tk.Canvas(self.results_outer, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.results_outer, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)

        self.results_inner = tk.Frame(self.canvas)
        self._canvas_window = self.canvas.create_window((0, 0), window=self.results_inner, anchor='nw')

        self.results_inner.bind('<Configure>', self._on_results_resize)
        self.canvas.bind('<Configure>', self._on_canvas_resize)

        self.canvas.bind_all('<MouseWheel>', self._on_mousewheel)
        self.canvas.bind_all('<Button-4>',   self._on_mousewheel)
        self.canvas.bind_all('<Button-5>',   self._on_mousewheel)

        self.placeholder = tk.Label(
            self.results_inner,
            text='Enter company name and email address above, then click Analyze.',
            font=('Helvetica', 10, 'italic'),
        )
        self.placeholder.pack(pady=24)

        # Verdict panel — hidden until analysis completes
        self.verdict_frame = tk.Frame(self.root_frame, height=66)
        self.verdict_frame.pack(fill='x', padx=16, pady=(0, 16))
        self.verdict_frame.pack_forget()

        self.verdict_label = tk.Label(
            self.verdict_frame,
            text='',
            font=('Helvetica', 18, 'bold'),
            pady=14,
        )
        self.verdict_label.pack(fill='x')

        self.disclaimer_label = tk.Label(
            self.root_frame,
            text='Heuristic tool — not 100% accurate. Always verify through official channels.',
            font=('Helvetica', 9, 'italic'),
            pady=3,
        )
        self.disclaimer_label.pack_forget()

    # ------------------------------------------------------------------
    # Analysis orchestration
    # ------------------------------------------------------------------

    def _clear_all(self):
        """Reset all input fields and the results panel."""
        self.company_var.set('')
        self.email_var.set('')
        self.header_text.delete('1.0', 'end')
        self._clear_results()
        self.verdict_frame.pack_forget()
        self.disclaimer_label.pack_forget()
        self._show_status('')
        p = self.palette
        self.placeholder = tk.Label(
            self.results_inner,
            text='Enter company name and email address above, then click Analyze.',
            font=('Helvetica', 10, 'italic'),
            bg=p['surface'],
            fg=p['text_dim'],
        )
        self.placeholder.pack(pady=24)

    def _start_analysis(self):
        """Validate inputs, disable the button, kick off the background worker."""
        company = self.company_var.get().strip()
        email   = self.email_var.get().strip()

        if not company:
            self._show_status('Please enter a company name.', error=True)
            return
        if not email:
            self._show_status('Please enter a sender email address.', error=True)
            return

        domain = extract_domain(email)
        if domain is None:
            self._show_status('Could not parse a domain from that email address.', error=True)
            return

        raw_headers = self.header_text.get('1.0', 'end').strip()

        self.analyze_btn.configure(state='disabled', text='  Analyzing…  ')
        self._show_status('Running checks (DNS and WHOIS may take a few seconds)…')
        self._clear_results()
        self.verdict_frame.pack_forget()
        self.disclaimer_label.pack_forget()

        thread = threading.Thread(
            target=self._run_analysis_worker,
            args=(company, email, domain, raw_headers),
            daemon=True,
        )
        thread.start()
        self.root.after(100, self._poll_result_queue)

    def _run_analysis_worker(self, company: str, email: str, domain: str, raw_headers: str):
        """Background thread — MUST NOT touch any Tkinter widgets."""
        try:
            free_prov   = is_free_provider(domain)
            ats_plat    = is_ats_platform(domain)
            domain_info = check_domain_vs_company(domain, company)
            whois_info  = get_domain_age(domain)
            mx_info     = check_mx_records(domain)
            spf_info    = check_spf_record(domain)
            dmarc_info  = check_dmarc_record(domain)

            display_mismatch  = None
            reply_to_mismatch = None
            if raw_headers:
                parsed            = parse_headers(raw_headers)
                display_mismatch  = check_display_name_mismatch(parsed, company)
                reply_to_mismatch = check_reply_to_mismatch(parsed)

            output = build_score(
                domain=domain,
                company_name=company,
                free_provider=free_prov,
                ats_platform=ats_plat,
                domain_info=domain_info,
                whois_info=whois_info,
                mx_info=mx_info,
                spf_info=spf_info,
                dmarc_info=dmarc_info,
                display_mismatch=display_mismatch,
                reply_to_mismatch=reply_to_mismatch,
            )
            self._result_queue.put(('ok', output))
        except Exception as e:
            self._result_queue.put(('error', str(e)))

    def _poll_result_queue(self):
        """Polls the queue on the main thread; updates the UI when done."""
        try:
            status, payload = self._result_queue.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll_result_queue)
            return

        self.analyze_btn.configure(state='normal', text='  Analyze Email  ')

        if status == 'error':
            self._show_status(f'Error during analysis: {payload}', error=True)
            return

        self._show_status('')
        self._display_results(payload)

    # ------------------------------------------------------------------
    # Results rendering
    # ------------------------------------------------------------------

    def _display_results(self, output):
        """Render the ScorerOutput as card rows in the scrollable panel."""
        self._clear_results()
        p = self.palette

        for result in output.results:
            icon  = STATUS_ICONS.get(result.status, '?')
            color = {
                'ok':      p['ok'],
                'warning': p['warning'],
                'fail':    p['fail'],
                'unknown': p['unknown'],
                'info':    p['text_dim'],
            }.get(result.status, p['text'])

            # Card row — surface2 bg gives a subtle lift off the canvas
            row = tk.Frame(self.results_inner, pady=6)
            row.pack(fill='x', padx=6, pady=(4, 0))
            row.configure(bg=p['surface2'])

            # Left accent stripe in the status colour
            stripe = tk.Frame(row, width=4, bg=color)
            stripe.pack(side='left', fill='y')
            stripe.pack_propagate(False)

            # Status icon
            tk.Label(
                row,
                text=icon,
                font=('Helvetica', 12, 'bold'),
                fg=color,
                bg=p['surface2'],
                width=2,
            ).pack(side='left', padx=(8, 2))

            # Check name
            tk.Label(
                row,
                text=result.name,
                font=('Helvetica', 10, 'bold'),
                fg=color,
                bg=p['surface2'],
                width=22,
                anchor='w',
            ).pack(side='left', padx=(0, 10))

            # Score delta (right-aligned, packed before detail so it anchors right)
            delta_text  = f'{result.delta:+d}' if result.delta != 0 else '—'
            delta_color = (p['ok'] if result.delta > 0
                           else p['fail'] if result.delta < 0
                           else p['text_dim'])
            tk.Label(
                row,
                text=delta_text,
                font=('Courier', 11, 'bold'),
                fg=delta_color,
                bg=p['surface2'],
                width=5,
                anchor='e',
            ).pack(side='right', padx=(0, 12))

            # Detail text — wraplength is updated dynamically in _on_canvas_resize
            detail_lbl = tk.Label(
                row,
                text=result.detail,
                font=('Helvetica', 9),
                fg=p['text_dim'],
                bg=p['surface2'],
                wraplength=500,
                justify='left',
                anchor='nw',
            )
            detail_lbl.pack(side='left', fill='x', expand=True, padx=(0, 6))
            self._detail_labels.append(detail_lbl)

        # Verdict banner
        verdict_colors = {
            'green':  p['verdict_low'],
            'yellow': p['verdict_med'],
            'red':    p['verdict_high'],
        }
        v_color = verdict_colors.get(output.color, p['text'])

        self.verdict_frame.configure(bg=v_color)
        self.verdict_label.configure(
            text=f'{output.verdict}   (score: {output.score:+d})',
            fg=p['btn_fg'] if self.mode == 'light' else p['bg'],
            bg=v_color,
        )
        self.verdict_frame.pack(fill='x', padx=16, pady=(0, 4))
        self.disclaimer_label.configure(bg=p['bg'], fg=p['disclaimer'])
        self.disclaimer_label.pack(fill='x', padx=16, pady=(0, 12))

    def _clear_results(self):
        """Remove all widgets from the results inner frame and reset label list."""
        self._detail_labels = []
        for widget in self.results_inner.winfo_children():
            widget.destroy()

    # ------------------------------------------------------------------
    # Theme management
    # ------------------------------------------------------------------

    def _toggle_mode(self):
        """Switch between dark and light palettes."""
        if self.mode == 'dark':
            self.mode    = 'light'
            self.palette = LIGHT_PALETTE
            self.mode_btn.configure(text='☾  Dark Mode')
        else:
            self.mode    = 'dark'
            self.palette = DARK_PALETTE
            self.mode_btn.configure(text='☀  Light Mode')
        self._apply_theme()

    def _apply_theme(self):
        """Re-apply the current palette to every widget."""
        p = self.palette

        self.root.configure(bg=p['bg'])
        self.root_frame.configure(bg=p['bg'])
        self.title_frame.configure(bg=p['bg'])
        self.title_sep.configure(bg=p['border'])
        self.btn_frame.configure(bg=p['bg'])

        self.title_label.configure(bg=p['bg'], fg=p['accent'])
        self.subtitle_label.configure(bg=p['bg'], fg=p['text_dim'])
        self.mode_btn.configure(bg=p['mode_btn_bg'], fg=p['mode_btn_fg'],
                                activebackground=p['border'], activeforeground=p['text'])

        self.input_frame.configure(bg=p['surface'], fg=p['text'])
        self.company_entry.configure(bg=p['surface2'], fg=p['text'], insertbackground=p['text'])
        self.email_entry.configure(bg=p['surface2'], fg=p['text'], insertbackground=p['text'])
        self.header_text.configure(bg=p['surface2'], fg=p['text'], insertbackground=p['text'])

        for widget in self.input_frame.winfo_children():
            if isinstance(widget, tk.Label):
                widget.configure(bg=p['surface'], fg=p['text_dim'])

        self.clear_btn.configure(bg=p['clear_btn_bg'], fg=p['clear_btn_fg'],
                                 activebackground=p['clear_btn_bg'],
                                 activeforeground=p['clear_btn_fg'])
        self.analyze_btn.configure(bg=p['btn_bg'], fg=p['btn_fg'],
                                   activebackground=p['accent_hover'],
                                   activeforeground=p['btn_fg'])
        self.status_label.configure(bg=p['bg'], fg=p['text_dim'])

        self.results_outer.configure(bg=p['surface'], fg=p['text'])
        self.canvas.configure(bg=p['surface'])
        self.results_inner.configure(bg=p['surface'])

        # Re-colour existing card rows (after a theme toggle mid-session).
        # Stripes are tk.Frame children — skip them to preserve status colours.
        for widget in self.results_inner.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.configure(bg=p['surface2'])
                for child in widget.winfo_children():
                    if isinstance(child, tk.Label):
                        child.configure(bg=p['surface2'])
                    # tk.Frame children are accent stripes — leave their bg alone

        if hasattr(self, 'placeholder') and self.placeholder.winfo_exists():
            self.placeholder.configure(bg=p['surface'], fg=p['text_dim'])

        if hasattr(self, 'disclaimer_label') and self.disclaimer_label.winfo_exists():
            self.disclaimer_label.configure(bg=p['bg'], fg=p['disclaimer'])

    # ------------------------------------------------------------------
    # Scroll helpers
    # ------------------------------------------------------------------

    def _on_results_resize(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))

    def _on_canvas_resize(self, event):
        """Keep the inner frame as wide as the canvas, and refresh wraplengths."""
        self.canvas.itemconfig(self._canvas_window, width=event.width)
        # Subtract stripe(4) + icon(~28) + name(~168) + delta(~60) + paddings(~50)
        wrap = max(80, event.width - 310)
        for lbl in self._detail_labels:
            if lbl.winfo_exists():
                lbl.configure(wraplength=wrap)

    def _on_mousewheel(self, event):
        if event.num == 4:
            self.canvas.yview_scroll(-1, 'units')
        elif event.num == 5:
            self.canvas.yview_scroll(1, 'units')
        else:
            self.canvas.yview_scroll(int(-event.delta / 60), 'units')

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _show_status(self, message: str, error: bool = False):
        color = self.palette['fail'] if error else self.palette['text_dim']
        self.status_label.configure(text=message, fg=color)

    def run(self):
        self.root.mainloop()
