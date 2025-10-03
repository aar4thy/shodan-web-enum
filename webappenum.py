#!/usr/bin/env python3
"""
web_enum.py

Shodan Web-App Enumerator (GUI) - simplified version WITHOUT favicon/JARM logic.

- No favicon or JARM computation or inputs.
- Builds anchored Shodan queries by category and runs them via the Shodan API.
- Export results to CSV/JSON.
"""

import os
import json
import time
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import shodan
import pandas as pd
from typing import List
import ipaddress
import re

# -------------------------
# Config
# -------------------------
PER_QUERY_LIMIT = 1000
DEFAULT_LIMIT_PER_QUERY = 200
GLOBAL_RESULTS_CAP = 2000

# -------------------------
# Utilities
# -------------------------
def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except Exception:
        return False

def shodan_escape(s: str) -> str:
    """
    Minimal escaping for Shodan query injection / weird chars.
    Remove double quotes and common control characters that may break queries.
    """
    if not isinstance(s, str):
        return ""
    sanitized = re.sub(r'["\n\r\t]', '', s).strip()
    return sanitized

# -------------------------
# Query builder
# -------------------------
def build_shodan_queries(target: str, categories: dict) -> List[str]:
    """
    Build a list of Shodan queries for the given target.
    categories: dict with boolean flags 'cms','admin','backups','dash','broad'
    """
    t_raw = target
    t = shodan_escape(t_raw)
    ip_target = is_ip(t)

    def hostname(x):
        return f'hostname:"{t}" AND ({x})'

    def ip_clause(x):
        return f'ip:"{t}" AND ({x})'

    queries = []

    # DOMAIN vs IP base queries
    if not ip_target:
        queries.append(f'hostname:"{t}"')
        queries.append(f'ssl.cert.subject.cn:"{t}" OR ssl.cert.alt_name:"{t}" OR ssl.cert.alt_name:"*.{t}"')
    else:
        queries.append(f'ip:"{t}"')

    # CMS
    if categories.get('cms'):
        if not ip_target:
            queries.append(hostname('product:"Drupal" OR product:"Joomla" OR product:"WordPress" OR http.html:"/user/login"'))
            queries.append(hostname('http.html:"wp-login.php" OR http.html:"/wp-admin" OR product:"WordPress" OR http.title:"WordPress"'))
            queries.append(hostname('http.html:"/administrator" OR product:"Joomla"'))
            queries.append(hostname('product:"Drupal" OR http.html:"/user/login"'))
        else:
            queries.append(ip_clause('http.html:"wp-login.php" OR http.html:"/administrator" OR http.html:"/user/login"'))

    # Admin panels / login UIs
    if categories.get('admin'):
        admin_clauses = [
            'http.title:"login"', 'http.html:"/login"', 'http.html:"/admin"', 'http.html:"/administrator"',
            'http.html:"/manager/html"', 'http.html:"/phpmyadmin"', 'http.title:"phpMyAdmin"', 'http.title:"cPanel"',
            'http.html:"/cpanel"', 'http.html:"/webmin"', 'http.title:"Webmin"', 'http.title:"Jenkins"', 'product:"Jenkins"',
            'product:"Grafana"', 'product:"Kibana"'
        ]
        clause = ' OR '.join(set(admin_clauses))
        queries.append(hostname(clause) if not ip_target else ip_clause(clause))
        queries.append(hostname('http.title:"Administration" AND -http.title:"Login" AND -http.title:"Error"') if not ip_target else ip_clause('http.title:"Administration" AND -http.title:"Login" AND -http.title:"Error"'))

    # Backups / VCS / dev files
    if categories.get('backups'):
        backup_clauses = [
            'http.html:".git"', 'http.html:".env"', 'http.html:"wp-config.php"', 'http.html:".htpasswd"',
            'http.html:".svn"', 'http.html:".backup"', 'http.html:".bak"', 'http.html:".old"', 'http.html:"/backup"',
            'http.html:"/staging"', 'http.html:"/test/"', 'http.html:"api_key="'
        ]
        clause = ' OR '.join(set(backup_clauses))
        queries.append(hostname(clause) if not ip_target else ip_clause(clause))

    # Dashboards / Management consoles
    if categories.get('dash'):
        dash_clauses = [
            'product:"Grafana" OR http.title:"Grafana" OR http.html:"/grafana"',
            'product:"Kibana" OR http.title:"Kibana" OR http.html:"/app/kibana"',
            'product:"Elasticsearch"',
            'product:"Prometheus" OR http.title:"Prometheus"',
            'product:"Jenkins" OR http.title:"Jenkins"'
        ]
        for c in dash_clauses:
            queries.append(hostname(c) if not ip_target else ip_clause(c))

    # Server fingerprinting / tech discovery
    tech_clauses = [
        'http.server:"Apache"', 'http.server:"nginx"', 'http.server:"Microsoft-IIS"', 'product:"IIS"',
        'product:"lighttpd"', 'product:"openresty"'
    ]
    tech_clause = ' OR '.join(set(tech_clauses))
    queries.append(f'hostname:"{t}" AND ({tech_clause})' if not ip_target else f'ip:"{t}" AND ({tech_clause})')

    # Useful checks (anchored)
    queries.append(hostname('http.html:"/admin/config.php" AND http.status:200') if not ip_target else ip_clause('http.html:"/admin/config.php" AND http.status:200'))
    queries.append(f'hostname:"{t}" AND ssl.cert.expired:true' if not ip_target else f'ip:"{t}" AND ssl.cert.expired:true')
    queries.append(f'hostname:"{t}" AND has_vuln:true' if not ip_target else f'ip:"{t}" AND has_vuln:true')
    queries.append(hostname('http.component:"jQuery" AND http.component_version:"1.7"') if not ip_target else ip_clause('http.component:"jQuery" AND http.component_version:"1.7"'))
    queries.append(hostname('http.html:"api_key="') if not ip_target else ip_clause('http.html:"api_key="'))

    # Broad options
    if categories.get('broad'):
        queries.append(f'ssl.cert.subject.cn:"{t}" OR ssl.cert.alt_name:"{t}" OR ssl.cert.alt_name:"*.{t}"')
        if len(t) >= 4:
            queries.append(f'"{t}"')

    # Deduplicate preserving order
    seen = set(); out = []
    for q in queries:
        if q not in seen:
            out.append(q); seen.add(q)
    return out

# -------------------------
# Flattening and candidate URL helpers
# -------------------------
def build_candidate_urls_from_banner(banner: dict) -> List[str]:
    urls = []
    port = banner.get("port") or 80
    try:
        port = int(port)
    except Exception:
        port = 80
    scheme = "https" if port in (443, 8443, 9443) else "http"
    hostnames = banner.get("hostnames") or []
    if hostnames:
        for h in hostnames[:2]:
            if port in (80, 443):
                urls.append(f"{scheme}://{h}")
            else:
                urls.append(f"{scheme}://{h}:{port}")
    ip = banner.get("ip_str") or banner.get("ip")
    if ip:
        if port in (80, 443):
            urls.append(f"{scheme}://{ip}")
        else:
            urls.append(f"{scheme}://{ip}:{port}")
    seen = set(); out = []
    for u in urls:
        if u not in seen:
            out.append(u); seen.add(u)
    return out

def flatten_banners(banners: List[dict]) -> pd.DataFrame:
    rows = []
    for b in banners:
        ip = b.get("ip_str") or b.get("ip") or ""
        port = b.get("port") or ""
        hostnames = b.get("hostnames") or []
        org = b.get("org") or ""
        isp = b.get("isp") or ""
        product = b.get("product") or (b.get("http") or {}).get("server") or ""
        version = b.get("version") or ""
        title = (b.get("http") or {}).get("title") or ""
        country = (b.get("location") or {}).get("country_name") or ""
        city = (b.get("location") or {}).get("city") or ""
        # CPEs
        cpe_val = b.get("cpe") or []
        if isinstance(cpe_val, list):
            cpes = ";".join([str(x) for x in cpe_val if x])
        else:
            cpes = str(cpe_val) if cpe_val else ""
        # CVEs from Shodan 'vulns' (dict keys)
        vulns = b.get("vulns") or {}
        if isinstance(vulns, dict):
            cves = ";".join(sorted(vulns.keys()))
        elif isinstance(vulns, list):
            cves = ";".join([str(x) for x in vulns])
        else:
            cves = ""
        # TLS cert CNs/SANs if present in banner
        cert_cn = ""
        cert_sans = ""
        sslobj = b.get("ssl") or {}
        try:
            cert = sslobj.get("cert") or {}
            subj = cert.get("subject")
            if isinstance(subj, dict):
                cert_cn = subj.get("CN") or subj.get("cn") or ""
            elif isinstance(subj, (list, tuple)):
                for item in subj:
                    if isinstance(item, (list, tuple)) and len(item) >= 2:
                        if str(item[0]).lower() in ("cn", "commonname", "common_name"):
                            cert_cn = item[1]; break
            ext = cert.get("extensions") or {}
            san_field = ext.get("subjectAltName") or ext.get("alt_names")
            sans = []
            if isinstance(san_field, list):
                sans = san_field
            elif isinstance(san_field, str):
                for part in san_field.split(","):
                    part = part.strip()
                    if part.lower().startswith("dns:"):
                        sans.append(part.partition(":")[2])
            alt_names = sslobj.get("alt_names") or []
            if isinstance(alt_names, list):
                sans.extend(alt_names)
            cert_sans = ";".join(sorted(set([s for s in sans if s])))
        except Exception:
            cert_cn = cert_cn or ""
            cert_sans = cert_sans or ""
        candidate_urls = ";".join(build_candidate_urls_from_banner(b))
        rows.append({
            "IP": ip,
            "Port": port,
            "Hostnames": ";".join(hostnames) if hostnames else "",
            "Org": org,
            "ISP": isp,
            "Product": product,
            "Version": version,
            "HTTP_Title": title,
            "Country": country,
            "City": city,
            "CPEs": cpes,
            "CVEs": cves,
            "Cert_CN": cert_cn,
            "Cert_SANs": cert_sans,
            "Candidate_URLs": candidate_urls,
            "raw_banner": b
        })
    df = pd.DataFrame(rows, columns=[
        "IP","Port","Hostnames","Org","ISP","Product","Version","HTTP_Title",
        "Country","City","CPEs","CVEs","Cert_CN","Cert_SANs","Candidate_URLs","raw_banner"
    ])
    df["raw_banner"] = df["raw_banner"].apply(lambda x: x if isinstance(x, str) else json.dumps(x, default=str, ensure_ascii=False))
    return df

# -------------------------
# Shodan query runner
# -------------------------
def run_shodan_queries(api_key: str, target: str, queries: List[str], per_query_limit: int, status_callback, progress_callback, stop_event: threading.Event = None):
    """
    Executes a set of queries (queries are fully formed strings).
    Returns list of banner dicts (deduplicated by ip:port).
    stop_event: threading.Event used to request cancellation from UI.
    """
    try:
        client = shodan.Shodan(api_key)
    except Exception as e:
        status_callback(f"Failed to init Shodan client: {e}")
        return None

    all_banners = []
    global_count = 0
    for idx, q in enumerate(queries, start=1):
        if stop_event and stop_event.is_set():
            status_callback("Stop requested; exiting before next query.")
            break
        formatted = q
        status_callback(f"[{idx}/{len(queries)}] Running: {formatted}")
        try:
            # Try to get count (best-effort)
            try:
                cnt = client.count(formatted).get("total", None)
            except Exception:
                cnt = None
            if cnt:
                status_callback(f" Shodan reports ~{cnt} matches for this combined query.")
            retrieved = 0
            retries = 0
            for banner in client.search_cursor(formatted):
                if stop_event and stop_event.is_set():
                    status_callback("Stop requested; finishing current query loop.")
                    break
                all_banners.append(banner)
                retrieved += 1
                global_count += 1
                if progress_callback:
                    try:
                        progress_callback(retrieved, cnt or per_query_limit)
                    except Exception:
                        pass
                # safety cap per query
                if retrieved >= per_query_limit:
                    status_callback(f" Reached per-query cap ({per_query_limit}), stopping this query early.")
                    break
                # global cap
                if GLOBAL_RESULTS_CAP and global_count >= GLOBAL_RESULTS_CAP:
                    status_callback(f"Reached global cap ({GLOBAL_RESULTS_CAP}), stopping all queries.")
                    break
            status_callback(f" Collected {retrieved} banners for this query.")
            if GLOBAL_RESULTS_CAP and global_count >= GLOBAL_RESULTS_CAP:
                break
        except shodan.APIError as e:
            status_callback(f" Shodan API error for query '{formatted}': {e}")
            # simple backoff for rate limiting
            if 'rate' in str(e).lower() or '429' in str(e):
                wait = min(60, (2 ** retries) * 1)
                status_callback(f" Rate limit detected — sleeping {wait}s then retrying query.")
                time.sleep(wait)
                retries += 1
                if retries < 4:
                    continue
        except Exception as e:
            status_callback(f" Error running query '{formatted}': {e}")
    # deduplicate by ip:port
    dedup = {}
    for b in all_banners:
        key = f"{b.get('ip_str') or b.get('ip','')}:{b.get('port','')}"
        if key not in dedup:
            dedup[key] = b
    return list(dedup.values())

# -------------------------
# Tkinter GUI
# -------------------------
class AppGUI:
    def __init__(self, root):
        self.root = root
        root.title("Shodan Web-App Enumerator (single-target)")
        root.geometry("1150x760")

        top = tk.Frame(root, padx=8, pady=6)
        top.pack(fill="x")

        tk.Label(top, text="Target (domain or IP):").grid(row=0, column=0, sticky="w")
        self.target_entry = tk.Entry(top, width=50)
        self.target_entry.grid(row=0, column=1, padx=6, sticky="w")

        tk.Label(top, text="Shodan API Key (or set SHODAN_API_KEY env):").grid(row=1, column=0, sticky="w", pady=(6,0))
        self.api_entry = tk.Entry(top, width=50, show="*")
        self.api_entry.grid(row=1, column=1, padx=6, sticky="w", pady=(6,0))

        tk.Label(top, text="Per-query cap (safety):").grid(row=0, column=2, sticky="w")
        self.cap_var = tk.IntVar(value=DEFAULT_LIMIT_PER_QUERY)
        self.cap_entry = tk.Entry(top, textvariable=self.cap_var, width=8)
        self.cap_entry.grid(row=0, column=3, padx=6, sticky="w")

        tk.Label(top, text="(max results per query)").grid(row=1, column=2, sticky="w")

        cat_frame = tk.LabelFrame(root, text="Query categories (toggle)")
        cat_frame.pack(fill="x", padx=8, pady=6)
        self.cat_vars = {
            'cms': tk.BooleanVar(value=True),
            'admin': tk.BooleanVar(value=True),
            'backups': tk.BooleanVar(value=True),
            'dash': tk.BooleanVar(value=True),
            'broad': tk.BooleanVar(value=False),
        }
        tk.Checkbutton(cat_frame, text="CMS (WordPress/Joomla/Drupal)", variable=self.cat_vars['cms']).pack(side="left", padx=6)
        tk.Checkbutton(cat_frame, text="Admin Panels / Login UIs", variable=self.cat_vars['admin']).pack(side="left", padx=6)
        tk.Checkbutton(cat_frame, text="Backups / VCS / Dev files", variable=self.cat_vars['backups']).pack(side="left", padx=6)
        tk.Checkbutton(cat_frame, text="Dashboards / Management", variable=self.cat_vars['dash']).pack(side="left", padx=6)
        tk.Checkbutton(cat_frame, text="Broad / Looser queries (noisy)", variable=self.cat_vars['broad']).pack(side="left", padx=6)

        btn_frame = tk.Frame(top)
        btn_frame.grid(row=0, column=6, rowspan=2, padx=8)
        self.preview_button = tk.Button(btn_frame, text="Preview Queries", command=self.preview_queries)
        self.preview_button.pack(fill="x", pady=2)
        self.run_button = tk.Button(btn_frame, text="Run Enumeration", bg="green", fg="white", command=self.start_run)
        self.run_button.pack(fill="x", pady=2)

        self.cancel_button = tk.Button(top, text="Cancel", bg="red", fg="white", command=self.cancel_run, state="disabled")
        self.cancel_button.grid(row=0, column=7, rowspan=2, padx=8)

        progress_frame = tk.Frame(root)
        progress_frame.pack(fill="x", padx=8, pady=6)
        self.progress = ttk.Progressbar(progress_frame, orient="horizontal", length=500, mode="determinate")
        self.progress.pack(side="left", padx=6)
        self.progress_label = tk.Label(progress_frame, text="Idle")
        self.progress_label.pack(side="left", padx=6)
        self.count_label = tk.Label(progress_frame, text="")
        self.count_label.pack(side="left", padx=6)

        cols = ("IP","Port","Hostnames","Org","Product","Version","HTTP_Title","CPEs","CVEs","Cert_CN","Cert_SANs","Candidate_URLs")
        self.tree = ttk.Treeview(root, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
            width = 100 if c!="Candidate_URLs" else 380
            self.tree.column(c, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=6)

        bottom = tk.Frame(root, padx=8, pady=6)
        bottom.pack(fill="x")
        tk.Button(bottom, text="Export CSV", command=self.export_csv).pack(side="right", padx=6)
        tk.Button(bottom, text="Export JSON (raw)", command=self.export_json).pack(side="right", padx=6)

        self.log = scrolledtext.ScrolledText(root, height=8, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=False, padx=8, pady=6)

        self._thread = None
        self._stop_event = threading.Event()
        self._banners = []
        self._df = pd.DataFrame()

    def log_msg(self, msg: str):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.log.config(state="normal")
            self.log.insert("end", f"[{ts}] {msg}\n")
            self.log.see("end")
            self.log.config(state="disabled")
        except Exception:
            print(f"[{ts}] {msg}")

    def preview_queries(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Missing target", "Please enter a domain name or IP address to build preview queries.")
            return
        categories = {k: v.get() for k, v in self.cat_vars.items()}
        queries = build_shodan_queries(target, categories)
        self.log_msg("Previewing queries (not executed):")
        for i, q in enumerate(queries, start=1):
            self.log_msg(f"[{i}] {q}")
        messagebox.showinfo("Preview", f"Built {len(queries)} queries — see log for full list.")

    def start_run(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Missing target", "Please enter a domain name or IP address to enumerate.")
            return
        api_key = self.api_entry.get().strip() or os.getenv("SHODAN_API_KEY", "").strip()
        if not api_key:
            messagebox.showerror("Missing API key", "Please enter a Shodan API key or set SHODAN_API_KEY environment variable.")
            return
        try:
            cap = int(self.cap_var.get())
            if cap <= 0 or cap > PER_QUERY_LIMIT:
                raise ValueError()
        except Exception:
            messagebox.showerror("Invalid cap", f"Per-query cap must be a positive integer (<= {PER_QUERY_LIMIT}).")
            return

        categories = {k: v.get() for k, v in self.cat_vars.items()}

        queries = build_shodan_queries(target, categories)

        self.root.after(0, lambda: self.run_button.config(state="disabled"))
        self.root.after(0, lambda: self.cancel_button.config(state="normal"))
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.log_msg(f"Starting enumeration for {target} ... Categories={categories}")
        self._banners = []
        self._df = pd.DataFrame()
        self.progress['value'] = 0
        self.progress['maximum'] = 1
        self.progress_label.config(text="Starting")
        self.count_label.config(text="")

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker, args=(api_key, target, queries, cap), daemon=True)
        self._thread.start()

    def cancel_run(self):
        self._stop_event.set()
        self.log_msg("Stop requested; will finish current iteration then exit.")
        self.root.after(0, lambda: self.cancel_button.config(state="disabled"))

    def _update_progress(self, current, total_estimate):
        def ui_update():
            total = total_estimate or self.cap_var.get()
            self.progress['maximum'] = max(1, total)
            self.progress['value'] = min(current, total)
            self.progress_label.config(text=f"Fetched {current} / {total}")
            self.count_label.config(text=f"Collected (so far): {len(self._banners)} unique")
        self.root.after(1, ui_update)

    def _worker(self, api_key, target, queries, cap):
        try:
            banners = run_shodan_queries(api_key, target, queries, cap, status_callback=self.log_msg, progress_callback=self._update_progress, stop_event=self._stop_event)
            if banners is None:
                self.log_msg("No banners returned or error occurred. See logs.")
                self.root.after(0, lambda: self.run_button.config(state="normal"))
                self.root.after(0, lambda: self.cancel_button.config(state="disabled"))
                return
            self._banners = banners
            self.log_msg(f"Total unique banners collected: {len(banners)}")
            self._df = flatten_banners(banners)
            def ui_populate():
                for _, row in self._df.iterrows():
                    vals = (
                        row.get("IP",""),
                        row.get("Port",""),
                        row.get("Hostnames",""),
                        row.get("Org",""),
                        row.get("Product",""),
                        row.get("Version",""),
                        row.get("HTTP_Title",""),
                        row.get("CPEs",""),
                        row.get("CVEs",""),
                        row.get("Cert_CN",""),
                        row.get("Cert_SANs",""),
                        row.get("Candidate_URLs","")
                    )
                    self.tree.insert("", "end", values=vals)
                self.progress['value'] = 0
                self.progress_label.config(text="Completed")
                self.count_label.config(text=f"Total unique: {len(self._banners)}")
                self.root.after(0, lambda: self.cancel_button.config(state="disabled"))
            self.root.after(1, ui_populate)
            self.log_msg("Flattening complete. You can export CSV/JSON now.")
        except Exception as e:
            self.log_msg(f"Worker error: {e}")
        finally:
            self.root.after(0, lambda: self.run_button.config(state="normal"))
            self.root.after(0, lambda: self.cancel_button.config(state="disabled"))

    def export_csv(self):
        if self._df is None or self._df.empty:
            messagebox.showwarning("No data", "No results to export. Run enumeration first.")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=f"shodan_{int(time.time())}.csv", filetypes=[("CSV files","*.csv")])
        if not save_path:
            return
        try:
            df_out = self._df.copy()
            df_out.to_csv(save_path, index=False, encoding="utf-8")
            self.log_msg(f"CSV exported: {save_path}")
            messagebox.showinfo("Saved", f"CSV saved to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Export error", f"Failed to write CSV: {e}")

    def export_json(self):
        if not self._banners:
            messagebox.showwarning("No data", "No results to export. Run enumeration first.")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=f"shodan_raw_{int(time.time())}.json", filetypes=[("JSON files","*.json")])
        if not save_path:
            return
        try:
            with open(save_path, "w", encoding="utf-8") as jf:
                json.dump(self._banners, jf, indent=2, ensure_ascii=False, default=str)
            self.log_msg(f"Raw JSON exported: {save_path}")
            messagebox.showinfo("Saved", f"JSON saved to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Export error", f"Failed to write JSON: {e}")

# -------------------------
# Run the app
# -------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = AppGUI(root)
    root.mainloop()
