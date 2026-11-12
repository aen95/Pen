#!/usr/bin/env python3
"""
Internal web form for the External Cyber Posture Review.

Colleagues open a page, enter a prospect's domain and company name, and get the
branded report back in the browser. Needs only Python 3.8+ and external_posture_review.py
in the same folder. No third-party packages.

THIS IS AN INTERNAL TOOL. Do not expose it to the public internet. A scanner with an open
front door lets anyone launch scans from HUB's network address.

Built-in protections
  * Login required (per-user scrypt-hashed passwords, or SSO via a reverse-proxy header)
  * Targets that resolve to private, loopback, or internal addresses are refused,
    including on every redirect (prevents the tool being used to probe HUB's own network)
  * Per-user hourly limit, a cap on simultaneous scans, and a cool-down per domain
  * CSRF check on the form post, strict security headers on every page
  * Audit log (who scanned which domain, when, with what result)

Quick start
  python3 posture_web.py --no-auth --logo hub_logo.png     # just you, on your own computer, no login
  python3 posture_web.py --add-user aaron            # or: shared use, creates users.txt (repeat per colleague)
  python3 posture_web.py --logo hub_logo.png --contact aaron.nelson@hubinternational.com
  then open http://127.0.0.1:8080

For use by other people, serve it over HTTPS: either --cert/--key here, or (better) run it on
127.0.0.1 behind your normal reverse proxy / App Gateway with SSO, using --auth-header.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import external_posture_review as epr

esc = lambda s: html.escape(str(s), quote=True)

CFG = SimpleNamespace()
JOBS: dict[str, dict] = {}
RATE: dict[str, list[float]] = {}
LAST_DOMAIN: dict[str, tuple[float, str, str]] = {}
AUTH_FAILS: dict[str, list[float]] = {}
LOCK = threading.Lock()
AUDIT_LOCK = threading.Lock()
SEM: threading.Semaphore
BAD_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home", ".localdomain", ".intranet", ".test", ".invalid")
JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")


# ------------------------------------------------------------------ passwords
def hash_pw(pw: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${dk.hex()}"


def check_pw(pw: str, stored: str) -> bool:
    try:
        _, salt, dk = stored.split("$")
        test = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(test.hex(), dk)
    except Exception:
        return False


def load_users() -> dict[str, str]:
    users = {}
    try:
        with open(CFG.users_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and ":" in line:
                    u, h = line.split(":", 1)
                    users[u] = h
    except FileNotFoundError:
        pass
    return users


def add_user(name: str, path: str):
    if not re.fullmatch(r"[A-Za-z0-9._@-]{2,64}", name):
        sys.exit("Usernames may contain letters, digits and . _ @ - only.")
    pw = getpass.getpass("Password (12+ characters): ")
    if len(pw) < 12:
        sys.exit("Use at least 12 characters.")
    if pw != getpass.getpass("Repeat password: "):
        sys.exit("Passwords did not match.")
    lines = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            lines = [ln.rstrip("\n") for ln in fh if not ln.startswith(name + ":")]
    lines.append(f"{name}:{hash_pw(pw)}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"User '{name}' saved to {path}")


# ------------------------------------------------------------------ audit
def audit(**rec):
    rec["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with AUDIT_LOCK:
        with open(CFG.audit_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")


# ------------------------------------------------------------------ jobs
def prune(now: float):
    ttl = CFG.ttl_hours * 3600
    for jid in [j for j, v in JOBS.items() if now - v["created"] > ttl]:
        del JOBS[jid]


def run_job(job_id: str):
    job = JOBS[job_id]
    with SEM:
        job["status"] = "running"
        try:
            args = SimpleNamespace(contact=CFG.contact, timeout=10.0, delay=0.5, http_port=CFG.http_port,
                                   https_port=CFG.https_port, skip_dns=CFG.skip_dns, no_ct=job["no_ct"],
                                   block_private=not CFG.allow_private)
            sc = epr.Scanner(job["domain"], args)
            sc.on_step = lambda m: job["steps"].append(m)
            sc.run()
            score, grade = sc.score()
            job["report"] = epr.render_html(sc, job["prospect"], job["producer"], CFG.logo_b64, CFG.logo_mime)
            job["score"], job["grade"] = score, grade
            job["status"] = "done"
            audit(user=job["user"], ip=job["ip"], domain=job["domain"], prospect=job["prospect"],
                  outcome="done", score=score, grade=grade)
        except epr.BlockedTarget as e:
            job["status"], job["error"] = "error", str(e)
            audit(user=job["user"], ip=job["ip"], domain=job["domain"], outcome="blocked", detail=str(e))
        except Exception as e:  # noqa
            job["status"], job["error"] = "error", "The review could not be completed. Check the domain and try again."
            audit(user=job["user"], ip=job["ip"], domain=job["domain"], outcome="error", detail=type(e).__name__)


# ------------------------------------------------------------------ pages
CSS = """
:root{--ink:#10243f;--muted:#56667a;--line:#d9e0ea;--panel:#f4f7fb;--accent:#1f64c4;
--serif:Charter,"Iowan Old Style","Palatino Linotype",Georgia,serif;
--sans:"Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif}
*{box-sizing:border-box}body{margin:0;color:var(--ink);background:#fff;font:15px/1.55 var(--sans)}
.wrap{max-width:720px;margin:0 auto;padding:32px 24px 64px}
.top{display:flex;justify-content:space-between;align-items:center;border-bottom:3px solid var(--ink);padding-bottom:14px}
.top img{height:40px}.top b{font-size:19px}.top span{color:var(--muted);font-size:13px}
h1{font:600 32px/1.15 var(--serif);margin:30px 0 6px}h2{font:600 20px var(--serif);margin:36px 0 10px}
.sub{color:var(--muted);margin:0 0 24px}
label{display:block;font-weight:600;margin:16px 0 0}
input[type=text]{display:block;width:100%;margin-top:5px;padding:10px 12px;font:inherit;border:1px solid #aab6c6;border-radius:4px;color:var(--ink)}
input[type=text]:focus-visible,button:focus-visible,a:focus-visible{outline:3px solid var(--accent);outline-offset:1px}
.hint{display:block;font-weight:400;color:var(--muted);font-size:13px;margin-top:2px}
.check{display:flex;gap:10px;align-items:flex-start;font-weight:400;margin-top:16px}.check input{margin-top:4px}
button{margin-top:22px;background:var(--ink);color:#fff;border:0;border-radius:4px;padding:11px 22px;font:600 15px var(--sans);cursor:pointer}
button:hover{background:#1b3a63}
.err{background:#fdf2f2;border-left:4px solid #9b1c1c;padding:10px 14px;margin:18px 0 0}
.scope{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 18px;color:var(--muted);font-size:13.5px;margin-top:30px}
.scope p{margin:6px 0}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);font-size:14px}
th{color:var(--muted);font-weight:500}a{color:var(--accent)}
ol.steps{padding-left:0;list-style:none;margin:20px 0}ol.steps li{padding:8px 0 8px 28px;position:relative;border-bottom:1px solid var(--line)}
ol.steps li::before{content:"";position:absolute;left:4px;top:15px;width:10px;height:10px;border-radius:50%;background:#2f7d4f}
ol.steps li.now::before{background:var(--accent);animation:pulse 1s ease-in-out infinite alternate}
@keyframes pulse{from{opacity:.3}to{opacity:1}}@media (prefers-reduced-motion:reduce){ol.steps li.now::before{animation:none}}
"""


def layout(title: str, body: str, nonce: str, script: str = "") -> str:
    brand = (f'<img alt="HUB International" src="data:{CFG.logo_mime};base64,{CFG.logo_b64}">'
             if CFG.logo_b64 else "<b>HUB International</b>")
    sc = f'<script nonce="{nonce}">{script}</script>' if script else ""
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>'
            f'<style>{CSS}</style></head><body><div class="wrap">'
            f'<div class="top">{brand}<span>Forestry and Wood Products practice</span></div>{body}</div>{sc}</body></html>')


def home_page(user: str, nonce: str, error: str = "", values: dict | None = None) -> str:
    v = values or {}
    rows = ""
    mine = sorted((j for j in JOBS.items() if j[1]["user"] == user), key=lambda kv: -kv[1]["created"])[:15]
    for jid, j in mine:
        when = time.strftime("%b %d, %H:%M", time.localtime(j["created"]))
        if j["status"] == "done":
            links = (f'<a href="/report/{jid}">Open</a> &nbsp; <a href="/report/{jid}?download=1">Download</a>')
            res = f'{esc(j["grade"])} ({j["score"]})'
        elif j["status"] == "error":
            links, res = "Failed", "&ndash;"
        else:
            links, res = f'<a href="/job/{jid}">In progress</a>', "&ndash;"
        rows += (f'<tr><td>{esc(j["prospect"])}<br><span style="color:var(--muted)">{esc(j["domain"])}</span></td>'
                 f'<td>{when}</td><td>{res}</td><td>{links}</td></tr>')
    recent = (f'<h2>Your recent reviews</h2><table><tr><th>Prospect</th><th>Run</th><th>Grade</th><th></th></tr>{rows}</table>'
              f'<p class="hint">Reports are kept for {CFG.ttl_hours} hours. Download any you want to keep.</p>') if rows else ""
    err = f'<div class="err" role="alert">{esc(error)}</div>' if error else ""
    body = f"""<h1>External Cyber Posture Review</h1>
<p class="sub">Enter a prospect's website domain to produce a client-ready report on its publicly visible security posture. It takes about a minute.</p>
{err}
<form method="post" action="/scan" autocomplete="off">
<label for="domain">Website domain<span class="hint">For example: examplelumber.com</span></label>
<input type="text" id="domain" name="domain" required maxlength="253" value="{esc(v.get('domain', ''))}" autofocus>
<label for="prospect">Company name<span class="hint">Shown on the report.</span></label>
<input type="text" id="prospect" name="prospect" required maxlength="120" value="{esc(v.get('prospect', ''))}">
<label for="producer">Prepared by</label>
<input type="text" id="producer" name="producer" maxlength="80" value="{esc(v.get('producer', CFG.default_producer))}">
<label class="check"><input type="checkbox" name="confirm" required> I am reviewing a prospect or client of HUB, and I understand this tool looks only at public information.</label>
<label class="check"><input type="checkbox" name="no_ct"> Skip the public certificate-log lookup (faster, but leaves out the hostname list)</label>
<button type="submit">Run review</button>
</form>
<div class="scope"><p>The review makes ordinary public requests only: a few page loads, one secure-connection check, and public DNS lookups. It never attempts to log in, guess pages, scan ports, or exploit anything.</p>
<p>It reviews only what is visible from outside. It is not a penetration test. Every review is logged with your username.</p></div>
{recent}"""
    script = ("try{var p=document.getElementById('producer');var k='posture_producer';"
              "if(!p.value&&localStorage.getItem(k))p.value=localStorage.getItem(k);"
              "document.querySelector('form').addEventListener('submit',function(){localStorage.setItem(k,p.value)})}catch(e){}")
    return layout("External Cyber Posture Review", body, nonce, script)


def progress_page(job_id: str, job: dict, nonce: str) -> str:
    body = f"""<h1>Running review</h1>
<p class="sub">{esc(job['prospect'])} &mdash; {esc(job['domain'])}</p>
<ol class="steps" id="steps" aria-live="polite"><li class="now">Starting</li></ol>
<div id="err" class="err" role="alert" hidden></div>
<p id="back" hidden><a href="/">Back to the form</a></p>"""
    script = f"""var id={json.dumps(job_id)};
function show(j){{var ol=document.getElementById('steps');ol.textContent='';
var s=j.steps.length?j.steps:[j.status==='queued'?'Waiting for a free slot':'Starting'];
s.forEach(function(t,i){{var li=document.createElement('li');li.textContent=t;
if(i===s.length-1&&j.status!=='done'&&j.status!=='error')li.className='now';ol.appendChild(li)}})}}
function poll(){{fetch('/api/job/'+id,{{credentials:'same-origin'}}).then(function(r){{return r.json()}}).then(function(j){{
show(j);
if(j.status==='done'){{location.href='/report/'+id}}
else if(j.status==='error'){{var e=document.getElementById('err');e.textContent=j.error;e.hidden=false;document.getElementById('back').hidden=false}}
else setTimeout(poll,1500)}}).catch(function(){{setTimeout(poll,3000)}})}}
poll();"""
    return layout("Running review", body, nonce, script)


# ------------------------------------------------------------------ handler
class Handler(BaseHTTPRequestHandler):
    server_version = "PostureReview"
    sys_version = ""

    def setup(self):
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(10)
            self.request.do_handshake()
        super().setup()

    def log_message(self, *a):  # audit log is the record; keep stdout quiet
        pass

    # --- helpers
    def client_ip(self):
        if CFG.auth_header:
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0]

    def send(self, code, body, ctype="text/html; charset=utf-8", nonce=None, extra=None, report=False):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if report:
            csp = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; base-uri 'none'"
        else:
            csp = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; form-action 'self'; "
                   f"frame-ancestors 'none'; base-uri 'none'" + (f"; script-src 'nonce-{nonce}'" if nonce else ""))
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if CFG.tls:
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, loc):
        self.send_response(303)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def authenticate(self):
        if CFG.no_auth:
            return "local"
        if CFG.auth_header:
            u = (self.headers.get(CFG.auth_header) or "").strip()
            return u[:128] or None
        ip = self.client_ip()
        now = time.time()
        with LOCK:
            AUTH_FAILS[ip] = [t for t in AUTH_FAILS.get(ip, []) if now - t < 600]
            if len(AUTH_FAILS[ip]) >= 10:
                return "LOCKED"
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(h[6:]).decode("utf-8").partition(":")
                stored = load_users().get(user)
                if stored and check_pw(pw, stored):
                    return user
                if not stored:
                    check_pw(pw, "scrypt$00$00")  # keep timing similar
            except Exception:
                pass
            with LOCK:
                AUTH_FAILS.setdefault(ip, []).append(now)
        return None

    def require_auth(self):
        user = self.authenticate()
        if user == "LOCKED":
            self.send(429, "Too many failed sign-ins. Try again in ten minutes.", "text/plain; charset=utf-8")
            return None
        if not user:
            self.send(401, "Sign-in required.", "text/plain; charset=utf-8",
                      extra={"WWW-Authenticate": 'Basic realm="Posture Review", charset="UTF-8"'})
            return None
        return user

    def same_origin(self):
        src = self.headers.get("Origin") or self.headers.get("Referer")
        if not src:
            return False
        host = urllib.parse.urlsplit(src).netloc
        allowed = {self.headers.get("Host"), self.headers.get("X-Forwarded-Host")} - {None}
        return host in allowed

    def own_job(self, jid, user):
        job = JOBS.get(jid) if JOB_ID_RE.match(jid or "") else None
        return job if job and job["user"] == user else None

    # --- routes
    def do_GET(self):
        path = urllib.parse.urlsplit(self.path)
        if path.path == "/healthz":
            return self.send(200, "ok", "text/plain; charset=utf-8")
        user = self.require_auth()
        if not user:
            return
        p = path.path
        nonce = secrets.token_urlsafe(16)
        if p == "/":
            with LOCK:
                prune(time.time())
                return self.send(200, home_page(user, nonce), nonce=nonce)
        if p.startswith("/job/"):
            job = self.own_job(p[5:], user)
            return self.send(200, progress_page(p[5:], job, nonce), nonce=nonce) if job else self.send(404, "Not found", "text/plain")
        if p.startswith("/api/job/"):
            job = self.own_job(p[9:], user)
            if not job:
                return self.send(404, "{}", "application/json")
            return self.send(200, json.dumps({"status": job["status"], "steps": job["steps"], "error": job.get("error", "")}),
                             "application/json")
        if p.startswith("/report/"):
            job = self.own_job(p[8:], user)
            if not job or job["status"] != "done":
                return self.send(404, "Not found", "text/plain")
            extra = {}
            if "download=1" in (path.query or ""):
                extra["Content-Disposition"] = f'attachment; filename="posture_review_{job["domain"]}.html"'
            return self.send(200, job["report"], report=True, extra=extra)
        self.send(404, "Not found", "text/plain")

    def do_POST(self):
        user = self.require_auth()
        if not user:
            return
        if urllib.parse.urlsplit(self.path).path != "/scan":
            return self.send(404, "Not found", "text/plain")
        if not self.same_origin():
            return self.send(403, "Cross-site request refused.", "text/plain")
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n <= 0 or n > 10_000:
            return self.send(400, "Bad request", "text/plain")
        form = {k: v[0].strip() for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace")).items()}
        nonce = secrets.token_urlsafe(16)

        def fail(msg, code=400):
            self.send(code, home_page(user, nonce, msg, form), nonce=nonce)

        if not form.get("confirm"):
            return fail("Please confirm the statement at the bottom of the form.")
        prospect = re.sub(r"[\x00-\x1f]", "", form.get("prospect", ""))[:120]
        producer = re.sub(r"[\x00-\x1f]", "", form.get("producer", ""))[:80]
        if not prospect:
            return fail("Enter the company name.")
        try:
            domain = epr.normalize_domain(form.get("domain", ""))
        except SystemExit as e:
            return fail(str(e.code) if isinstance(e.code, str) else "Enter a valid domain, such as examplelumber.com.")
        if not CFG.allow_private and ("." not in domain or domain.endswith(BAD_SUFFIXES)):
            return fail("Enter a public website domain, such as examplelumber.com.")
        if not CFG.allow_private:
            for h in (domain, "www." + domain):
                try:
                    epr.assert_public_host(h)
                except epr.BlockedTarget:
                    audit(user=user, ip=self.client_ip(), domain=domain, outcome="blocked-at-form")
                    return fail("That domain points to a non-public address, so it can't be reviewed.")
                except OSError:
                    continue

        now = time.time()
        with LOCK:
            prune(now)
            recent = [t for t in RATE.get(user, []) if now - t < 3600]
            if len(recent) >= CFG.max_per_hour:
                return fail(f"Limit reached: {CFG.max_per_hour} reviews per hour. Try again later.", 429)
            last = LAST_DOMAIN.get(domain)
            if last and now - last[0] < 600 and JOBS.get(last[1], {}).get("status") != "error":
                if last[2] == user:
                    return self.redirect(f"/job/{last[1]}")
                return fail("That domain was reviewed a few minutes ago. Please wait before running it again.", 429)
            jid = secrets.token_urlsafe(24)
            JOBS[jid] = {"user": user, "ip": self.client_ip(), "domain": domain, "prospect": prospect, "producer": producer,
                         "no_ct": bool(form.get("no_ct")), "status": "queued", "steps": [], "created": now}
            RATE[user] = recent + [now]
            LAST_DOMAIN[domain] = (now, jid, user)
        audit(user=user, ip=self.client_ip(), domain=domain, prospect=prospect, outcome="started")
        threading.Thread(target=run_job, args=(jid,), daemon=True).start()
        self.redirect(f"/job/{jid}")


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):  # dropped TLS handshakes etc.
        pass


def main():
    global SEM
    p = argparse.ArgumentParser(description="Internal web form for the External Cyber Posture Review.")
    p.add_argument("--add-user", metavar="NAME", help="Create or update a login, then exit")
    p.add_argument("--users-file", default="users.txt")
    p.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1; use 0.0.0.0 to serve your network)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--cert", help="TLS certificate (PEM) to serve HTTPS directly")
    p.add_argument("--key", help="TLS private key (PEM)")
    p.add_argument("--auth-header", help="Trust this request header for the username (e.g. X-MS-CLIENT-PRINCIPAL-NAME "
                                         "from Azure App Service / an SSO proxy). Only use when the app is reachable "
                                         "solely through that proxy.")
    p.add_argument("--no-auth", action="store_true",
                   help="No login. Only allowed when bound to 127.0.0.1, i.e. for use on your own computer.")
    p.add_argument("--logo", help="HUB logo image (PNG/JPG/SVG) used on the form and in reports")
    p.add_argument("--contact", default="not provided", help="Contact email placed in the scanner's User-Agent")
    p.add_argument("--default-producer", default="")
    p.add_argument("--audit-log", default="audit.log")
    p.add_argument("--max-per-hour", type=int, default=20)
    p.add_argument("--max-concurrent", type=int, default=3)
    p.add_argument("--ttl-hours", type=int, default=24)
    p.add_argument("--lab-mode", action="store_true",
                   help="TESTING ONLY: allow private targets, skip DNS checks, scan ports 8080/8443. Never use in production.")
    a = p.parse_args()

    if a.add_user:
        return add_user(a.add_user, a.users_file)

    CFG.users_file, CFG.audit_log, CFG.contact = a.users_file, a.audit_log, a.contact
    CFG.default_producer, CFG.max_per_hour, CFG.ttl_hours = a.default_producer, a.max_per_hour, a.ttl_hours
    CFG.auth_header, CFG.tls, CFG.no_auth = a.auth_header, bool(a.cert and a.key), a.no_auth
    if a.no_auth and a.host not in ("127.0.0.1", "localhost", "::1"):
        sys.exit("--no-auth is only allowed with --host 127.0.0.1 (your own computer). "
                 "Anyone who can reach an open scanner can launch scans from this machine.")
    CFG.allow_private = CFG.skip_dns = a.lab_mode
    CFG.http_port, CFG.https_port = (8080, 8443) if a.lab_mode else (80, 443)
    CFG.logo_b64, CFG.logo_mime = None, "image/png"
    if a.logo:
        with open(a.logo, "rb") as fh:
            CFG.logo_b64 = base64.b64encode(fh.read()).decode()
        CFG.logo_mime = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "svg": "image/svg+xml"}.get(a.logo.lower().rsplit(".", 1)[-1], "image/png")
    SEM = threading.Semaphore(a.max_concurrent)

    if not a.auth_header and not a.no_auth and not load_users():
        sys.exit("No users yet. Create one first:  python3 posture_web.py --add-user yourname")
    if a.lab_mode:
        print("*** LAB MODE: private targets allowed. Do not use in production. ***")
    if not CFG.tls and a.host not in ("127.0.0.1", "localhost") and not a.auth_header:
        print("WARNING: serving logins over plain HTTP on a network interface. Use --cert/--key or an HTTPS reverse proxy.")

    srv = Server((a.host, a.port), Handler)
    if CFG.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(a.cert, a.key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    print(f"Posture Review web form on {'https' if CFG.tls else 'http'}://{a.host}:{a.port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
