#!/usr/bin/env python3
"""
CAM Web — Flask web layer for CAM GUI IEC 62443-4-2 auth system.

All authentication, RBAC, session, and audit logic is imported
directly from cam_gui_iec62443 — this file is presentation only.

Routes
------
GET  /                  → redirect to /login
GET  /login             → login page
POST /login             → authenticate → dashboard or admin
GET  /dashboard         → user dashboard (role-filtered)
GET  /admin             → admin panel  (ADMINISTRATOR / SECADM / RBACMNT only)
GET  /admin/sessions    → active session list (JSON)
GET  /admin/logs        → audit log viewer
POST /admin/unlock/<u>  → unlock a user account
GET  /change-password   → password change form
POST /change-password   → process password change
POST /logout            → terminate session
GET  /healthz           → liveness probe (no auth)
"""

import sys
import os
import secrets

# ── locate the auth module (same directory or parent) ───────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
for _candidate in (_HERE, os.path.dirname(_HERE)):
    if os.path.isfile(os.path.join(_candidate, "cam_gui_iec62443.py")):
        sys.path.insert(0, _candidate)
        break

import cam_gui_iec62443 as auth

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, flash, abort,
)
from functools import wraps
from datetime import timedelta

# ── Flask app setup ──────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)          # regenerated on restart (stateless cookies)
app.config["SESSION_COOKIE_HTTPONLY"]  = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=auth.SESSION_ABSOLUTE_LIMIT)

# ── Admin roles that may access /admin ───────────────────────────────────────
ADMIN_ROLES = frozenset({"ADMINISTRATOR", "SECADM", "RBACMNT", "SECAUD"})


# ════════════════════════════════════════════════════════════════════════════
# Decorators
# ════════════════════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        roles = session.get("roles", [])
        if not any(r in ADMIN_ROLES for r in roles):
            auth.audit("ADMIN_ACCESS_DENIED", user=session["user"],
                       session=session.get("token", "-"))
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ════════════════════════════════════════════════════════════════════════════
# Auth routes
# ════════════════════════════════════════════════════════════════════════════

@app.get("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        raw_user = request.form.get("username", "")
        raw_pwd  = request.form.get("password", "")

        try:
            user = auth.validate_username(raw_user)
            pwd  = auth.validate_password(raw_pwd)
        except auth.InputValidationError as exc:
            error = str(exc)
            return render_template("login.html", error=error), 400

        # CR 1.11 – lockout check
        if auth.ldap_account_locked(user):
            auth.audit("LOGIN_DENIED_LOCKED", user=user)
            error = "Account is locked. Contact your administrator."
            return render_template("login.html", error=error), 403

        # Auth waterfall
        source = None
        if auth.ldaps_auth(user, pwd):
            source = "LDAPS"
        elif auth.pam_login(auth.PAM_RADIUS_SERVICE, user, pwd):
            source = "RADIUS"
        elif auth.sssd_alive() and auth.pam_login(auth.PAM_LDAP_SERVICE, user, pwd):
            source = "SSSD"

        if source is None:
            auth.ldap_record_failure(user)
            auth.audit("LOGIN_FAIL", user=user,
                       extra="methods_tried=LDAPS,RADIUS,SSSD")
            error = "Authentication failed."
            return render_template("login.html", error=error), 401

        auth.ldap_reset_failures(user)

        # Role resolution
        roles = auth.ldap_role_from_title(user) or auth.ldap_roles_from_groups(user)
        if not roles:
            auth.audit("LOGIN_DENIED_NO_ROLES", user=user, extra=f"source={source}")
            error = "No authorised roles assigned to this account."
            return render_template("login.html", error=error), 403

        # Time-of-day
        if not auth.time_allowed(roles):
            auth.audit("LOGIN_DENIED_TIME", user=user,
                       extra=f"source={source} roles={roles}")
            error = "Access is not permitted at this time."
            return render_template("login.html", error=error), 403

        # Session registry (CR 2.7)
        token = secrets.token_hex(32)
        if not auth.register_session(user, token):
            auth.audit("SESSION_CONCURRENT_DENIED", user=user)
            error = "A session for this account is already active."
            return render_template("login.html", error=error), 409

        perms = auth.resolve_permissions(roles)
        session.permanent = True
        session["user"]   = user
        session["roles"]  = roles
        session["perms"]  = list(perms)
        session["token"]  = token
        session["source"] = source

        auth.audit("LOGIN_SUCCESS", user=user, session=token,
                   extra=f"source={source} roles={roles}")

        return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)


@app.post("/logout")
@login_required
def logout():
    user  = session["user"]
    token = session.get("token", "-")
    auth.audit("LOGOUT", user=user, session=token)
    auth.deregister_session(user)
    session.clear()
    return redirect(url_for("login"))


# ════════════════════════════════════════════════════════════════════════════
# User dashboard
# ════════════════════════════════════════════════════════════════════════════

@app.get("/dashboard")
@login_required
def dashboard():
    user  = session["user"]
    roles = session.get("roles", [])
    perms = set(session.get("perms", []))
    auth.audit("DASHBOARD_VIEW", user=user, session=session.get("token", "-"))
    return render_template("dashboard.html",
                           user=user, roles=roles, perms=perms,
                           web_url=auth.WEB_URL,
                           ldap_url=auth.LDAP_ADMIN_URL,
                           is_admin=any(r in ADMIN_ROLES for r in roles))


# ════════════════════════════════════════════════════════════════════════════
# Password change
# ════════════════════════════════════════════════════════════════════════════

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user  = session["user"]
    error = None
    ok_msg = None

    if request.method == "POST":
        old     = request.form.get("old_password", "")
        new     = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if not old or not new or new != confirm:
            error = "Passwords do not match or a field is empty."
        else:
            try:
                auth.validate_password(new)
            except auth.InputValidationError as exc:
                error = str(exc)

        if not error:
            if not auth._verify_current_password(user, old):
                auth.audit("PWCHANGE_AUTH_FAIL", user=user,
                           session=session.get("token", "-"))
                error = "Current password is incorrect."
            else:
                policy_ok, reason = auth.password_policy_ok(user, old, new)
                if not policy_ok:
                    error = reason
                elif auth.ldap_change_password(user, old, new):
                    auth.audit("PASSWORD_CHANGE_SUCCESS", user=user,
                               session=session.get("token", "-"))
                    ok_msg = "Password updated successfully."
                else:
                    auth.audit("PASSWORD_CHANGE_FAIL", user=user,
                               session=session.get("token", "-"))
                    error = "Password change failed. Contact your administrator."

    return render_template("change_password.html",
                           user=user, error=error, ok_msg=ok_msg)


# ════════════════════════════════════════════════════════════════════════════
# Admin panel
# ════════════════════════════════════════════════════════════════════════════

@app.get("/admin")
@admin_required
def admin():
    user  = session["user"]
    roles = session.get("roles", [])
    auth.audit("ADMIN_VIEW", user=user, session=session.get("token", "-"))
    return render_template("admin.html", user=user, roles=roles,
                           is_admin=True)


@app.get("/admin/sessions")
@admin_required
def admin_sessions():
    """Return active sessions as JSON for the dashboard table."""
    try:
        raw = auth._read_registry()
        if raw is auth._REGISTRY_CORRUPT:
            return jsonify({"error": "Session registry corrupt"}), 500
        sessions = []
        for uname, data in raw.items():
            if uname.startswith("__"):
                continue
            sessions.append({
                "user":       uname,
                "token":      data.get("token", "")[:8] + "…",
                "login_time": data.get("login_time", ""),
                "expires_at": data.get("expires_at", ""),
            })
        return jsonify({"sessions": sessions})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.get("/admin/logs")
@admin_required
def admin_logs():
    """Return last N lines of the audit log as JSON."""
    n = min(int(request.args.get("n", 200)), 1000)
    lines = []
    try:
        with open(auth.LOG_FILE, "r") as fh:
            lines = fh.readlines()[-n:]
    except OSError:
        pass
    parsed = []
    for line in reversed(lines):
        line = line.strip()
        if line:
            parsed.append(line)
    return jsonify({"lines": parsed, "log_file": auth.LOG_FILE})


@app.post("/admin/unlock/<username>")
@admin_required
def admin_unlock(username: str):
    """Unlock a user account — ADMINISTRATOR only."""
    roles = session.get("roles", [])
    if "ADMINISTRATOR" not in roles and "SECADM" not in roles:
        abort(403)
    try:
        auth.validate_username(username)
    except auth.InputValidationError:
        abort(400)

    auth.ldap_reset_failures(username)
    auth.audit("ADMIN_UNLOCK", user=session["user"],
               session=session.get("token", "-"),
               extra=f"target={username}")
    return jsonify({"ok": True, "user": username})


# ════════════════════════════════════════════════════════════════════════════
# Liveness probe
# ════════════════════════════════════════════════════════════════════════════

@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok", "app": "CAM Web"}), 200


# ════════════════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    auth.startup_self_test()
    # Production: use gunicorn -w 1 -b 127.0.0.1:8080 app:app
    # Single worker only — session registry uses file locking, not in-memory
    app.run(host="127.0.0.1", port=8080, debug=False)


# ════════════════════════════════════════════════════════════════════════════
# Projects browser
# ════════════════════════════════════════════════════════════════════════════

@app.get("/projects")
@login_required
def projects():
    perms = set(session.get("perms", []))
    if "Projects" not in perms:
        abort(403)
    user = session["user"]
    auth.audit("PROJECTS_VIEW", user=user, session=session.get("token", "-"))
    entries = []
    try:
        for name in sorted(os.listdir(auth.PROJECTS_DIR)):
            full = os.path.join(auth.PROJECTS_DIR, name)
            stat = os.stat(full)
            import datetime
            entries.append({
                "name":   name,
                "is_dir": os.path.isdir(full),
                "size":   stat.st_size,
                "mtime":  datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            })
    except OSError:
        entries = []
    return render_template("projects.html", entries=entries,
                           projects_dir=auth.PROJECTS_DIR, user=user,
                           is_admin=any(r in ADMIN_ROLES for r in session.get("roles", [])))


# ════════════════════════════════════════════════════════════════════════════
# Audit log viewer
# ════════════════════════════════════════════════════════════════════════════

@app.get("/logs")
@login_required
def logs():
    perms = set(session.get("perms", []))
    if "Logs" not in perms:
        abort(403)
    user  = session["user"]
    roles = session.get("roles", [])
    auth.audit("LOGS_VIEW", user=user, session=session.get("token", "-"))
    return render_template("logs.html", user=user,
                           is_admin=any(r in ADMIN_ROLES for r in roles),
                           log_file=auth.LOG_FILE)


@app.get("/logs/data")
@login_required
def logs_data():
    perms    = set(session.get("perms", []))
    if "Logs" not in perms:
        abort(403)
    user     = session["user"]
    roles    = session.get("roles", [])
    is_admin = any(r in ADMIN_ROLES for r in roles)
    n        = min(int(request.args.get("n", 200)), 1000)
    q        = request.args.get("q", "").lower()
    lines    = []
    try:
        with open(auth.LOG_FILE) as fh:
            lines = fh.readlines()[-n:]
    except OSError:
        pass
    result = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        if not is_admin and f"user={user}" not in line:
            continue
        if q and q not in line.lower():
            continue
        result.append(line)
    return jsonify({"lines": result, "log_file": auth.LOG_FILE})


# ════════════════════════════════════════════════════════════════════════════
# Restricted shell
# ════════════════════════════════════════════════════════════════════════════

SHELL_ALLOWED_CMDS = {
    "ls", "pwd", "whoami", "id", "date", "uptime", "df", "free",
    "cat", "head", "tail", "grep", "find", "ps", "systemctl",
    "ip", "hostname", "uname", "echo",
}

@app.get("/shell")
@login_required
def shell():
    perms = set(session.get("perms", []))
    if "Shell" not in perms:
        abort(403)
    user = session["user"]
    auth.audit("SHELL_VIEW", user=user, session=session.get("token", "-"))
    return render_template("shell.html", user=user,
                           allowed=sorted(SHELL_ALLOWED_CMDS),
                           is_admin=any(r in ADMIN_ROLES for r in session.get("roles", [])))


@app.post("/shell/run")
@login_required
def shell_run():
    import subprocess as sp
    perms = set(session.get("perms", []))
    if "Shell" not in perms:
        abort(403)
    user = session["user"]
    raw  = (request.json or {}).get("cmd", "").strip()
    if not raw:
        return jsonify({"output": "", "error": "Empty command"})
    parts = raw.split()
    base  = parts[0].lstrip("./")
    if base not in SHELL_ALLOWED_CMDS:
        auth.audit("SHELL_BLOCKED", user=user, session=session.get("token", "-"),
                   extra=f"cmd={base}")
        return jsonify({"output": "",
                        "error": f"'{base}' not permitted. Allowed: {', '.join(sorted(SHELL_ALLOWED_CMDS))}"})
    auth.audit("SHELL_EXEC", user=user, session=session.get("token", "-"),
               extra=f"cmd={raw[:80]}")
    try:
        r = sp.run(parts, text=True, capture_output=True, timeout=10,
                   cwd=os.path.expanduser("~"),
                   env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
        return jsonify({"output": r.stdout, "error": r.stderr})
    except sp.TimeoutExpired:
        return jsonify({"output": "", "error": "Timed out (10s limit)"})
    except Exception as exc:
        return jsonify({"output": "", "error": str(exc)})
