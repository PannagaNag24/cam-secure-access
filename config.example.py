# ══════════════════════════════════════════════════════════════════════════
#  CAM Secure Access — Configuration Template
#  Copy to config.py and fill in your values.
#  config.py is gitignored and must never be committed.
# ══════════════════════════════════════════════════════════════════════════

# ── LDAP ──────────────────────────────────────────────────────────────────
LDAP_SERVER_URI      = "ldap://localhost"       # ldaps://localhost for TLS
LDAP_PORT            = 389                      # 636 for LDAPS
LDAP_USE_TLS         = False                    # True when using LDAPS
LDAP_BASE            = "dc=example,dc=com"
LDAP_CA_CERT         = ""                       # /etc/cam/certs/ca.crt when TLS
LDAP_SVC_DN          = "cn=admin,dc=example,dc=com"
LDAP_SVC_PASS_FILE   = "/etc/cam/svc_bind.secret"
LDAP_CONNECT_TIMEOUT = 5
LDAP_RECEIVE_TIMEOUT = 10

# ── PAM services ──────────────────────────────────────────────────────────
PAM_RADIUS_SERVICE   = "cam-gui-radius"
PAM_LDAP_SERVICE     = "cam-gui"

# ── Session policy ────────────────────────────────────────────────────────
SESSION_IDLE_TIMEOUT   = 300
SESSION_ABSOLUTE_LIMIT = 28800
MAX_LOGIN_ATTEMPTS     = 5
CONCURRENT_SESSION_MAX = 1

# ── Password policy ───────────────────────────────────────────────────────
MIN_PASSWORD_LENGTH    = 12
PASSWORD_HISTORY_DEPTH = 5

# ── URLs ──────────────────────────────────────────────────────────────────
WEB_URL        = "https://www.google.com"
LDAP_ADMIN_URL = "http://localhost:8080"

# ── Time-of-day access policy (local wall-clock, CR 2.1) ─────────────────
TIME_POLICY = {
    "ENGINEER":      ("00:00", "23:59"),
    "OPERATOR":      ("06:00", "22:00"),
    "VIEWER":        ("06:00", "22:00"),
    "INSTALLER":     ("07:00", "19:00"),
    "SECAUD":        ("00:00", "23:59"),
    "RBACMNT":       ("00:00", "23:59"),
    "ADMINISTRATOR": ("00:00", "23:59"),
    "SECADM":        ("00:00", "23:59"),
}

# ── Flask ─────────────────────────────────────────────────────────────────
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
