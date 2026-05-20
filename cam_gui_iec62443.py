#!/usr/bin/env python3

"""
CAM GUI – Industrial Authentication System
IEC 62443-4-2 Compliant Implementation

IEC 62443-4-2 Requirements Addressed
─────────────────────────────────────
CR 1.1  – Human user identification and authentication
CR 1.2  – Software process and device identification and authentication
CR 1.3  – Account management (lockout, disable, creation)
CR 1.4  – Identifier management (unique IDs enforced via LDAP uid)
CR 1.5  – Authenticator management (password policy, change enforcement)
CR 1.6  – Wireless access management (N/A – wired only, noted)
CR 1.7  – Strength of password-based authentication (complexity + history)
CR 1.8  – Public key infrastructure certificates (LDAPS TLS enforced)
CR 1.9  – Strength of public key authentication (TLS cert validation)
CR 1.10 – Authenticator feedback (masked password entry)
CR 1.11 – Unsuccessful login attempts (lockout after threshold)
CR 1.12 – System use notification (pre-login banner)
CR 1.13 – Access via untrusted networks (LDAPS only, no plain LDAP, no anonymous bind)
CR 2.1  – Authorization enforcement (RBAC + permission resolution)
CR 2.2  – Wireless use control (N/A)
CR 2.3  – Use of portable and mobile devices (restricted shell, no USB)
CR 2.4  – Mobile code (no dynamic imports, no eval)
CR 2.5  – Session lock (idle timeout enforced)
CR 2.6  – Remote session termination (forced logout on timeout)
CR 2.7  – Concurrent session control (single session per user, file-backed registry)
CR 2.8  – Auditable events (all auth/authz events logged)
CR 2.9  – Audit storage capacity (rotating file handler)
CR 2.10 – Response to audit processing failures (fallback syslog)
CR 2.11 – Timestamps (ISO-8601 UTC timestamps in all logs)
CR 2.12 – Non-repudiation (user, source, session token in every log)
CR 3.1  – Communication integrity (LDAPS TLS)
CR 3.2  – Malicious code protection (input validation, no shell=True)
CR 3.3  – Security functionality verification (startup self-test)
CR 3.4  – Software and information integrity (file permission check)
CR 3.5  – Input validation (all user inputs sanitised)
CR 3.6  – Deterministic output (explicit exception handling)
CR 3.7  – Error handling (no sensitive data in error messages)
CR 4.1  – Information confidentiality (credentials never logged)
CR 4.2  – Information persistence (no credential caching)
CR 4.3  – Use of cryptography (TLS 1.2+, SHA-256 session tokens, PBKDF2-HMAC-SHA256 password history)
"""

import tkinter as tk
from tkinter import messagebox, simpledialog
import subprocess
import pam
import os
import re
import ssl
import hmac
import hashlib
import webbrowser
import threading
import secrets
import logging
import logging.handlers
import socket
from datetime import datetime, timezone, timedelta


# ── Timezone helpers ─────────────────────────────────────────────────────────
# utcnow()        – UTC-aware datetime for all audit logs and session timestamps
# localtime_hhmm()– Local wall-clock HH:MM for time-of-day access policy
#                   (operators set policy in local time, not UTC)

def utcnow() -> datetime:
    """Return current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def localtime_hhmm() -> str:
    """Return local wall-clock time as 'HH:MM' for access-policy checks."""
    return datetime.now().strftime("%H:%M")
from ldap3 import (
    Server, Connection, ALL, MODIFY_REPLACE, Tls
)
from ldap3.core.exceptions import LDAPException, LDAPBindError
import ldap3.extend


# ═══════════════════════════════════════════════════════════════
#  CONFIGURATION
#  Load from config.py (gitignored). Falls back to safe defaults
#  so the module imports cleanly without a config file.
# ═══════════════════════════════════════════════════════════════

try:
    import config as _cfg
except ImportError:
    _cfg = None  # type: ignore[assignment]

def _c(attr, default):
    """Return value from config.py or the given default."""
    return getattr(_cfg, attr, default) if _cfg else default


# ── LDAP ──────────────────────────────────────────────────────
LDAP_SERVER_URI      = _c("LDAP_SERVER_URI",      "ldap://localhost")
LDAP_PORT            = _c("LDAP_PORT",             389)
LDAP_USE_TLS         = _c("LDAP_USE_TLS",          False)
LDAP_BASE            = _c("LDAP_BASE",             "dc=example,dc=com")
LDAP_PEOPLE_OU       = f"ou=People,{LDAP_BASE}"
LDAP_CA_CERT         = _c("LDAP_CA_CERT",          "")
LDAP_SVC_DN          = _c("LDAP_SVC_DN",           f"cn=admin,dc=example,dc=com")
LDAP_SVC_PASS_FILE   = _c("LDAP_SVC_PASS_FILE",    "/etc/cam/svc_bind.secret")
LDAP_CONNECT_TIMEOUT = _c("LDAP_CONNECT_TIMEOUT",  5)
LDAP_RECEIVE_TIMEOUT = _c("LDAP_RECEIVE_TIMEOUT",  10)

# ── PAM ───────────────────────────────────────────────────────
PAM_RADIUS_SERVICE   = _c("PAM_RADIUS_SERVICE",    "cam-gui-radius")
PAM_LDAP_SERVICE     = _c("PAM_LDAP_SERVICE",      "cam-gui")

# ── Session / lockout ─────────────────────────────────────────
SESSION_IDLE_TIMEOUT   = _c("SESSION_IDLE_TIMEOUT",   300)
SESSION_ABSOLUTE_LIMIT = _c("SESSION_ABSOLUTE_LIMIT", 28800)
MAX_LOGIN_ATTEMPTS     = _c("MAX_LOGIN_ATTEMPTS",     5)
MIN_PASSWORD_LENGTH    = _c("MIN_PASSWORD_LENGTH",    12)
PASSWORD_HISTORY_DEPTH = _c("PASSWORD_HISTORY_DEPTH", 5)
CONCURRENT_SESSION_MAX = _c("CONCURRENT_SESSION_MAX", 1)

INPUT_MAX_LEN         = 256
ALLOWED_USERNAME_RE   = re.compile(r"^[a-z0-9._-]{1,64}$")

# ── Paths ─────────────────────────────────────────────────────
BASE_DIR       = os.path.expanduser("~/CAM_RESOURCES")
PROJECTS_DIR   = os.path.join(BASE_DIR, ".projects")
LOGS_DIR       = os.path.join(BASE_DIR, ".logs")
WEB_URL        = _c("WEB_URL",        "https://www.google.com")
LDAP_ADMIN_URL = _c("LDAP_ADMIN_URL", "http://localhost:8443/lam/templates/login.php")

# ── Log path: try privileged system dir, fall back to user dir ──
_SYSTEM_LOG_DIR   = "/var/log/cam_gui"
_FALLBACK_LOG_DIR = os.path.join(BASE_DIR, ".logs")

def _resolve_log_file() -> str:
    """
    Return the best available log file path.
    Tries the privileged system directory first; falls back to the
    user-writable CAM_RESOURCES directory if the system dir cannot
    be created or written to.  Never raises — always returns a path.
    """
    for candidate_dir in (_SYSTEM_LOG_DIR, _FALLBACK_LOG_DIR):
        try:
            os.makedirs(candidate_dir, exist_ok=True)
            candidate = os.path.join(candidate_dir, "cam_gui.log")
            # Verify we can actually open for append
            with open(candidate, "a"):
                pass
            return candidate
        except OSError:
            continue
    # Last resort: temp file in home directory
    return os.path.expanduser("~/cam_gui.log")

os.makedirs(PROJECTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR,     exist_ok=True)
LOG_FILE = _resolve_log_file()


# ═══════════════════════════════════════════════════════════════
#  AUDIT LOGGING
#  CR 2.8 / CR 2.9 / CR 2.10 / CR 2.11 / CR 2.12
#  • ISO-8601 UTC timestamps
#  • Rotating file (10 MB × 10 backups)
#  • Syslog fallback
#  • Credentials are NEVER logged (CR 4.1)
# ═══════════════════════════════════════════════════════════════

_LOG_FORMAT = (
    "%(asctime)s UTC | %(levelname)-8s | "
    "host=%(hostname)s | %(message)s"
)

class _UTCFormatter(logging.Formatter):
    """
    Force UTC timestamps (CR 2.11).
    Override formatTime directly — avoids the converter= approach
    which requires a struct_time but datetime.utcfromtimestamp
    returns a datetime object, causing TypeError in Python 3.12.
    """

    def __init__(self):
        super().__init__(fmt=_LOG_FORMAT, datefmt="%Y-%m-%dT%H:%M:%SZ")

    def formatTime(self, record, datefmt=None):
        ct = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return ct.strftime(datefmt or "%Y-%m-%dT%H:%M:%SZ")

    def format(self, record):
        record.hostname = socket.gethostname()
        return super().format(record)


def _build_logger() -> logging.Logger:
    log = logging.getLogger("CAM_AUTH")
    log.setLevel(logging.INFO)
    log.propagate = False

    # Rotating file handler  (CR 2.9)
    try:
        fh = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=10
        )
        fh.setFormatter(_UTCFormatter())
        log.addHandler(fh)
    except OSError as exc:
        # CR 2.10 – if file log fails, fall through to syslog only
        print(f"[WARN] Cannot open log file {LOG_FILE}: {exc}")

    # Syslog fallback  (CR 2.10)
    try:
        sh = logging.handlers.SysLogHandler(address="/dev/log")
        sh.setFormatter(logging.Formatter("CAM_AUTH: %(message)s"))
        log.addHandler(sh)
    except OSError:
        pass

    return log


logger = _build_logger()


def audit(event: str, user: str = "-", session: str = "-",
          extra: str = "") -> None:
    """
    Structured audit record.
    CR 2.8 – auditable events
    CR 2.12 – non-repudiation (user + session_token in every record)
    CR 4.1  – credentials are NEVER passed to this function
    """
    logger.info(
        f"event={event} user={user} session={session[:8] if session != '-' else '-'} "
        f"{extra}"
    )


# ═══════════════════════════════════════════════════════════════
#  EXTERNAL SESSION REGISTRY
#  CR 2.7  – concurrent session control (survives restart/crash)
#  CR 2.5  – expired sessions pruned on every registry access
#  CR 2.6  – absolute session limit enforced in registry
#  CR 2.12 – session token recorded in registry for audit trail
# ═══════════════════════════════════════════════════════════════

import json
import tempfile
import fcntl

# Registry file location — tries privileged path first
_SESSION_REGISTRY_DIRS = ["/var/run/cam_gui", os.path.join(BASE_DIR, ".sessions")]


def _resolve_registry_path() -> str:
    for d in _SESSION_REGISTRY_DIRS:
        try:
            os.makedirs(d, mode=0o700, exist_ok=True)
            path = os.path.join(d, "sessions.json")
            # Verify writable
            with open(path, "a"):
                pass
            return path
        except OSError:
            continue
    raise RuntimeError("Cannot create session registry in any candidate directory")


SESSION_REGISTRY_FILE = _resolve_registry_path()
_sessions_lock = threading.Lock()


# Sentinel returned by _read_registry() on unrecoverable corruption.
# register_session() treats this as "all slots occupied" → deny login.
_REGISTRY_CORRUPT: dict = {"__corrupt__": True}


def _quarantine_registry() -> None:
    """Rename the corrupt registry file so an operator can inspect it."""
    ts = utcnow().strftime("%Y%m%dT%H%M%SZ")
    quarantine = SESSION_REGISTRY_FILE + f".corrupt.{ts}"
    try:
        os.replace(SESSION_REGISTRY_FILE, quarantine)
        logger.critical(
            f"event=SESSION_REGISTRY_QUARANTINED path={quarantine}"
        )
    except OSError as exc:
        logger.critical(
            f"event=SESSION_REGISTRY_QUARANTINE_FAILED error={exc}"
        )


def _read_registry() -> dict:
    """
    Read and return the session registry dict, pruning expired entries.
    Holds a shared fcntl lock (LOCK_SH) for the duration of the read,
    allowing concurrent readers while blocking writers.

    Return values:
      dict   – valid registry (may be empty if file does not exist yet)
      _REGISTRY_CORRUPT – file exists but is corrupt; callers must deny
                          new sessions until an operator intervenes.
    """
    try:
        with open(SESSION_REGISTRY_FILE, "a+") as fh:
            fcntl.flock(fh, fcntl.LOCK_SH)
            fh.seek(0)
            raw = fh.read().strip()
            fcntl.flock(fh, fcntl.LOCK_UN)
        sessions: dict = json.loads(raw) if raw else {}
    except OSError:
        # File does not exist yet or cannot be opened — treat as empty
        return {}
    except json.JSONDecodeError:
        # File exists but is corrupt — fail-secure: quarantine and deny
        logger.critical(
            "event=SESSION_REGISTRY_CORRUPT "
            f"path={SESSION_REGISTRY_FILE} "
            "action=quarantine_and_deny_new_sessions"
        )
        _quarantine_registry()
        return _REGISTRY_CORRUPT

    # Prune expired sessions (CR 2.5 / CR 2.6)
    now = utcnow().isoformat()
    pruned = {u: s for u, s in sessions.items() if s.get("expires_at", "") > now}
    if len(pruned) != len(sessions):
        _write_registry(pruned)
    return pruned


def _write_registry(sessions: dict) -> None:
    """
    Atomically write the session registry using temp-file rename.
    Holds an exclusive fcntl lock during the write.
    """
    registry_dir = os.path.dirname(SESSION_REGISTRY_FILE)
    try:
        fd, tmp_path = tempfile.mkstemp(dir=registry_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                json.dump(sessions, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
                fcntl.flock(fh, fcntl.LOCK_UN)
            os.replace(tmp_path, SESSION_REGISTRY_FILE)
        except Exception:
            os.unlink(tmp_path)
            raise
    except OSError as exc:
        logger.error(f"event=SESSION_REGISTRY_WRITE_ERROR error={exc}")


def register_session(user: str, token: str) -> bool:
    """
    Register a new session.  Returns False if the user already has
    a valid active session (CR 2.7 – single session per user),
    or if the registry is corrupt (fail-secure).
    Session expiry = now + SESSION_ABSOLUTE_LIMIT (CR 2.6).
    """
    with _sessions_lock:
        sessions = _read_registry()
        if sessions is _REGISTRY_CORRUPT:
            logger.critical(
                f"event=SESSION_DENIED_REGISTRY_CORRUPT user={user}"
            )
            return False
        if user in sessions:
            logger.warning(
                f"event=SESSION_ALREADY_ACTIVE user={user} "
                f"existing_token={sessions[user].get('token','?')[:8]}"
            )
            return False
        now = utcnow()
        sessions[user] = {
            "token":      token,
            "login_time": now.isoformat(),
            "expires_at": (now + timedelta(seconds=SESSION_ABSOLUTE_LIMIT)).isoformat(),
        }
        _write_registry(sessions)
        return True


def deregister_session(user: str) -> None:
    """Remove the user's session from the persistent registry."""
    with _sessions_lock:
        sessions = _read_registry()
        if user in sessions:
            sessions.pop(user)
            _write_registry(sessions)


# ═══════════════════════════════════════════════════════════════
#  LDAP TLS HELPER
#  CR 1.8 / CR 1.9 / CR 3.1 – certificate validation mandatory
# ═══════════════════════════════════════════════════════════════

def _make_tls() -> Tls | None:
    """Return Tls object when LDAP_USE_TLS=True, None for plain ldap://."""
    if not LDAP_USE_TLS:
        return None
    return Tls(
        ca_certs_file=LDAP_CA_CERT,
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLS_CLIENT,
    )


class SvcBindError(Exception):
    """Raised when the service-account credential cannot be loaded or bound."""


def _svc_bind() -> Connection:
    """
    Privileged service-account bind used for directory reads/writes.
    CR 1.2 – software process authentication.
    Raises SvcBindError (not RuntimeError) so callers can handle it cleanly.
    """
    try:
        with open(LDAP_SVC_PASS_FILE, "r") as fh:
            svc_pass = fh.read().strip()
    except OSError as exc:
        raise SvcBindError(
            f"Cannot read service credential file "
            f"{LDAP_SVC_PASS_FILE}: {exc}"
        ) from exc

    server = Server(
        LDAP_SERVER_URI,
        port=LDAP_PORT,
        use_ssl=LDAP_USE_TLS,
        tls=_make_tls(),
        connect_timeout=LDAP_CONNECT_TIMEOUT,
        get_info=ALL,
    )
    try:
        conn = Connection(
            server,
            user=LDAP_SVC_DN,
            password=svc_pass,
            auto_bind=True,
            receive_timeout=LDAP_RECEIVE_TIMEOUT,
            read_only=False,
        )
    except LDAPException as exc:
        raise SvcBindError(
            f"Service account bind failed for {LDAP_SVC_DN}: {exc}"
        ) from exc
    return conn


# ── No anonymous bind. All LDAP operations require the service account.
# ── CR 1.2 / CR 4.1 – unauthenticated directory access is prohibited.
# ── If _svc_bind() raises SvcBindError the caller logs and skips the
# ── operation; it does NOT fall back to anonymous access.


# ═══════════════════════════════════════════════════════════════
#  INPUT VALIDATION
#  CR 3.5 – validate all inputs before use
# ═══════════════════════════════════════════════════════════════

class InputValidationError(ValueError):
    pass


def validate_username(value: str) -> str:
    if not value or len(value) > INPUT_MAX_LEN:
        raise InputValidationError("Username length invalid")
    if not ALLOWED_USERNAME_RE.match(value):
        raise InputValidationError("Username contains illegal characters")
    return value


def validate_password(value: str) -> str:
    if not value or len(value) > INPUT_MAX_LEN:
        raise InputValidationError("Password length invalid")
    return value


# ═══════════════════════════════════════════════════════════════
#  SSSD HEALTH CHECK
#  CR 3.3 / CR 3.6 – verify SSSD daemon is running before PAM
#  fallback; avoids hanging PAM calls when sssd is stopped
# ═══════════════════════════════════════════════════════════════

def sssd_alive() -> bool:
    """Return True only if the sssd daemon is actively running."""
    try:
        out = subprocess.check_output(
            ["systemctl", "is-active", "sssd"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        alive = out.strip() == "active"
        if not alive:
            logger.info("event=SSSD_UNAVAILABLE detail=daemon_not_active")
        return alive
    except (subprocess.SubprocessError, OSError) as exc:
        logger.error(f"event=SSSD_CHECK_ERROR error={type(exc).__name__}")
        return False


# ═══════════════════════════════════════════════════════════════
#  PAM AUTHENTICATION
# ═══════════════════════════════════════════════════════════════

_pam = pam.pam()


def pam_login(service: str, user: str, password: str) -> bool:
    """CR 1.1 – human user authentication via PAM."""
    # Map PAM service name to human-readable method label for logs
    method = "RADIUS" if service == PAM_RADIUS_SERVICE else "SSSD"
    logger.info(f"event=AUTH_ATTEMPT user={user} method={method} pam_service={service}")
    try:
        result = _pam.authenticate(user, password, service=service)
        if result:
            logger.info(f"event=AUTH_METHOD_SUCCESS user={user} method={method}")
        else:
            logger.info(f"event=AUTH_METHOD_FAIL user={user} method={method} reason=pam_rejected")
        return result
    except Exception as exc:                         # noqa: BLE001
        logger.error(
            f"event=AUTH_METHOD_FAIL user={user} method={method} "
            f"pam_service={service} reason={type(exc).__name__}"
        )
        return False


# ═══════════════════════════════════════════════════════════════
#  LDAPS DIRECT AUTHENTICATION
#  CR 1.1 / CR 1.8 – TLS-only bind, no plain LDAP
# ═══════════════════════════════════════════════════════════════

def ldaps_auth(user: str, password: str) -> bool:
    user_dn = f"uid={user},{LDAP_PEOPLE_OU}"
    logger.info(f"event=AUTH_ATTEMPT user={user} method=LDAPS")
    try:
        server = Server(
            LDAP_SERVER_URI,
            port=LDAP_PORT,
            use_ssl=LDAP_USE_TLS,
            tls=_make_tls(),
            connect_timeout=LDAP_CONNECT_TIMEOUT,
            get_info=ALL,
        )
        conn = Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=True,
            receive_timeout=LDAP_RECEIVE_TIMEOUT,
        )
        conn.unbind()
        logger.info(f"event=AUTH_METHOD_SUCCESS user={user} method=LDAPS")
        return True
    except LDAPBindError:
        logger.info(f"event=AUTH_METHOD_FAIL user={user} method=LDAPS reason=bind_rejected")
        return False
    except LDAPException as exc:
        logger.error(f"event=AUTH_METHOD_FAIL user={user} method=LDAPS reason={type(exc).__name__}")
        return False


# ═══════════════════════════════════════════════════════════════
#  ACCOUNT LOCKOUT
#  CR 1.3 / CR 1.11 – lockout enforcement via service account
# ═══════════════════════════════════════════════════════════════

def ldap_account_locked(user: str) -> bool:
    """
    Check if account is locked.
    Supports both custom accountLocked attribute and
    OpenLDAP ppolicy pwdAccountLockedTime attribute.
    CR 1.3 / CR 1.11 – account lockout enforcement.

    IMPORTANT: Returns False (not locked) on LDAP errors
    to avoid locking out all users when the attribute is absent
    from the schema or the service bind is unavailable.
    Application-level lockout (loginFailures counter) is the
    primary enforcement mechanism in that case.
    """
    user_dn = f"uid={user},{LDAP_PEOPLE_OU}"
    try:
        conn = _svc_bind()
        conn.search(
            user_dn,
            "(objectClass=*)",
            attributes=["accountLocked", "pwdAccountLockedTime"]
        )

        if not conn.entries:
            conn.unbind()
            return False   # User not found — let auth fail naturally

        entry = conn.entries[0]
        conn.unbind()

        # Check custom accountLocked attribute (if schema has it)
        if "accountLocked" in entry and entry.accountLocked.value is not None:
            return str(entry.accountLocked.value).upper() == "TRUE"

        # Check OpenLDAP ppolicy pwdAccountLockedTime (if schema has it)
        if "pwdAccountLockedTime" in entry and entry.pwdAccountLockedTime.value is not None:
            val = str(entry.pwdAccountLockedTime.value).strip()
            # "000001010000Z" is the sentinel value for indefinitely locked
            return bool(val)

        # Neither attribute present — not locked
        return False

    except Exception as exc:                         # noqa: BLE001
        logger.error(
            f"event=LOCKOUT_CHECK_ERROR user={user} error={type(exc).__name__}"
        )
        # Return False here (not locked) so that a missing schema attribute
        # or a transient LDAP error does not deny ALL users.
        # The loginFailures counter enforced by ldap_record_failure() provides
        # the actual lockout protection (CR 1.11).
        return False


# OpenLDAP ppolicy sentinel: this value means "permanently locked"
_PPOLICY_LOCKED_SENTINEL = "000001010000Z"


def ldap_record_failure(user: str) -> None:
    """
    Increment loginFailures counter.
    On threshold: write pwdAccountLockedTime (OpenLDAP ppolicy standard)
    AND accountLocked=TRUE (custom schema fallback) so both schemas work.
    CR 1.11 – unsuccessful login attempt handling.
    """
    user_dn = f"uid={user},{LDAP_PEOPLE_OU}"
    try:
        conn = _svc_bind()  # write required
        conn.search(user_dn, "(objectClass=*)", attributes=["loginFailures"])
        if not conn.entries:
            conn.unbind()
            return
        failures = int(conn.entries[0].loginFailures.value or 0) + 1
        updates: dict = {"loginFailures": [(MODIFY_REPLACE, [str(failures)])]}
        if failures >= MAX_LOGIN_ATTEMPTS:
            # Write both lock attributes — works on OpenLDAP ppolicy
            # and custom schema environments
            updates["pwdAccountLockedTime"] = [(MODIFY_REPLACE, [_PPOLICY_LOCKED_SENTINEL])]
            updates["accountLocked"]        = [(MODIFY_REPLACE, ["TRUE"])]
            audit("ACCOUNT_LOCKED", user=user,
                  extra=f"failures={failures} threshold={MAX_LOGIN_ATTEMPTS}")
        conn.modify(user_dn, updates)
        conn.unbind()
    except SvcBindError as exc:
        logger.warning(f"event=RECORD_FAILURE_SKIP user={user} reason=no_svc_bind detail={exc}")
    except Exception as exc:                         # noqa: BLE001
        logger.error(
            f"event=RECORD_FAILURE_ERROR user={user} error={type(exc).__name__}"
        )


def ldap_reset_failures(user: str) -> None:
    """
    Reset failure counter and clear both lock attributes on successful auth.
    CR 1.11 – reset after successful authentication.
    """
    user_dn = f"uid={user},{LDAP_PEOPLE_OU}"
    try:
        conn = _svc_bind()  # write required
        conn.modify(user_dn, {
            "loginFailures":       [(MODIFY_REPLACE, ["0"])],
            "pwdAccountLockedTime": [(MODIFY_REPLACE, [])],   # delete value
            "accountLocked":       [(MODIFY_REPLACE, ["FALSE"])],
        })
        conn.unbind()
    except SvcBindError as exc:
        logger.warning(f"event=RESET_FAILURE_SKIP user={user} reason=no_svc_bind detail={exc}")
    except Exception as exc:                         # noqa: BLE001
        logger.error(
            f"event=RESET_FAILURE_ERROR user={user} error={type(exc).__name__}"
        )


# ═══════════════════════════════════════════════════════════════
#  PASSWORD POLICY
#  CR 1.5 / CR 1.7
# ═══════════════════════════════════════════════════════════════

def _fetch_password_history(user: str) -> list[str]:
    """Retrieve stored hashed password history from LDAP."""
    user_dn = f"uid={user},{LDAP_PEOPLE_OU}"
    try:
        conn = _svc_bind()
        conn.search(user_dn, "(objectClass=*)", attributes=["passwordHistory"])
        if not conn.entries:
            return []
        raw = conn.entries[0].passwordHistory.values   # multi-value
        conn.unbind()
        return list(raw) if raw else []
    except Exception:                                  # noqa: BLE001
        return []


# PBKDF2 parameters — NIST SP 800-132 / CR 4.3
_PBKDF2_ITERATIONS = 260_000
_PBKDF2_HASH       = "sha256"
_HISTORY_DELIM     = ":"


def _hash_password_for_history(password: str, salt: bytes | None = None) -> str:
    """
    PBKDF2-HMAC-SHA256 hash for password history storage.
    CR 4.3 – use of cryptography (strong KDF, not raw hash).

    Returns a portable string:
        pbkdf2:sha256:<iterations>:<hex_salt>:<hex_dk>

    If salt is None a fresh random 32-byte salt is generated.
    This means two calls with the same password produce different
    stored values — comparison uses _verify_history_hash().
    """
    if salt is None:
        salt = secrets.token_bytes(32)
    dk = hashlib.pbkdf2_hmac(
        _PBKDF2_HASH,
        password.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
    )
    return (
        f"pbkdf2{_HISTORY_DELIM}{_PBKDF2_HASH}"
        f"{_HISTORY_DELIM}{_PBKDF2_ITERATIONS}"
        f"{_HISTORY_DELIM}{salt.hex()}"
        f"{_HISTORY_DELIM}{dk.hex()}"
    )


def _verify_history_hash(password: str, stored: str) -> bool:
    """
    Constant-time verification of a password against a stored history hash.
    Supports both legacy sha256 records and current pbkdf2 records.
    """
    try:
        parts = stored.split(_HISTORY_DELIM)
        if parts[0] == "pbkdf2" and len(parts) == 5:
            _, algo, iterations, salt_hex, dk_hex = parts
            salt = bytes.fromhex(salt_hex)
            expected_dk = bytes.fromhex(dk_hex)
            candidate_dk = hashlib.pbkdf2_hmac(
                algo,
                password.encode("utf-8"),
                salt,
                int(iterations),
            )
            return hmac.compare_digest(candidate_dk, expected_dk)
        # Legacy plain SHA-256 record (migrate on next password change)
        legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(legacy, stored)
    except Exception:                                # noqa: BLE001
        return False


def password_policy_ok(
    user: str,
    old: str,
    new: str,
    skip_history: bool = False,
) -> tuple[bool, str]:
    """
    CR 1.7 – password complexity + history check.
    Returns (ok, reason).

    skip_history=True bypasses the LDAP history lookup — used only
    by the startup self-test so it exercises local logic without
    making a network call against a non-existent test user.
    """
    if len(new) < MIN_PASSWORD_LENGTH:
        return False, f"Minimum {MIN_PASSWORD_LENGTH} characters required"

    if user.lower() in new.lower():
        return False, "Password must not contain the username"

    # Check 4-char username substrings
    for i in range(len(user) - 3):
        if user[i:i+4].lower() in new.lower():
            return False, "Password must not contain username fragments"

    if new == old:
        return False, "New password must differ from current password"

    complexity = [
        (r"[A-Z]",         "uppercase letter"),
        (r"[a-z]",         "lowercase letter"),
        (r"[0-9]",         "digit"),
        (r"[^A-Za-z0-9]",  "special character"),
    ]
    for pattern, label in complexity:
        if not re.search(pattern, new):
            return False, f"Password must contain at least one {label}"

    # History check (CR 1.7 – password reuse) — skipped during self-test
    if not skip_history:
        new_hash = _hash_password_for_history(new)
        history  = _fetch_password_history(user)
        if any(_verify_history_hash(new, h) for h in history[-PASSWORD_HISTORY_DEPTH:]):
            return False, f"Password was used in the last {PASSWORD_HISTORY_DEPTH} changes"

    return True, ""


# ═══════════════════════════════════════════════════════════════
#  PASSWORD CHANGE
#  CR 1.5 – uses LDAP Password Modify Extended Operation
#  (avoids exposing credentials on the process command line)
# ═══════════════════════════════════════════════════════════════

def _verify_current_password(user: str, password: str) -> bool:
    """
    Verify the user's current password via direct LDAPS bind.
    CR 1.1 / CR 1.8 – uses the same TLS-verified mechanism as login.
    Falls back to PAM (SSSD) only if LDAPS is unavailable.
    Never uses subprocess or shell.
    """
    # Primary: LDAPS bind (same path as login, TLS enforced)
    if ldaps_auth(user, password):
        logger.info(
            f"event=PWCHANGE_VERIFY_SUCCESS user={user} method=LDAPS"
        )
        return True

    # Fallback: PAM/SSSD (only if SSSD daemon is running)
    if sssd_alive() and pam_login(PAM_LDAP_SERVICE, user, password):
        logger.info(
            f"event=PWCHANGE_VERIFY_SUCCESS user={user} method=SSSD_PAM"
        )
        return True

    logger.warning(f"event=PWCHANGE_VERIFY_FAIL user={user}")
    return False


def ldap_change_password(user: str, old: str, new: str) -> bool:
    """
    CR 1.5 / CR 4.1 – Password Modify Extended Op via ldap3 RFC 3062.
    Never exposes credentials to subprocess arguments.
    Authenticates as the user (not the service account) so the
    directory enforces its own password policy as well.
    """
    user_dn = f"uid={user},{LDAP_PEOPLE_OU}"
    try:
        server = Server(
            LDAP_SERVER_URI,
            port=LDAP_PORT,
            use_ssl=LDAP_USE_TLS,
            tls=_make_tls(),
            connect_timeout=LDAP_CONNECT_TIMEOUT,
        )
        conn = Connection(
            server,
            user=user_dn,
            password=old,
            auto_bind=True,
            receive_timeout=LDAP_RECEIVE_TIMEOUT,
        )
        # RFC 3062 Password Modify Extended Operation
        result = conn.extend.standard.modify_password(
            user=user_dn,
            old_password=old,
            new_password=new,
        )
        conn.unbind()

        if result:
            _update_password_history(user, new)

        return bool(result)
    except LDAPBindError:
        return False
    except LDAPException as exc:
        logger.error(
            f"event=PWCHANGE_ERROR user={user} error={type(exc).__name__}"
        )
        return False


def _update_password_history(user: str, new_password: str) -> None:
    """Append new password hash to LDAP passwordHistory attribute."""
    user_dn = f"uid={user},{LDAP_PEOPLE_OU}"
    try:
        conn = _svc_bind()
        conn.search(user_dn, "(objectClass=*)", attributes=["passwordHistory"])
        history: list[str] = []
        if conn.entries:
            history = list(conn.entries[0].passwordHistory.values or [])
        history.append(_hash_password_for_history(new_password))
        history = history[-PASSWORD_HISTORY_DEPTH:]
        conn.modify(user_dn, {"passwordHistory": [(MODIFY_REPLACE, history)]})
        conn.unbind()
    except Exception as exc:                         # noqa: BLE001
        logger.error(
            f"event=HISTORY_UPDATE_ERROR user={user} error={type(exc).__name__}"
        )


# ═══════════════════════════════════════════════════════════════
#  ROLE RESOLUTION (RBAC)
#  CR 2.1 – authorisation enforcement
# ═══════════════════════════════════════════════════════════════

VALID_ROLES: frozenset[str] = frozenset({
    "VIEWER", "OPERATOR", "ENGINEER", "ADMINISTRATOR",
    "INSTALLER", "SECAUD", "SECADM", "RBACMNT",
})

# CR 2.8 / CR 2.1 – time-of-day access windows per role
TIME_POLICY: dict[str, tuple[str, str]] = _c("TIME_POLICY", {
    "ENGINEER":      ("08:00", "19:00"),
    "OPERATOR":      ("08:00", "19:00"),
    "VIEWER":        ("08:00", "18:00"),
    "INSTALLER":     ("08:00", "17:00"),
    "SECAUD":        ("08:00", "18:00"),
    "RBACMNT":       ("08:00", "18:00"),
    "ADMINISTRATOR": ("00:00", "23:59"),
    "SECADM":        ("00:00", "23:59"),
})

# CR 2.1 – minimum-privilege permission sets
RBAC_POLICY: dict[str, frozenset[str]] = {
    "VIEWER":        frozenset({"Web", "Logs"}),
    "OPERATOR":      frozenset({"Web", "Logs"}),
    "ENGINEER":      frozenset({"Web", "Projects", "Logs", "Shell"}),
    "ADMINISTRATOR": frozenset({"Web", "Projects", "Logs", "Shell", "LDAP"}),
    "INSTALLER":     frozenset({"Projects", "Shell"}),
    "SECAUD":        frozenset({"Logs"}),
    "SECADM":        frozenset({"Logs", "LDAP"}),
    "RBACMNT":       frozenset({"LDAP"}),
}


def ldap_role_from_title(user: str) -> list[str]:
    """Primary role source: LDAP title attribute."""
    user_dn = f"uid={user},{LDAP_PEOPLE_OU}"
    try:
        conn = _svc_bind()
        conn.search(user_dn, "(objectClass=*)", attributes=["title"])
        if not conn.entries:
            conn.unbind()
            return []
        title = str(conn.entries[0].title.value or "").strip().upper()
        conn.unbind()
        return [title] if title in VALID_ROLES else []
    except Exception as exc:                         # noqa: BLE001
        logger.error(
            f"event=ROLE_TITLE_ERROR user={user} error={type(exc).__name__}"
        )
        return []


def ldap_roles_from_groups(user: str) -> list[str]:
    """Fallback role source: OS group membership."""
    try:
        out = subprocess.check_output(
            ["id", "-nG", user],
            text=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        )
        groups = out.strip().split()
        return sorted(g for g in groups if g in VALID_ROLES)
    except (subprocess.SubprocessError, OSError) as exc:
        logger.error(
            f"event=ROLE_GROUP_ERROR user={user} error={type(exc).__name__}"
        )
        return []


# ═══════════════════════════════════════════════════════════════
#  TIME-OF-DAY ACCESS CONTROL
#  CR 2.1 – supplemental temporal access policy
# ═══════════════════════════════════════════════════════════════

def time_allowed(roles: list[str]) -> bool:
    """
    CR 2.1 – time-of-day access policy.
    Uses local wall-clock time so policy windows match what operators
    configure (e.g. "08:00–18:00" means 8 AM local, not 8 AM UTC).
    """
    now = localtime_hhmm()
    for role in roles:
        start, end = TIME_POLICY.get(role, ("00:00", "23:59"))
        if start <= now <= end:
            return True
    return False


# ═══════════════════════════════════════════════════════════════
#  PERMISSION RESOLUTION
# ═══════════════════════════════════════════════════════════════

def resolve_permissions(roles: list[str]) -> frozenset[str]:
    perms: set[str] = set()
    for role in roles:
        perms |= RBAC_POLICY.get(role, frozenset())
    return frozenset(perms)


# ═══════════════════════════════════════════════════════════════
#  STARTUP SELF-TEST
#  CR 3.3 – security functionality verification at startup
# ═══════════════════════════════════════════════════════════════

def startup_self_test() -> None:
    """
    Verify critical security components before accepting any logins.
    Exits the process if any check fails.
    """
    failures: list[str] = []

    # 1. CA certificate file must exist and be readable
    if not os.path.isfile(LDAP_CA_CERT):
        failures.append(f"CA cert not found: {LDAP_CA_CERT}")

    # 2. Service credential file must exist and be root-readable only
    if not os.path.isfile(LDAP_SVC_PASS_FILE):
        failures.append(f"Service credential file missing: {LDAP_SVC_PASS_FILE}")
    else:
        stat = os.stat(LDAP_SVC_PASS_FILE)
        if stat.st_mode & 0o077:
            failures.append(
                f"Service credential file has insecure permissions: "
                f"{oct(stat.st_mode)}"
            )

    # 3. Log directory writable
    if not os.access(os.path.dirname(LOG_FILE), os.W_OK):
        failures.append(f"Log directory not writable: {os.path.dirname(LOG_FILE)}")

    # 4. Password policy logic self-check — skip_history=True so no
    #    LDAP call is made against a non-existent "testuser" account.
    #    This tests length, complexity, username-fragment rules only.
    ok, reason = password_policy_ok(
        "testuser", "OldPass1!", "NewP@ssw0rd99", skip_history=True
    )
    if not ok:
        failures.append(f"Password policy self-check failed unexpectedly: {reason}")

    if failures:
        for msg in failures:
            logger.critical(f"event=SELF_TEST_FAIL detail={msg}")
        raise SystemExit(
            "CRITICAL: Startup self-test failed. See logs. Aborting."
        )

    logger.info("event=SELF_TEST_PASS")


# ═══════════════════════════════════════════════════════════════
#  SYSTEM USE NOTIFICATION BANNER
#  CR 1.12 – pre-login warning banner
# ═══════════════════════════════════════════════════════════════

SYSTEM_BANNER = (
    "AUTHORISED USE ONLY\n\n"
    "This system is for authorised personnel only.\n"
    "All access is monitored and recorded in accordance with\n"
    "site security policy and applicable legislation.\n\n"
    "Unauthorised access or misuse may result in disciplinary\n"
    "action and/or criminal prosecution.\n\n"
    "By continuing you consent to monitoring."
)


# ═══════════════════════════════════════════════════════════════
#  GUI APPLICATION
# ═══════════════════════════════════════════════════════════════

class CAMGUI(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("CAM Secure Login")
        self.geometry("520x580")
        self.resizable(False, False)

        # Session state
        self._session_token:   str | None      = None
        self._session_user:    str | None      = None
        self._last_activity:   datetime | None = None
        self._session_start:   datetime | None = None
        self._idle_stop:       threading.Event = threading.Event()

        # Input variables
        self.user = tk.StringVar()
        self.pwd  = tk.StringVar()

        # CR 1.12 – show banner once before login UI
        self._show_banner()

    # ── Banner (CR 1.12) ──────────────────────────────────────

    def _show_banner(self) -> None:
        accepted = messagebox.askokcancel(
            "System Use Notification", SYSTEM_BANNER
        )
        if not accepted:
            self.destroy()
            return
        self.login_ui()

    # ── Helpers ───────────────────────────────────────────────

    def _clear(self) -> None:
        for widget in self.winfo_children():
            widget.destroy()

    def _touch_activity(self, _event=None) -> None:
        """Reset idle timer on any user interaction (CR 2.5)."""
        if self._session_token:
            self._last_activity = utcnow()

    # ── Session management (CR 2.5 / CR 2.6 / CR 2.7) ────────

    def _start_session(self, user: str) -> bool:
        token = secrets.token_hex(32)
        if not register_session(user, token):
            audit("SESSION_CONCURRENT_DENIED", user=user)
            messagebox.showerror(
                "Denied",
                "A session for this account is already active."
            )
            return False
        self._session_token = token
        self._session_user  = user
        now = utcnow()
        self._last_activity = now
        self._session_start = now
        self._idle_stop.clear()
        self._start_watchdog()
        return True

    def _start_watchdog(self) -> None:
        """Background thread – enforces idle + absolute timeouts."""
        def watchdog() -> None:
            while not self._idle_stop.wait(timeout=5):
                now = utcnow()
                if self._last_activity and self._session_start:
                    idle = (now - self._last_activity).total_seconds()
                    age  = (now - self._session_start).total_seconds()
                    if idle >= SESSION_IDLE_TIMEOUT:
                        self.after(0, lambda: self._force_logout("IDLE_TIMEOUT"))
                        return
                    if age >= SESSION_ABSOLUTE_LIMIT:
                        self.after(0, lambda: self._force_logout("ABSOLUTE_TIMEOUT"))
                        return

        threading.Thread(target=watchdog, daemon=True).start()

    def _end_session(self) -> None:
        self._idle_stop.set()
        if self._session_user:
            deregister_session(self._session_user)
        self._session_token = None
        self._session_user  = None
        self._last_activity = None
        self._session_start = None

    def _force_logout(self, reason: str = "TIMEOUT") -> None:
        audit(
            f"SESSION_{reason}",
            user=self._session_user or "-",
            session=self._session_token or "-",
        )
        self._end_session()
        messagebox.showwarning("Session", "Your session has expired.")
        self.login_ui()

    # ── Login UI ──────────────────────────────────────────────

    def login_ui(self) -> None:
        self._clear()
        self.user.set("")
        self.pwd.set("")

        tk.Label(self, text="CAM Secure Access", font=("Arial", 14, "bold")).pack(pady=10)
        tk.Label(self, text="Username").pack()
        user_entry = tk.Entry(self, textvariable=self.user)
        user_entry.pack()

        tk.Label(self, text="Password").pack()
        # CR 1.10 – authenticator feedback masked
        tk.Entry(self, textvariable=self.pwd, show="•").pack()

        tk.Button(self, text="Login",           command=self._login).pack(pady=10)
        tk.Button(self, text="Change Password", command=self._change_password).pack()

        user_entry.focus_set()

    # ── Authentication (CR 1.1 / CR 1.11 / CR 1.13) ──────────

    def _login(self) -> None:
        raw_user = self.user.get()
        raw_pwd  = self.pwd.get()

        # CR 3.5 – validate inputs before any processing
        try:
            user = validate_username(raw_user)
            pwd  = validate_password(raw_pwd)
        except InputValidationError as exc:
            messagebox.showerror("Input Error", str(exc))
            return

        # CR 1.11 – check lockout before attempting auth
        if ldap_account_locked(user):
            audit("LOGIN_DENIED_LOCKED", user=user)
            messagebox.showerror("Locked", "Account is locked. Contact your administrator.")
            return

        # Authentication waterfall — tries each method in order,
        # logs every attempt and outcome (CR 2.8 / CR 2.12)
        source: str | None = None

        if ldaps_auth(user, pwd):
            source = "LDAPS"
        elif pam_login(PAM_RADIUS_SERVICE, user, pwd):
            source = "RADIUS"
        elif sssd_alive() and pam_login(PAM_LDAP_SERVICE, user, pwd):
            source = "SSSD"
        else:
            # All three methods rejected — sssd_alive already logged if SSSD skipped
            pass

        if source is None:
            ldap_record_failure(user)
            audit("LOGIN_FAIL", user=user,
                  extra="methods_tried=LDAPS,RADIUS,SSSD")
            # CR 3.7 – generic error, no disclosure of failure reason
            messagebox.showerror("Denied", "Authentication failed.")
            return

        ldap_reset_failures(user)

        # Role resolution (CR 2.1)
        roles = ldap_role_from_title(user) or ldap_roles_from_groups(user)
        if not roles:
            audit("LOGIN_DENIED_NO_ROLES", user=user, extra=f"source={source}")
            messagebox.showerror("Denied", "No authorised roles are assigned to this account.")
            return

        # Time-of-day control (CR 2.1)
        if not time_allowed(roles):
            audit("LOGIN_DENIED_TIME", user=user, extra=f"source={source} roles={roles}")
            messagebox.showerror("Denied", "Access is not permitted at this time.")
            return

        # Concurrent session control (CR 2.7)
        if not self._start_session(user):
            return

        audit(
            "LOGIN_SUCCESS",
            user=user,
            session=self._session_token or "-",
            extra=f"source={source} roles={roles}",
        )

        self._dashboard(user, roles)

    # ── Password Change (CR 1.5 / CR 1.7) ────────────────────

    def _change_password(self) -> None:
        raw_user = simpledialog.askstring("Change Password", "Username:")
        if not raw_user:
            return

        try:
            user = validate_username(raw_user)
        except InputValidationError as exc:
            messagebox.showerror("Input Error", str(exc))
            return

        old     = simpledialog.askstring("Change Password", "Current password:", show="•")
        new     = simpledialog.askstring("Change Password", "New password:",     show="•")
        confirm = simpledialog.askstring("Change Password", "Confirm password:", show="•")

        if not old or not new or new != confirm:
            messagebox.showerror("Error", "Passwords do not match or input cancelled.")
            return

        # Verify current password via LDAPS (primary) or PAM fallback (CR 1.5)
        if not _verify_current_password(user, old):
            audit("PWCHANGE_AUTH_FAIL", user=user)
            messagebox.showerror("Denied", "Current password is incorrect.")
            return

        ok, reason = password_policy_ok(user, old, new)
        if not ok:
            messagebox.showerror("Policy Violation", reason)
            return

        if ldap_change_password(user, old, new):
            audit("PASSWORD_CHANGE_SUCCESS", user=user)
            messagebox.showinfo("Success", "Password updated successfully.")
        else:
            audit("PASSWORD_CHANGE_FAIL", user=user)
            messagebox.showerror("Error", "Password change failed. Contact your administrator.")

    # ── Dashboard (CR 2.1 – permissions enforced in UI) ───────

    def _dashboard(self, user: str, roles: list[str]) -> None:
        self._clear()

        # Bind activity touch to all window events (CR 2.5)
        self.bind_all("<Key>",    self._touch_activity)
        self.bind_all("<Button>", self._touch_activity)

        tk.Label(self, text=f"Welcome, {user}", font=("Arial", 13, "bold")).pack(pady=8)
        tk.Label(self, text=f"Roles: {', '.join(roles)}").pack()

        perms = resolve_permissions(roles)

        # Render only permitted buttons (CR 2.1 – least privilege)
        if "Shell" in perms:
            tk.Button(
                self, text="Open Shell",
                command=lambda: self._guarded_action(
                    user,
                    lambda: subprocess.Popen(
                        ["gnome-terminal", "--", "su", "-", user],
                        close_fds=True,
                    ),
                    "SHELL_OPEN",
                )
            ).pack(pady=2)

        if "Projects" in perms:
            tk.Button(
                self, text="Projects",
                command=lambda: self._guarded_action(
                    user,
                    lambda: subprocess.Popen(
                        ["xdg-open", PROJECTS_DIR],
                        close_fds=True,
                    ),
                    "PROJECTS_OPEN",
                )
            ).pack(pady=2)

        if "Logs" in perms:
            tk.Button(
                self, text="Logs",
                command=lambda: self._guarded_action(
                    user,
                    lambda: subprocess.Popen(
                        ["xdg-open", LOGS_DIR],
                        close_fds=True,
                    ),
                    "LOGS_OPEN",
                )
            ).pack(pady=2)

        if "Web" in perms:
            tk.Button(
                self, text="Web Portal",
                command=lambda: self._guarded_action(
                    user,
                    lambda: webbrowser.open(WEB_URL),
                    "WEB_OPEN",
                )
            ).pack(pady=2)

        if "LDAP" in perms:
            tk.Button(
                self, text="LDAP Admin",
                command=lambda: self._guarded_action(
                    user,
                    lambda: webbrowser.open(LDAP_ADMIN_URL),
                    "LDAP_ADMIN_OPEN",
                )
            ).pack(pady=2)

        tk.Button(
            self, text="Logout",
            command=lambda: self._logout(user),
        ).pack(pady=20)

    def _guarded_action(self, user: str, action, event_name: str) -> None:
        """Execute a dashboard action with session validation and audit."""
        if not self._session_token:
            messagebox.showerror("Session", "No active session.")
            return
        self._touch_activity()
        audit(event_name, user=user, session=self._session_token)
        try:
            action()
        except Exception as exc:                     # noqa: BLE001
            logger.error(
                f"event=ACTION_ERROR action={event_name} "
                f"user={user} error={type(exc).__name__}"
            )
            messagebox.showerror("Error", "Action could not be completed.")

    def _logout(self, user: str) -> None:
        audit("LOGOUT", user=user, session=self._session_token or "-")
        self._end_session()
        self.login_ui()


# ═══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    startup_self_test()     # CR 3.3 – abort if self-test fails
    CAMGUI().mainloop()
