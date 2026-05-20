#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════
#  CAM Secure Access — Host System Configuration Installer
#  Installs PAM, SSSD, and RADIUS client config onto the host.
#  Run from repo root: chmod +x install-system-config.sh
#                      sudo ./install-system-config.sh
# ══════════════════════════════════════════════════════════════════════════
set -e
REPO="$(cd "$(dirname "$0")" && pwd)"

echo "================================================"
echo " CAM Secure Access — Host System Config Installer"
echo "================================================"

# ── 1. Packages ───────────────────────────────────────────────────────────
echo "→ Installing packages..."
apt-get update -q
apt-get install -y libpam-radius-auth sssd sssd-ldap libpam-sss libnss-sss
echo "   done"

# ── 2. PAM files ──────────────────────────────────────────────────────────
echo "→ Installing PAM service files..."
cp "$REPO/system-config/pam.d/cam-gui-radius" /etc/pam.d/cam-gui-radius
cp "$REPO/system-config/pam.d/cam-gui"        /etc/pam.d/cam-gui
chmod 644 /etc/pam.d/cam-gui-radius /etc/pam.d/cam-gui
echo "   /etc/pam.d/cam-gui-radius"
echo "   /etc/pam.d/cam-gui"

# ── 3. RADIUS client ──────────────────────────────────────────────────────
echo "→ Installing RADIUS client config..."
cp "$REPO/system-config/radius/pam_radius_auth.conf" /etc/pam_radius_auth.conf
chmod 600 /etc/pam_radius_auth.conf
echo "   /etc/pam_radius_auth.conf"

# ── 4. SSSD ───────────────────────────────────────────────────────────────
echo "→ Installing SSSD config..."
cp "$REPO/system-config/sssd/sssd.conf" /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
chown root:root /etc/sssd/sssd.conf

# Substitute LDAP password from .env if available
if [ -f "$REPO/.env" ]; then
    PASS=$(grep ^LDAP_ADMIN_PASSWORD "$REPO/.env" | cut -d= -f2-)
    [ -n "$PASS" ] && sed -i "s|ldap_default_authtok = .*|ldap_default_authtok = $PASS|" /etc/sssd/sssd.conf
fi
echo "   /etc/sssd/sssd.conf"

# ── 5. Service credential for Flask app ───────────────────────────────────
echo "→ Creating service credential file..."
mkdir -p /etc/cam
if [ -f "$REPO/.env" ]; then
    PASS=$(grep ^LDAP_ADMIN_PASSWORD "$REPO/.env" | cut -d= -f2-)
    echo "$PASS" > /etc/cam/svc_bind.secret
else
    echo "welcome123#" > /etc/cam/svc_bind.secret
fi
chown root:"$(logname 2>/dev/null || echo abb)" /etc/cam/svc_bind.secret
chmod 640 /etc/cam/svc_bind.secret
echo "   /etc/cam/svc_bind.secret"

# ── 6. Log directory ──────────────────────────────────────────────────────
echo "→ Creating log directory..."
mkdir -p /var/log/cam_gui
chown "$(logname 2>/dev/null || echo abb)":"$(logname 2>/dev/null || echo abb)" /var/log/cam_gui
echo "   /var/log/cam_gui"

# ── 7. Restart SSSD ───────────────────────────────────────────────────────
echo "→ Restarting SSSD..."
systemctl enable sssd && systemctl restart sssd
sleep 2
systemctl is-active sssd && echo "   sssd: running ✓" || echo "   sssd: check journalctl -u sssd"

echo ""
echo "================================================"
echo " Done. Now run the web app:"
echo "   cd cam_web && python3 app.py"
echo "================================================"
