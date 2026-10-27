#!/bin/bash
# Provision (once) and run a deliberately vulnerable Samba AD DC. LAB USE ONLY.
set -e

REALM="REDLAB.LOCAL"
DOMAIN="REDLAB"
DCHOST="dc1"
ADMINPASS="Redlab123!"
MARKER="/var/lib/samba/.provisioned"

if [ ! -f "$MARKER" ]; then
  echo "[*] Provisioning Samba AD DC for ${REALM} ..."
  rm -f /etc/samba/smb.conf
  # The DC's own FQDN must resolve to its IP before provisioning (critical for Kerberos/DNS).
  IP="$(hostname -I | awk '{print $1}')"
  grep -q "${DCHOST}.redlab.local" /etc/hosts || echo "${IP} ${DCHOST}.redlab.local ${DCHOST}" >> /etc/hosts
  samba-tool domain provision \
    --use-rfc2307 --realm="$REALM" --domain="$DOMAIN" \
    --server-role=dc --dns-backend=SAMBA_INTERNAL \
    --option="dns forwarder=8.8.8.8" \
    --adminpass="$ADMINPASS" --host-name="$DCHOST"
  cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf

  echo "[*] Weakening password policy (vulnerable lab) ..."
  samba-tool domain passwordsettings set --complexity=off --min-pwd-length=4 \
    --history-length=0 --max-pwd-age=0 || true

  echo "[*] Creating users ..."
  samba-tool user create test 'monkey'      # AS-REP roastable (pre-auth disabled below)
  samba-tool user create svc_sql 'sunshine' # Kerberoastable (SPN added below)
  samba-tool user create j.doe 'password'   # low-priv authenticated user

  echo "[*] Adding SPN to svc_sql (Kerberoastable) ..."
  samba-tool spn add MSSQLSvc/dc1.redlab.local:1433 svc_sql || true

  echo "[*] Disabling Kerberos pre-auth on 'test' (AS-REP roastable) ..."
  ldbmodify -H /var/lib/samba/private/sam.ldb <<'LDIF' || true
dn: CN=test,CN=Users,DC=redlab,DC=local
changetype: modify
replace: userAccountControl
userAccountControl: 4194816
LDIF

  touch "$MARKER"
  echo "[*] Provisioning complete."
fi

[ -f /etc/krb5.conf ] || cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf

echo "[*] Starting Samba AD DC (foreground) ..."
exec samba -i
