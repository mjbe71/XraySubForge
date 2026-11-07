#!/usr/bin/env bash
# XraySubForge installer: asks a few questions and sets everything up (service, HTTPS, admin panel).
#
#   curl -fsSL https://raw.githubusercontent.com/mjbe71/XraySubForge/main/install.sh | sudo bash
#
# Afterwards:  sudo xraysubforge help
# Works on Debian/Ubuntu out of the box (packages are installed with apt); on other systems install
# python3 (with venv), git, curl and openssl yourself first.
set -euo pipefail

REPO_URL=${XSF_REPO:-https://github.com/mjbe71/XraySubForge}
BRANCH=${XSF_BRANCH:-main}
APP_DIR=${XSF_DIR:-/opt/xraysubforge}
CONF_DIR=${XSF_CONF_DIR:-/etc/xraysubforge}
BIN_DIR=${XSF_BIN_DIR:-/usr/local/bin}
UNIT_DIR=${XSF_UNIT_DIR:-/etc/systemd/system}
NO_SYSTEMD=${XSF_NO_SYSTEMD:-0}          # testing only
SVC_USER=xraysubforge
CONFIG="$CONF_DIR/config.json"
CERT_DIR="$CONF_DIR/certs"

CMD=install
YES=0 PANEL_URL="" PORT="" DOMAIN="" CERT="" KEY="" EMAIL="" PURGE=0
WANT_LE=0 NO_TLS=0 ADMIN=ask            # ask | yes | no

# ---------------------------------------------------------------- output helpers
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'; else B="" G="" Y="" R="" N=""; fi
say()  { printf '%s\n' "${B}==>${N} $*"; }
ok()   { printf '%s\n' "${G}✓${N} $*"; }
warn() { printf '%s\n' "${Y}!${N} $*" >&2; }
die()  { printf '%s\n' "${R}✗ $*${N}" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

TTY=""
{ : </dev/tty; } 2>/dev/null && TTY=/dev/tty
interactive() { [ -n "$TTY" ] && [ "$YES" != 1 ]; }

ask() {                                   # ask "question" "default" -> answer on stdout
  local a=""
  if interactive; then
    if [ -n "${2:-}" ]; then printf '%s [%s]: ' "$1" "$2" >&2; else printf '%s: ' "$1" >&2; fi
    IFS= read -r a <"$TTY" || a=""
  fi
  printf '%s' "${a:-${2:-}}"
}
yesno() {                                 # yesno "question" y|n -> status 0 = yes
  local d=${2:-y} a="" hint="Y/n"
  [ "$d" = n ] && hint="y/N"
  if ! interactive; then [ "$d" = y ]; return; fi
  printf '%s [%s]: ' "$1" "$hint" >&2
  IFS= read -r a <"$TTY" || a=""
  case "${a:-$d}" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}
usage() {
  cat <<EOF
XraySubForge installer

  install.sh [install|update|tls|uninstall|sync-certs] [options]

  install    first install (default); on an existing install it behaves like "update"
  update     get the newest version and restart (settings are kept)
  tls        (re)do the HTTPS step: use certificate files or get a Let's Encrypt one
  uninstall  remove the service and the program (settings are kept unless --purge)

Options (all are asked interactively when missing):
  --panel-url URL    JSON-subscription URL of your 3x-ui panel
  --domain NAME      domain for HTTPS, e.g. sub.example.com
  --cert FILE --key FILE   use these certificate files (fullchain + private key)
  --letsencrypt      get a free Let's Encrypt certificate for --domain
  --email ADDRESS    e-mail for Let's Encrypt (optional)
  --no-tls           plain HTTP on localhost only (e.g. behind your own reverse proxy)
  --port N           port to listen on
  --admin / --no-admin   enable the web admin panel (password: env XSF_ADMIN_PASSWORD, or asked)
  -y, --yes          never ask; use the given options and defaults
  --purge            with uninstall: also delete settings and certificates
EOF
}

parse_args() {
  if [ $# -gt 0 ]; then case "$1" in install|update|tls|uninstall|sync-certs) CMD=$1; shift ;; esac; fi
  while [ $# -gt 0 ]; do
    case "$1" in
      --panel-url) PANEL_URL=${2:?}; shift ;;
      --domain) DOMAIN=${2:?}; shift ;;
      --cert) CERT=${2:?}; shift ;;
      --key) KEY=${2:?}; shift ;;
      --email) EMAIL=${2:?}; shift ;;
      --port) PORT=${2:?}; shift ;;
      --letsencrypt) WANT_LE=1 ;;
      --no-tls) NO_TLS=1 ;;
      --admin) ADMIN=yes ;;
      --no-admin) ADMIN=no ;;
      --purge) PURGE=1 ;;
      -y|--yes) YES=1 ;;
      -h|--help|help) usage; exit 0 ;;
      *) die "Unknown option: $1 (try --help)" ;;
    esac
    shift
  done
}

# ---------------------------------------------------------------- system helpers
need_root() { [ "$(id -u)" = 0 ] || die "Please run as root:  curl -fsSL $REPO_URL/raw/$BRANCH/install.sh | sudo bash"; }

port_free() {                             # true if nothing listens on TCP port $1
  have ss || return 0
  ! ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$1\$"
}

ensure_prereqs() {
  local missing=()
  have python3 || missing+=(python3)
  python3 -c 'import venv, ensurepip' 2>/dev/null || missing+=(python3-venv)
  have git || [ -n "${XSF_SOURCE:-}" ] || missing+=(git)
  have curl || missing+=(curl)
  have openssl || missing+=(openssl)
  if [ ${#missing[@]} -gt 0 ]; then
    have apt-get || die "Missing: ${missing[*]}. Please install them (python3 with venv, git, curl, openssl) and run again."
    say "Installing system packages: ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates "${missing[@]}" >/dev/null
  fi
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || die "Python 3.9 or newer is required."
}

mf() { (cd "$APP_DIR" && XRAYSUBFORGE_CONFIG="$CONFIG" "$APP_DIR/venv/bin/python" -m xraysubforge "$@"); }

fix_config_owner() {
  [ -f "$CONFIG" ] || return 0
  chown "$SVC_USER:$SVC_USER" "$CONFIG"
  chmod 600 "$CONFIG"
}

fetch_code() {
  if [ -n "${XSF_SOURCE:-}" ]; then          # testing: copy from a local folder
    mkdir -p "$APP_DIR"; cp -a "$XSF_SOURCE/." "$APP_DIR/"; rm -rf "$APP_DIR/.git"
  elif [ -d "$APP_DIR/.git" ]; then
    say "Updating the program"
    git -C "$APP_DIR" -c safe.directory="$APP_DIR" fetch --quiet --depth 1 origin "$BRANCH"
    git -C "$APP_DIR" -c safe.directory="$APP_DIR" reset --quiet --hard FETCH_HEAD
  else
    [ -z "$(ls -A "$APP_DIR" 2>/dev/null || true)" ] || die "$APP_DIR exists and is not a XraySubForge install; move it away first."
    say "Downloading XraySubForge"
    git clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
  fi
}

setup_venv() {
  if [ ! -x "$APP_DIR/venv/bin/python" ]; then
    say "Creating the Python environment"
    if [ "${XSF_SKIP_PIP:-0}" = 1 ]; then python3 -m venv --system-site-packages "$APP_DIR/venv"; else python3 -m venv "$APP_DIR/venv"; fi
  fi
  if [ "${XSF_SKIP_PIP:-0}" != 1 ]; then
    say "Installing Python packages"
    "$APP_DIR/venv/bin/pip" install --quiet --disable-pip-version-check -r "$APP_DIR/requirements.txt"
  fi
}

setup_user_dirs() {
  id "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
  install -d -m 750 -o "$SVC_USER" -g "$SVC_USER" "$CONF_DIR" "$CERT_DIR"
  chown -R root:root "$APP_DIR"
}

# ---------------------------------------------------------------- certificates
cert_covers() {                           # does certificate $1 cover domain $2?
  local names n d=${2,,}
  names=$(openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/.*DNS: *//p' | tr -d ' ' || true)
  [ -n "$names" ] || names=$(openssl x509 -in "$1" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *//p' || true)
  for n in $names; do
    n=${n,,}
    case "$n" in
      \*.*) [ "${d#*.}" = "${n#*.}" ] && return 0 ;;
      *) [ "$n" = "$d" ] && return 0 ;;
    esac
  done
  return 1
}

check_cert() {                            # check_cert cert key [domain]: 0 ok, 1 unusable, 2 valid but wrong domain
  local c=$1 k=$2 d=${3:-} a b
  [ -r "$c" ] || { warn "Cannot read $c"; return 1; }
  [ -r "$k" ] || { warn "Cannot read $k"; return 1; }
  openssl x509 -in "$c" -noout 2>/dev/null || { warn "$c is not a certificate file"; return 1; }
  openssl x509 -in "$c" -noout -checkend 86400 >/dev/null || { warn "The certificate in $c has expired"; return 1; }
  a=$(openssl x509 -in "$c" -noout -pubkey 2>/dev/null | openssl md5 2>/dev/null || true)
  b=$(openssl pkey -in "$k" -pubout -passin pass: </dev/null 2>/dev/null | openssl md5 2>/dev/null || true)
  [ -n "$a" ] && [ "$a" = "$b" ] || { warn "The private key $k does not belong to $c (or is password protected)"; return 1; }
  if [ -n "$d" ] && ! cert_covers "$c" "$d"; then warn "The certificate in $c does not cover $d"; return 2; fi
  return 0
}

set_cert_source() { printf '%s\n%s\n' "$1" "$2" >"$CERT_DIR/source"; chmod 600 "$CERT_DIR/source"; }

sync_certs() {                            # copy the recorded certificate into $CERT_DIR (readable by the service user)
  [ -f "$CERT_DIR/source" ] || { warn "No certificate recorded; nothing to sync."; return 0; }
  local sc sk changed=0
  sc=$(sed -n 1p "$CERT_DIR/source"); sk=$(sed -n 2p "$CERT_DIR/source")
  [ -r "$sc" ] && [ -r "$sk" ] || { warn "Cannot read the certificate files $sc / $sk"; return 1; }
  if ! cmp -s "$sc" "$CERT_DIR/fullchain.pem" 2>/dev/null || ! cmp -s "$sk" "$CERT_DIR/privkey.pem" 2>/dev/null; then
    check_cert "$sc" "$sk" || [ $? = 2 ] || { warn "The new certificate looks unusable; keeping the old one."; return 1; }
    install -m 600 -o "$SVC_USER" -g "$SVC_USER" "$sc" "$CERT_DIR/fullchain.pem.new"
    install -m 600 -o "$SVC_USER" -g "$SVC_USER" "$sk" "$CERT_DIR/privkey.pem.new"
    mv -f "$CERT_DIR/fullchain.pem.new" "$CERT_DIR/fullchain.pem"
    mv -f "$CERT_DIR/privkey.pem.new" "$CERT_DIR/privkey.pem"
    changed=1; ok "Certificate copied for the service"
  fi
  if [ "$changed" = 1 ] && [ "$NO_SYSTEMD" != 1 ] && systemctl is-active --quiet xraysubforge 2>/dev/null; then
    systemctl restart xraysubforge && ok "Service restarted with the new certificate"
  fi
  return 0
}

issue_letsencrypt() {                     # issue_letsencrypt domain email
  local domain=$1 email=${2:-} ip mine
  if ! have certbot; then
    have apt-get || { warn "certbot is not installed; install it (https://certbot.eff.org) or give certificate files."; return 1; }
    say "Installing certbot"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null || return 1
  fi
  ip=$(getent ahostsv4 "$domain" 2>/dev/null | awk 'NR==1{print $1}' || true)
  mine=$(curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)
  if [ -z "$ip" ]; then
    warn "$domain does not resolve yet. Create a DNS A record pointing to this server first."
    return 1
  elif [ -n "$mine" ] && [ "$ip" != "$mine" ]; then
    warn "$domain points to $ip but this server's address looks like $mine."
    yesno "Try anyway?" n || return 1
  fi
  if ! port_free 80; then
    warn "Port 80 is in use. Let's Encrypt needs it for a minute (and again at each renewal)."
    warn "Stop whatever uses it (for example nginx) and run:  sudo xraysubforge tls"
    return 1
  fi
  local args=(certonly --standalone --preferred-challenges http -d "$domain" --non-interactive --agree-tos
              --deploy-hook "$APP_DIR/install.sh sync-certs")
  if [ -n "$email" ]; then args+=(-m "$email"); else args+=(--register-unsafely-without-email); fi
  say "Asking Let's Encrypt for a certificate for $domain"
  set_cert_source "/etc/letsencrypt/live/$domain/fullchain.pem" "/etc/letsencrypt/live/$domain/privkey.pem"
  certbot "${args[@]}" || { rm -f "$CERT_DIR/source"; warn "Let's Encrypt refused or failed (see the messages above)."; return 1; }
}

step_tls() {                              # decides HTTPS; sets TLS_OK=1 when certificate files are in place
  TLS_OK=0
  [ "$NO_TLS" = 1 ] && return 0
  if [ -z "$DOMAIN" ]; then
    if interactive; then
      echo >&2
      say "HTTPS: users should reach the subscription over a domain name that points to this server."
      DOMAIN=$(ask "Domain for the subscription link (e.g. sub.example.com), or press Enter for plain HTTP on localhost" "")
    fi
  fi
  [ -n "$DOMAIN" ] || return 0
  DOMAIN=${DOMAIN,,}

  # 1) certificate files given by the user
  if [ -z "$CERT" ] && interactive; then
    CERT=$(ask "Path of your certificate file (fullchain), or press Enter to look for one / get a free one" "")
    [ -z "$CERT" ] || KEY=$(ask "Path of the private key file" "")
  fi
  if [ -n "$CERT" ]; then
    [ -n "$KEY" ] || die "--cert needs --key"
    local rc=0; check_cert "$CERT" "$KEY" "$DOMAIN" || rc=$?
    if [ $rc = 0 ] || { [ $rc = 2 ] && yesno "Use it anyway?" n; }; then set_cert_source "$CERT" "$KEY"; sync_certs; TLS_OK=1; return 0; fi
    interactive || die "The given certificate cannot be used."
  fi

  # 2) a certificate that already exists on this machine (3x-ui / x-ui / acme.sh / certbot ...)
  if [ "$WANT_LE" != 1 ] && [ -x "$APP_DIR/venv/bin/python" ]; then
    local c k covers days names rc others=""
    while IFS=$'\t' read -r c k covers days names; do
      [ -n "$c" ] || continue
      if [ "$covers" = yes ] && [ -n "$k" ]; then
        rc=0; check_cert "$c" "$k" "$DOMAIN" >/dev/null 2>&1 || rc=$?
        if [ $rc = 0 ]; then
          ok "Found a valid certificate for $DOMAIN: $c (${days:-?} days left)"
          if yesno "Use it?" y; then set_cert_source "$c" "$k"; sync_certs; TLS_OK=1; return 0; fi
          continue
        fi
        others="$others\n    $c  [covers $DOMAIN but is not usable: expired or its key does not match]"
      else
        others="$others\n    $c  [for: ${names:-?}$([ -n "$k" ] || echo "; no matching private key found")]"
      fi
    done < <(mf detect-xui --scan "$DOMAIN" 2>/dev/null || true)
    if [ -n "$others" ]; then
      echo >&2
      say "Certificates found on this machine that cannot be used for $DOMAIN:"
      printf '%b\n' "$others" | head -n 12 >&2
      if interactive; then
        CERT=$(ask "Path of the certificate to use instead (fullchain), or press Enter to continue" "")
        if [ -n "$CERT" ]; then
          KEY=$(ask "Path of its private key" "")
          rc=0; check_cert "$CERT" "$KEY" "$DOMAIN" || rc=$?
          if [ $rc = 0 ] || { [ $rc = 2 ] && yesno "Use it anyway?" n; }; then set_cert_source "$CERT" "$KEY"; sync_certs; TLS_OK=1; return 0; fi
        fi
      fi
    else
      interactive && say "No existing certificate found on this machine."
    fi
  fi

  # 3) a new certificate from Let's Encrypt
  if [ "$WANT_LE" = 1 ] || yesno "Get a free Let's Encrypt certificate for $DOMAIN now? (the domain must already point to this server)" y; then
    [ -z "$EMAIL" ] && EMAIL=$(ask "E-mail for expiry notices (optional)" "")
    if issue_letsencrypt "$DOMAIN" "$EMAIL"; then sync_certs; TLS_OK=1; return 0; fi
  fi
  [ "$YES" != 1 ] || die "Could not set up HTTPS for $DOMAIN."
  warn "Continuing without HTTPS. Run  sudo xraysubforge tls  when you are ready."
}

# ---------------------------------------------------------------- configuration
suggest_panel() {
  SUGGEST_URL="" SUGGEST_VERIFY=true
  local line
  line=$(mf detect-xui --suggest 2>/dev/null || true)
  if [ -n "$line" ]; then SUGGEST_URL=${line%%$'\t'*}; SUGGEST_VERIFY=${line##*$'\t'}; fi
}

step_panel() {
  suggest_panel
  EXISTING_URL=$(mf config-get panel.url 2>/dev/null || true)       # from an interrupted earlier run
  if [ -z "$PANEL_URL" ]; then
    if [ -n "$SUGGEST_URL" ]; then ok "Found a 3x-ui panel on this server."; fi
    interactive && echo "The panel's JSON-subscription address (see your 3x-ui settings; the user's id is added at the end)." >&2
    PANEL_URL=$(ask "Panel JSON-subscription URL" "${EXISTING_URL:-$SUGGEST_URL}")
  fi
  [ -n "$PANEL_URL" ] || die "A panel URL is required (use --panel-url)."
  case "$PANEL_URL" in http://*|https://*) ;; *) die "The panel URL must start with http:// or https://" ;; esac
  local verify=true
  [ "$PANEL_URL" = "$SUGGEST_URL" ] && verify=$SUGGEST_VERIFY
  local code
  code=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' "$PANEL_URL" 2>/dev/null || true)
  if [ -z "$code" ] || [ "$code" = 000 ]; then warn "Could not reach $PANEL_URL from here (check the address and the firewall); continuing."; else ok "The panel answered (HTTP $code)."; fi
  mf config-set "panel.url=$PANEL_URL" "panel.verify_tls=$verify"
}

step_listen() {
  local def
  if [ "$TLS_OK" = 1 ]; then def=443; port_free 443 || def=8443; else def=8080; fi
  if [ -z "$PORT" ]; then
    PORT=$(ask "Port to listen on" "$def")
  fi
  case "$PORT" in ''|*[!0-9]*) die "Port must be a number." ;; esac
  { [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; } || die "Port must be between 1 and 65535."
  if systemctl is-active --quiet xraysubforge 2>/dev/null; then :; elif ! port_free "$PORT"; then
    warn "Port $PORT is already in use."; interactive && PORT=$(ask "Another port" "$((PORT + 1))")
    port_free "$PORT" || die "Port $PORT is in use."
  fi
  if [ "$TLS_OK" = 1 ]; then
    mf config-set server.host=0.0.0.0 "server.port=$PORT" "server.tls_cert=$CERT_DIR/fullchain.pem" "server.tls_key=$CERT_DIR/privkey.pem"
  else
    mf config-set server.host=127.0.0.1 "server.port=$PORT"
    mf config-set --unset server.tls_cert server.tls_key
  fi
}

step_admin() {
  [ "$ADMIN" = no ] && return 0
  local have_hash
  have_hash=$(mf config-get admin.password_hash 2>/dev/null || true)
  if [ -n "$have_hash" ]; then ADMIN_ON=1; return 0; fi
  if [ "$ADMIN" = ask ]; then
    interactive || return 0
    echo >&2
    [ "$TLS_OK" = 1 ] && echo "The admin panel would be reachable on the same address as the subscription (/admin), protected by the password." >&2
    yesno "Enable the web admin panel (edit rules in the browser)?" y || return 0
  fi
  local pw=${XSF_ADMIN_PASSWORD:-} pw2
  if [ -z "$pw" ]; then
    interactive || die "Set XSF_ADMIN_PASSWORD to use --admin without questions."
    warn "The password is shown on screen while you type it (so you can see typos). Make sure nobody is watching."
    while :; do
      pw=$(ask "Choose an admin password (at least 8 characters)" "")
      [ "${#pw}" -ge 8 ] || { warn "Too short; try again."; continue; }
      break
    done
  fi
  printf '%s\n' "$pw" | mf set-admin-password --stdin >/dev/null && ADMIN_ON=1
}

# ---------------------------------------------------------------- service files
write_service_files() {
  cat >"$BIN_DIR/xraysubforge" <<EOF
#!/bin/sh
# Manage XraySubForge. Run "xraysubforge help".
export XRAYSUBFORGE_CONFIG="$CONFIG"
export XSF_CTL="$BIN_DIR/xraysubforge"
if [ -z "\$1" ] && [ -t 0 ]; then set -- menu; fi
case "\${1:-help}" in
  update|tls|uninstall|sync-certs) exec "$APP_DIR/install.sh" "\$@" ;;
  status)  exec systemctl status xraysubforge ;;
  restart) exec systemctl restart xraysubforge ;;
  stop)    exec systemctl stop xraysubforge ;;
  start)   exec systemctl start xraysubforge ;;
  logs)    exec journalctl -u xraysubforge -n 100 -f ;;
  help|-h|--help)
    cat <<'TXT'
xraysubforge                         interactive menu (everything below, and more)
xraysubforge status | start | stop | restart | logs
xraysubforge update                  get the newest version
xraysubforge tls                     set up or change HTTPS (certificate files or Let's Encrypt)
xraysubforge set-admin-password      set or change the admin password
xraysubforge config-set KEY=VALUE    change a setting (e.g. server.port=8443)
xraysubforge check                   validate the configuration
xraysubforge uninstall [--purge]       remove it (also in the menu)
TXT
    ;;
  *) cd "$APP_DIR" && exec "$APP_DIR/venv/bin/python" -m xraysubforge "\$@" ;;
esac
EOF
  chmod 755 "$BIN_DIR/xraysubforge"
  [ "$NO_SYSTEMD" = 1 ] && return 0
  cat >"$UNIT_DIR/xraysubforge.service" <<EOF
[Unit]
Description=XraySubForge subscription proxy
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$APP_DIR
Environment=XRAYSUBFORGE_CONFIG=$CONFIG
ExecStart=$APP_DIR/venv/bin/gunicorn app:app
Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$CONF_DIR

[Install]
WantedBy=multi-user.target
EOF
  cat >"$UNIT_DIR/xraysubforge-certsync.service" <<EOF
[Unit]
Description=XraySubForge: copy a renewed HTTPS certificate

[Service]
Type=oneshot
ExecStart=$APP_DIR/install.sh sync-certs
EOF
  cat >"$UNIT_DIR/xraysubforge-certsync.timer" <<EOF
[Unit]
Description=XraySubForge: daily certificate check

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
}

start_service() {
  [ "$NO_SYSTEMD" = 1 ] && { warn "Skipping the service (XSF_NO_SYSTEMD)."; return 0; }
  systemctl enable --quiet xraysubforge >/dev/null 2>&1 || true
  systemctl enable --quiet --now xraysubforge-certsync.timer >/dev/null 2>&1 || true
  systemctl restart xraysubforge
  local scheme=http port i
  port=$(mf config-get server.port 2>/dev/null || echo 8080)
  [ -n "$(mf config-get server.tls_cert 2>/dev/null || true)" ] && scheme=https
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsk --max-time 3 "$scheme://127.0.0.1:$port/healthz" >/dev/null 2>&1; then ok "The service is running."; return 0; fi
    sleep 1
  done
  warn "The service did not answer yet. Look at:  sudo xraysubforge logs"
  return 1
}

summary() {
  local port scheme=http host route tlsc
  port=$(mf config-get server.port 2>/dev/null || echo 8080)
  route=$(mf config-get server.route 2>/dev/null || echo /sub/)
  tlsc=$(mf config-get server.tls_cert 2>/dev/null || true)
  [ -n "$tlsc" ] && scheme=https
  host=${DOMAIN:-127.0.0.1}
  if [ -z "$DOMAIN" ] && [ -n "$tlsc" ]; then host="your-domain"; fi
  local shown=":$port"
  { [ "$scheme" = https ] && [ "$port" = 443 ]; } && shown=""
  { [ "$scheme" = http ] && [ "$port" = 80 ]; } && shown=""
  echo
  say "${G}Done.${N}"
  echo "  Subscription link:  $scheme://$host$shown${route%/}/<subscription id>"
  if [ "${ADMIN_ON:-0}" = 1 ]; then
    if [ -n "$tlsc" ]; then echo "  Admin panel:        $scheme://$host$shown/admin"
    else echo "  Admin panel:        $scheme://127.0.0.1:$port/admin   (from your computer: ssh -L $port:127.0.0.1:$port user@this-server)"; fi
  fi
  echo "  Manage:             sudo xraysubforge help"
  if [ -z "$tlsc" ]; then
    echo
    warn "The service listens on localhost only and without HTTPS. For users on the internet run:  sudo xraysubforge tls"
  elif have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
    echo
    warn "A firewall (ufw) is active. Open the port:  sudo ufw allow $port/tcp"
  fi
}

# ---------------------------------------------------------------- commands
do_install() {
  need_root
  local existed=0
  # "installed" means the LAST step ran (it writes the `xraysubforge` command); a run that was interrupted earlier has
  # left a config and program files behind but no command, and must be continued, not mistaken for a finished install
  [ -f "$CONFIG" ] && [ -d "$APP_DIR" ] && [ -x "$BIN_DIR/xraysubforge" ] && existed=1
  if [ "$existed" = 0 ] && { [ -f "$CONFIG" ] || [ -d "$APP_DIR" ]; }; then
    warn "A previous installation was not finished. Continuing it."
  fi
  say "XraySubForge installer"
  ensure_prereqs
  fetch_code
  setup_venv
  setup_user_dirs
  if [ "$existed" = 1 ]; then
    ok "Already installed: updating (your settings are kept)."
    write_service_files; fix_config_owner; start_service; return 0
  fi
  [ -f "$CONFIG" ] || printf '{}\n' >"$CONFIG"
  fix_config_owner
  step_panel
  step_tls
  step_listen
  step_admin
  fix_config_owner
  write_service_files
  start_service || true
  summary
}

do_update() {
  need_root
  [ -d "$APP_DIR" ] || die "Not installed yet (no $APP_DIR). Run the install first."
  ensure_prereqs
  fetch_code
  setup_venv
  setup_user_dirs
  write_service_files
  fix_config_owner
  start_service || true
  ok "Updated."
}

do_tls() {
  need_root
  [ -f "$CONFIG" ] || die "Not installed yet. Run the install first."
  [ -f "$CERT_DIR/source" ] && : # an earlier source is simply replaced below
  step_tls
  step_listen
  fix_config_owner
  start_service || true
  summary
}

do_uninstall() {
  need_root
  if interactive; then
    yesno "Remove XraySubForge$([ "$PURGE" = 1 ] && echo ' AND its settings/certificates')?" n || { echo "Nothing removed."; return 0; }
  elif [ "$YES" != 1 ]; then
    die "Add --yes to uninstall without questions."
  fi
  if [ "$NO_SYSTEMD" != 1 ]; then
    systemctl disable --now xraysubforge xraysubforge-certsync.timer >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR"/xraysubforge.service "$UNIT_DIR"/xraysubforge-certsync.service "$UNIT_DIR"/xraysubforge-certsync.timer
    systemctl daemon-reload || true
  fi
  # a certbot renewal that still calls our (now deleted) sync script would report an error on every renewal
  local f
  for f in /etc/letsencrypt/renewal/*.conf; do
    [ -f "$f" ] && grep -q "$APP_DIR/install.sh" "$f" 2>/dev/null && sed -i "\#$APP_DIR/install.sh#d" "$f" || true
  done
  rm -f "$BIN_DIR/xraysubforge"
  rm -rf "$APP_DIR"
  if [ "$PURGE" = 1 ]; then rm -rf "$CONF_DIR"; id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" || true; fi
  ok "Removed.$([ "$PURGE" = 1 ] || echo " Settings are still in $CONF_DIR (use --purge to delete them).") Certificates issued by certbot stay in /etc/letsencrypt."
}

main() {
  parse_args "$@"
  case "$CMD" in
    install) do_install ;;
    update) do_update ;;
    tls) do_tls ;;
    uninstall) do_uninstall ;;
    sync-certs) need_root; sync_certs ;;
  esac
}

main "$@"
