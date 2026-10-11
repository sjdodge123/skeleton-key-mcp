#!/usr/bin/env bash
# skeleton-key-pelican-host.sh — fixed-purpose root helper for Skeleton Key's
# Pelican panel-host tools (panel_version / panel_prepare_runtime / wings_update).
#
# WHY THIS EXISTS. A Pelican panel upgrade has host-level prerequisites that need
# root: switching the PHP runtime (new PHP release + php-fpm + the nginx socket)
# and updating the Wings daemon binary. Skeleton Key's SSH user must NOT get
# general sudo for that. Instead the owner installs THIS script once, root-owned
# and non-writable, and grants ONE NOPASSWD sudoers rule for it alone:
#
#   <ssh-user> ALL=(root) NOPASSWD: /usr/local/sbin/skeleton-key-pelican-host.sh
#
# Skeleton Key then runs `sudo -n /usr/local/sbin/skeleton-key-pelican-host.sh
# <subcommand> <arg>` and nothing else as root. The script accepts exactly three
# fixed subcommands, validates its single argument with a strict pattern before
# doing anything, never passes an argument to a shell unquoted, is idempotent,
# and refuses to run if it is not root-owned/non-writable (otherwise the sudoers
# rule would be a privilege escalation for whoever can edit it).
#
# INSTALL (as an admin on the panel host; see scripts/host/README.md):
#   sudo install -o root -g root -m 0755 skeleton-key-pelican-host.sh /usr/local/sbin/skeleton-key-pelican-host.sh
#   echo '<ssh-user> ALL=(root) NOPASSWD: /usr/local/sbin/skeleton-key-pelican-host.sh' \
#     | sudo tee /etc/sudoers.d/skeleton-key-pelican-host >/dev/null
#   sudo chmod 0440 /etc/sudoers.d/skeleton-key-pelican-host
#   sudo visudo -cf /etc/sudoers.d/skeleton-key-pelican-host
#
# SUBCOMMANDS
#   status                 Installed PHP versions, CLI default, active php-fpm units,
#                          the nginx fastcgi socket the panel site uses, Wings version
#                          and unit state. Read-only; key=value lines.
#   php-prepare <8.N>      Add ppa:ondrej/php if missing, install php<8.N> + the
#                          extensions Pelican needs, make it the CLI default, switch
#                          `fastcgi_pass unix:/run/php/php8.X-fpm.sock` ONLY in nginx
#                          files whose site root is PANEL_ROOT, `nginx -t`, then
#                          restart php<8.N>-fpm and nginx. Prints `php -v`.
#   wings-update <vTAG>    Download wings_linux_<arch> + checksums.txt for that
#                          GitHub release, verify the SHA-256, replace WINGS_BIN
#                          atomically (previous binary kept as .prev), restart the
#                          wings unit, roll back if it does not come up. Prints
#                          `wings version`.
# Anything else exits 2. Exit 1 = a step failed; exit 2 = refused (bad usage,
# bad argument, not root, integrity check).
#
# Debian/Ubuntu only (apt, update-alternatives, systemd, /run/php sockets).

set -euo pipefail
umask 022
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C

HELPER_VERSION=1

# --- Site-specific constants. Edit at install time if your layout differs. ------
# Only nginx files that mention this path get their fastcgi socket rewritten, so
# an unrelated server block (e.g. a reverse proxy in front of Wings) is never
# touched. Deliberately NOT overridable from the environment or arguments.
PANEL_ROOT=/var/www/pelican
WINGS_BIN=/usr/local/bin/wings
WINGS_UNIT=wings
NGINX_DIRS="/etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/conf.d"
# Extensions Pelican's install docs list; installed as php<ver>-<ext>.
PHP_EXTS="fpm cli gd mysql mbstring bcmath xml curl zip intl sqlite3"
WINGS_RELEASES=https://github.com/pelican-dev/wings/releases/download

ME=skeleton-key-pelican-host

log()    { echo "$ME: $*" >&2; }
die()    { echo "$ME: ERROR: $*" >&2; exit 1; }
refuse() { echo "$ME: REFUSED: $*" >&2; exit 2; }

usage() {
  cat >&2 <<USAGE
usage: $ME status
       $ME php-prepare <8.N>      (e.g. 8.4)
       $ME wings-update <vX.Y.Z[-pre]>   (e.g. v1.0.0-rc.1)
USAGE
  exit 2
}

require_root() {
  [ "$(id -u)" -eq 0 ] || refuse "must run as root (Skeleton Key invokes it via 'sudo -n')"
}

# The sudoers rule names this path, so this file must not be writable by anyone
# but root — otherwise editing it is a root shell. Checked on every privileged run.
require_self_integrity() {
  local self owner perms
  self=$(readlink -f -- "$0")
  owner=$(stat -c %u -- "$self")
  perms=$(stat -c %A -- "$self")
  [ "$owner" = "0" ] || refuse "$self is not owned by root"
  # %A is like -rwxr-xr-x: index 5 = group write, index 8 = other write.
  [ "${perms:5:1}" = "-" ] && [ "${perms:8:1}" = "-" ] || refuse "$self is group/world-writable"
}

# --- Shared probes --------------------------------------------------------------

# nginx config files (symlinks resolved, de-duplicated) that both mention
# PANEL_ROOT and carry a php-fpm fastcgi socket line. Newline-separated.
nginx_panel_sites() {
  local d f real
  for d in $NGINX_DIRS; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
      [ -f "$f" ] || continue
      real=$(readlink -f -- "$f") || continue
      grep -qF -- "$PANEL_ROOT" "$real" 2>/dev/null || continue
      grep -qE 'fastcgi_pass[[:space:]]+unix:/run/php/php[0-9]+\.[0-9]+-fpm\.sock' "$real" 2>/dev/null || continue
      echo "$real"
    done
  done | sort -u
}

# "1.0.0-beta22" from `wings version` ("wings v1.0.0-beta22" + a copyright line), or "".
wings_version() {
  [ -x "$WINGS_BIN" ] || { echo ""; return 0; }
  "$WINGS_BIN" version 2>/dev/null | head -n1 | sed -nE 's/^wings[[:space:]]+v?([^[:space:]]+).*$/\1/p' || true
}

php_cli_version() { php -r 'echo PHP_VERSION;' 2>/dev/null || true; }

# "8.3" from /etc/alternatives/php -> /usr/bin/php8.3, or "".
php_default_version() {
  local t
  t=$(readlink -f /etc/alternatives/php 2>/dev/null || true)
  case "$t" in */php[0-9]*) echo "${t##*/php}" ;; *) echo "" ;; esac
}

# Space-separated installed PHP versions, from the versioned CLI binaries.
php_installed_versions() {
  local b out=""
  for b in /usr/bin/php[0-9]*.[0-9]*; do
    [ -x "$b" ] || continue
    case "${b##*/php}" in *.*) out="$out ${b##*/php}" ;; esac
  done
  echo "${out# }"
}

unit_state() { systemctl is-active -- "$1" 2>/dev/null || true; }

# --- status ---------------------------------------------------------------------

cmd_status() {
  local v installed active="" sites site="" sock=""
  echo "helper=1"
  echo "helper_version=$HELPER_VERSION"
  echo "panel_root=$PANEL_ROOT"
  echo "php_cli=$(php_cli_version)"
  echo "php_default=$(php_default_version)"
  installed=$(php_installed_versions)
  echo "php_installed=$installed"
  for v in $installed; do
    [ "$(unit_state "php$v-fpm")" = "active" ] && active="$active $v"
  done
  echo "php_fpm_active=${active# }"
  sites=$(nginx_panel_sites)
  if [ -n "$sites" ]; then
    site=$(printf '%s\n' "$sites" | head -n1)
    sock=$(grep -hoE 'unix:/run/php/php[0-9]+\.[0-9]+-fpm\.sock' "$site" 2>/dev/null | head -n1 || true)
  fi
  echo "nginx_site=$site"
  echo "nginx_socket=${sock#unix:}"
  echo "nginx_active=$(unit_state nginx)"
  echo "wings=$(wings_version)"
  echo "wings_active=$(unit_state "$WINGS_UNIT")"
}

# --- php-prepare ----------------------------------------------------------------

cmd_php_prepare() {
  local ver=$1 pkgs ext sock sites f changed=() bak
  # Strict shape: 8.N (one or two digits). Nothing else is ever interpolated.
  printf '%s' "$ver" | grep -Eq '^8\.[0-9]{1,2}$' || refuse "php-prepare: version must look like 8.4 (got '$ver')"
  require_root
  require_self_integrity
  [ -d "$PANEL_ROOT" ] || refuse "php-prepare: panel root $PANEL_ROOT does not exist (edit PANEL_ROOT in $0 if the panel lives elsewhere)"

  sites=$(nginx_panel_sites)
  [ -n "$sites" ] || refuse "php-prepare: no nginx config under $NGINX_DIRS mentions $PANEL_ROOT with a php-fpm fastcgi socket line; nothing to switch"

  # 1. PPA (only if no apt source already carries ondrej/php).
  if ! grep -rqs 'ondrej/php' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
    log "adding ppa:ondrej/php"
    apt-get -q update
    apt-get -qy install software-properties-common
    add-apt-repository -y ppa:ondrej/php
  fi
  apt-get -q update

  # 2. PHP + extensions. Naming php<ver>-fpm in the SAME transaction is what keeps
  #    apt from satisfying the php<ver> metapackage with libapache2-mod-php.
  pkgs="php$ver"
  for ext in $PHP_EXTS; do pkgs="$pkgs php$ver-$ext"; done
  log "installing: $pkgs"
  # shellcheck disable=SC2086  # word-splitting the fixed package list is intended
  apt-get -qy install $pkgs

  # 3. CLI default — artisan/composer in the panel upgrade run plain `php`.
  update-alternatives --set php "/usr/bin/php$ver" >/dev/null

  # 4. nginx: rewrite the fastcgi socket line only in the panel's own site files.
  sock="/run/php/php$ver-fpm.sock"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if grep -qF -- "unix:$sock" "$f"; then
      log "$f already uses $sock"
      continue
    fi
    bak="$f.bak-skeleton-key"
    cp -p -- "$f" "$bak"
    sed -E -i "s#(fastcgi_pass[[:space:]]+unix:/run/php/php)[0-9]+\.[0-9]+(-fpm\.sock)#\1${ver}\2#g" -- "$f"
    changed+=("$f")
    log "switched fastcgi socket in $f (backup: $bak)"
  done <<< "$sites"

  if ! nginx -t 2>&1 | sed "s/^/$ME: nginx -t: /" >&2; then
    for f in "${changed[@]+"${changed[@]}"}"; do
      mv -f -- "$f.bak-skeleton-key" "$f"
      log "restored $f"
    done
    die "nginx -t failed after the socket switch; site files restored, nginx NOT restarted"
  fi

  # 5. Services. The old php-fpm is left installed and running as the rollback point.
  systemctl enable --now "php$ver-fpm" >/dev/null 2>&1 || true
  systemctl restart "php$ver-fpm"
  systemctl restart nginx

  log "done"
  php -v | head -n1
  cmd_status
}

# --- wings-update ---------------------------------------------------------------

rollback_wings() {
  if [ -f "$WINGS_BIN.prev" ]; then
    mv -f -- "$WINGS_BIN.prev" "$WINGS_BIN"
    systemctl restart "$WINGS_UNIT" || true
    log "rolled back to the previous wings binary"
  fi
}

cmd_wings_update() {
  local tag=$1 want current arch asset tmp expected actual mode
  printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9]+(\.[A-Za-z0-9]+)*)?$' \
    || refuse "wings-update: tag must look like v1.0.0-rc.1 (got '$tag')"
  [ "${#tag}" -le 40 ] || refuse "wings-update: tag too long"
  require_root
  require_self_integrity

  want=${tag#v}
  current=$(wings_version)
  if [ "$current" = "$want" ]; then
    log "wings is already $want"
    [ "$(unit_state "$WINGS_UNIT")" = "active" ] || systemctl restart "$WINGS_UNIT"
    cmd_status
    return 0
  fi

  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported architecture '$arch'" ;;
  esac
  asset="wings_linux_$arch"

  tmp=$(mktemp -d /tmp/skeleton-key-wings.XXXXXX)
  # shellcheck disable=SC2064  # expand $tmp now, on purpose
  trap "rm -r -f -- '$tmp'" EXIT

  log "downloading $tag/$asset"
  curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "$tmp/$asset" "$WINGS_RELEASES/$tag/$asset"
  curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "$tmp/checksums.txt" "$WINGS_RELEASES/$tag/checksums.txt"

  # checksums.txt lines are "<sha256>  <file>" (a leading '*' marks binary mode).
  expected=$(awk -v f="$asset" '{ n = $2; sub(/^\*/, "", n); if (n == f) print $1 }' "$tmp/checksums.txt" | head -n1)
  [ -n "$expected" ] || die "checksums.txt for $tag has no entry for $asset"
  actual=$(sha256sum -- "$tmp/$asset" | awk '{ print $1 }')
  [ "$expected" = "$actual" ] || die "SHA-256 mismatch for $asset (expected $expected, got $actual); nothing installed"
  log "checksum verified"

  chmod 0755 -- "$tmp/$asset"
  "$tmp/$asset" version >/dev/null 2>&1 || die "the downloaded binary does not run on this host; nothing installed"

  # Keep the existing mode (owners often leave wings 0700/0744) and swap atomically.
  mode=0755
  [ -e "$WINGS_BIN" ] && mode=$(stat -c %a -- "$WINGS_BIN")
  install -o root -g root -m "$mode" -- "$tmp/$asset" "$WINGS_BIN.new"
  [ -e "$WINGS_BIN" ] && cp -p -- "$WINGS_BIN" "$WINGS_BIN.prev"
  mv -f -- "$WINGS_BIN.new" "$WINGS_BIN"

  if ! systemctl restart "$WINGS_UNIT"; then
    rollback_wings
    die "wings unit failed to restart on $tag; rolled back"
  fi
  sleep 3
  if [ "$(unit_state "$WINGS_UNIT")" != "active" ]; then
    rollback_wings
    die "wings unit is not active after updating to $tag; rolled back"
  fi

  log "done"
  "$WINGS_BIN" version | head -n1
  cmd_status
}

# --- dispatch: fixed subcommands, exact arity, validation before privilege -------

[ "$#" -ge 1 ] || usage
case "$1" in
  status)
    [ "$#" -eq 1 ] || usage
    require_root
    cmd_status
    ;;
  php-prepare)
    [ "$#" -eq 2 ] || usage
    cmd_php_prepare "$2"
    ;;
  wings-update)
    [ "$#" -eq 2 ] || usage
    cmd_wings_update "$2"
    ;;
  *)
    usage
    ;;
esac
