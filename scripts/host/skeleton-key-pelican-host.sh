#!/usr/bin/env bash
# skeleton-key-pelican-host.sh — fixed-purpose root helper for Skeleton Key's
# Pelican panel-host tools (panel_version / panel_prepare_runtime / panel_upgrade /
# wings_update).
#
# WHY THIS EXISTS. Upgrading a Pelican panel is host-level work that needs root:
# switching the PHP runtime when a release raises the floor (new PHP + php-fpm +
# the nginx socket), the panel upgrade itself (artisan/composer as the panel
# user, permissions), and replacing the Wings daemon binary. Skeleton Key's SSH
# user must NOT get general sudo for that. Instead the owner installs THIS script
# once, root-owned and non-writable, and grants ONE NOPASSWD sudoers rule for it
# alone:
#
#   <ssh-user> ALL=(root) NOPASSWD: /usr/local/sbin/skeleton-key-pelican-host.sh
#
# Skeleton Key then runs `sudo -n /usr/local/sbin/skeleton-key-pelican-host.sh
# <subcommand> <args>` and nothing else as root. The script accepts exactly four
# fixed subcommands, validates every argument with a strict pattern before doing
# anything, never passes an argument to a shell unquoted, is idempotent, and
# refuses to run if it is not root-owned/non-writable (otherwise the sudoers rule
# would be a privilege escalation for whoever can edit it).
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
#   panel-upgrade <version> <vTAG> [--skip-backup]
#                          Upgrade the panel from exactly <version> (refused when
#                          config/app.php says otherwise) to release <vTAG>: download
#                          panel.tar.gz + checksum.txt and verify, run composer's
#                          platform check on the NEW lock file BEFORE maintenance
#                          mode, back up the database, then Pelican's documented
#                          sequence — artisan down, extract, permissions, composer
#                          install, migrate, optimize:clear, queue:restart, artisan
#                          up. artisan/composer/tar run as PANEL_USER, never root.
#                          Stops at the first failed step and reports it (and whether
#                          the panel was left in maintenance mode). Step output goes
#                          to LOG_DIR; stdout stays key=value.
#   wings-update <vTAG>    Download wings_linux_<arch> + checksums.txt for that
#                          GitHub release, verify the SHA-256, replace WINGS_BIN
#                          atomically (previous binary kept as .prev), restart the
#                          wings unit, roll back if it does not come up. Prints
#                          `wings version`.
# Anything else exits 2. Exit 1 = a step failed; exit 2 = refused (bad usage,
# bad argument, not root, integrity check, stale version).
#
# Debian/Ubuntu only (apt, update-alternatives, systemd, runuser, /run/php sockets).

set -euo pipefail
umask 022
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C

HELPER_VERSION=2

# --- Site-specific constants. Edit at install time if your layout differs. ------
# Only nginx files that mention this path get their fastcgi socket rewritten, so
# an unrelated server block (e.g. a reverse proxy in front of Wings) is never
# touched. Deliberately NOT overridable from the environment or arguments.
PANEL_ROOT=/var/www/pelican
# Unix user that owns the panel files; artisan/composer/tar run as this user so
# an upgrade cannot leave root-owned files the webserver can't write.
PANEL_USER=www-data
WINGS_BIN=/usr/local/bin/wings
WINGS_UNIT=wings
NGINX_DIRS="/etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/conf.d"
# Extensions Pelican's install docs list; installed as php<ver>-<ext>.
PHP_EXTS="fpm cli gd mysql mbstring bcmath xml curl zip intl sqlite3"
PANEL_RELEASES=https://github.com/pelican-dev/panel/releases/download
WINGS_RELEASES=https://github.com/pelican-dev/wings/releases/download
# Per-run step output for panel-upgrade (root-only); stdout over SSH stays key=value.
LOG_DIR=/var/log/skeleton-key

ME=skeleton-key-pelican-host
TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9]+(\.[A-Za-z0-9]+)*)?$'
VERSION_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9]+(\.[A-Za-z0-9]+)*)?$'

log()    { echo "$ME: $*" >&2; }
die()    { echo "$ME: ERROR: $*" >&2; exit 1; }
refuse() { echo "$ME: REFUSED: $*" >&2; exit 2; }

usage() {
  cat >&2 <<USAGE
usage: $ME status
       $ME php-prepare <8.N>                                  (e.g. 8.4)
       $ME panel-upgrade <version> <vX.Y.Z[-pre]> [--skip-backup]   (e.g. 1.0.0-beta35 v1.0.0-rc.1)
       $ME wings-update <vX.Y.Z[-pre]>                        (e.g. v1.0.0-rc.1)
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

# "1.0.0-beta35" from the panel's config/app.php, or "".
panel_installed_version() {
  sed -nE "s/^[[:space:]]*'version'[[:space:]]*=>[[:space:]]*'([^']+)'.*/\1/p" "$PANEL_ROOT/config/app.php" 2>/dev/null | head -n1 || true
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

# Run a command as the panel's unix user.
as_panel_user() { runuser -u "$PANEL_USER" -- "$@"; }

# verify_sha256 <file> <checksum-list> <asset-name>: lines are "<sha256>  <file>"
# (a leading '*' marks binary mode). Dies on a missing entry or a mismatch.
verify_sha256() {
  local expected actual
  expected=$(awk -v f="$3" '{ n = $2; sub(/^\*/, "", n); if (n == f) print $1 }' "$2" | head -n1)
  [ -n "$expected" ] || die "$(basename -- "$2") has no entry for $3; nothing installed"
  actual=$(sha256sum -- "$1" | awk '{ print $1 }')
  [ "$expected" = "$actual" ] || die "SHA-256 mismatch for $3 (expected $expected, got $actual); nothing installed"
  log "checksum verified for $3"
}

# --- status ---------------------------------------------------------------------

cmd_status() {
  local v installed active="" sites site="" sock=""
  echo "helper=1"
  echo "helper_version=$HELPER_VERSION"
  echo "panel_root=$PANEL_ROOT"
  echo "panel_version=$(panel_installed_version)"
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

# --- panel-upgrade --------------------------------------------------------------

UPGRADE_STEPS_DONE=""
UPGRADE_MAINTENANCE=0
UPGRADE_LOG=""

# step <name> <cmd...>: run one upgrade step with its output appended to the run
# log; on failure print the machine-readable state and stop. The log, not the SSH
# channel, gets the noisy output, so stdout stays key=value.
step() {
  local name=$1 rc=0
  shift
  log "step: $name"
  printf -- '--- %s step %s: %s\n' "$(date -Is)" "$name" "$*" >>"$UPGRADE_LOG"
  "$@" >>"$UPGRADE_LOG" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "failed_step=$name"
    echo "steps_done=${UPGRADE_STEPS_DONE# }"
    echo "maintenance=$UPGRADE_MAINTENANCE"
    tail -n 12 -- "$UPGRADE_LOG" | sed "s/^/$ME: $name: /" >&2
    die "step '$name' failed (exit $rc); full output in $UPGRADE_LOG"
  fi
  UPGRADE_STEPS_DONE="$UPGRADE_STEPS_DONE $name"
}

cmd_panel_upgrade() {
  local expect=$1 tag=$2 skip_backup=0 installed engine stamp backup="" tmp members
  printf '%s' "$expect" | grep -Eq "$VERSION_RE" || refuse "panel-upgrade: version must look like 1.0.0-beta35 (got '$expect')"
  printf '%s' "$tag" | grep -Eq "$TAG_RE" || refuse "panel-upgrade: tag must look like v1.0.0-rc.1 (got '$tag')"
  [ "${#expect}" -le 40 ] && [ "${#tag}" -le 40 ] || refuse "panel-upgrade: argument too long"
  if [ "$#" -eq 3 ]; then
    [ "$3" = "--skip-backup" ] || refuse "panel-upgrade: the only option is --skip-backup (got '$3')"
    skip_backup=1
  fi
  require_root
  require_self_integrity
  [ -f "$PANEL_ROOT/config/app.php" ] || refuse "panel-upgrade: no panel at $PANEL_ROOT (edit PANEL_ROOT in $0 if it lives elsewhere)"
  id -u "$PANEL_USER" >/dev/null 2>&1 || refuse "panel-upgrade: panel user '$PANEL_USER' does not exist (edit PANEL_USER in $0)"
  command -v composer >/dev/null 2>&1 || refuse "panel-upgrade: composer is not installed on this host"

  installed=$(panel_installed_version)
  [ -n "$installed" ] || die "could not read the installed version from $PANEL_ROOT/config/app.php"
  [ "$installed" = "$expect" ] || refuse "panel-upgrade: the panel is on '$installed', not '$expect' — stale picture, re-run panel_version"
  echo "panel_before=$installed"
  if [ "$installed" = "${tag#v}" ]; then
    log "panel is already $tag"
    echo "panel_after=$installed"
    echo "already_current=1"
    return 0
  fi

  mkdir -p "$LOG_DIR" && chmod 0750 "$LOG_DIR"
  UPGRADE_LOG="$LOG_DIR/panel-upgrade-$(date +%Y%m%d-%H%M%S).log"
  : >"$UPGRADE_LOG" && chmod 0640 "$UPGRADE_LOG"
  echo "upgrade_log=$UPGRADE_LOG"
  # A dropped SSH session must not kill a half-done upgrade: ignore SIGHUP and
  # finish; the caller re-reads the state with `status` / panel_version.
  trap '' HUP

  tmp=$(mktemp -d /tmp/skeleton-key-panel.XXXXXX)
  chmod 0755 "$tmp"
  # shellcheck disable=SC2064  # expand $tmp now, on purpose
  trap "rm -r -f -- '$tmp'" EXIT

  # 1. Download + verify, BEFORE anything touches the panel.
  step download-release curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "$tmp/panel.tar.gz" "$PANEL_RELEASES/$tag/panel.tar.gz"
  step download-checksum curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "$tmp/checksum.txt" "$PANEL_RELEASES/$tag/checksum.txt"
  verify_sha256 "$tmp/panel.tar.gz" "$tmp/checksum.txt" panel.tar.gz
  chmod 0644 -- "$tmp/panel.tar.gz"

  # 2. Platform pre-flight on the NEW release's lock file, still before maintenance
  #    mode: PHP version AND extensions. This is the check rc.1's PHP 8.4 floor needs.
  install -d -m 0755 "$tmp/preflight"
  install -d -o "$PANEL_USER" -g "$PANEL_USER" -m 0700 "$tmp/composer-cache"
  members=$(tar -tzf "$tmp/panel.tar.gz" | grep -E '^(\./)?composer\.(json|lock)$' || true)
  [ -n "$members" ] || die "panel.tar.gz for $tag contains no composer.json; refusing to continue"
  # shellcheck disable=SC2086  # the member list is newline/space separated names without spaces
  tar -xzf "$tmp/panel.tar.gz" -C "$tmp/preflight" $members
  chmod -R a+rX -- "$tmp/preflight"
  if [ -f "$tmp/preflight/composer.lock" ]; then
    step preflight-platform as_panel_user env COMPOSER_CACHE_DIR="$tmp/composer-cache" COMPOSER_NO_INTERACTION=1 \
      composer -d "$tmp/preflight" check-platform-reqs --lock --no-dev
  else
    log "WARNING: $tag ships no composer.lock; platform pre-flight skipped (the caller's PHP gate still applies)"
  fi

  # 3. Database backup — 'migrate' has no undo.
  if [ "$skip_backup" -eq 1 ]; then
    log "WARNING: database backup skipped on request"
    echo "db_backup=skipped"
  else
    engine=$(sed -nE 's/^DB_CONNECTION=["'"'"']?([A-Za-z]+).*/\1/p' "$PANEL_ROOT/.env" 2>/dev/null | head -n1 | tr '[:upper:]' '[:lower:]')
    stamp=$(date +%Y%m%d-%H%M%S)
    case "$engine" in
      sqlite)
        backup="$PANEL_ROOT/storage/pelican-db-backup-$stamp.sqlite"
        step db-backup as_panel_user cp -- "$PANEL_ROOT/database/database.sqlite" "$backup"
        ;;
      mysql|mariadb)
        backup="$PANEL_ROOT/storage/pelican-db-backup-$stamp.sql"
        # .env is sourced INSIDE the panel user's shell; the password reaches
        # mysqldump via MYSQL_PWD, never on a command line or in the run log.
        # shellcheck disable=SC2016  # the $vars are for the panel user's shell, on purpose
        step db-backup as_panel_user bash -c 'cd "$1" && set -a && . ./.env && set +a && MYSQL_PWD="$DB_PASSWORD" mysqldump --no-tablespaces -h "$DB_HOST" -P "${DB_PORT:-3306}" -u "$DB_USERNAME" "$DB_DATABASE" > "$2"' _ "$PANEL_ROOT" "$backup"
        ;;
      *)
        refuse "panel-upgrade: DB_CONNECTION='${engine:-unset}' in $PANEL_ROOT/.env — only sqlite, mysql and mariadb are handled, and 'migrate' has no undo"
        ;;
    esac
    echo "db_backup=$backup"
  fi

  # 4. Pelican's documented sequence. From here the panel is in maintenance mode
  #    until the last step; a failure leaves it there (reported) rather than
  #    serving half-upgraded code.
  step maintenance-mode as_panel_user php "$PANEL_ROOT/artisan" down
  UPGRADE_MAINTENANCE=1
  step extract as_panel_user tar -xzf "$tmp/panel.tar.gz" -C "$PANEL_ROOT"
  step fix-permissions chmod -R 755 -- "$PANEL_ROOT/storage" "$PANEL_ROOT/bootstrap/cache"
  step composer-install as_panel_user env COMPOSER_CACHE_DIR="$tmp/composer-cache" COMPOSER_NO_INTERACTION=1 \
    composer -d "$PANEL_ROOT" install --no-dev --optimize-autoloader
  step migrate as_panel_user php "$PANEL_ROOT/artisan" migrate --seed --force
  step clear-caches as_panel_user php "$PANEL_ROOT/artisan" optimize:clear
  step restart-queue as_panel_user php "$PANEL_ROOT/artisan" queue:restart
  step exit-maintenance as_panel_user php "$PANEL_ROOT/artisan" up
  UPGRADE_MAINTENANCE=0

  echo "steps_done=${UPGRADE_STEPS_DONE# }"
  echo "maintenance=0"
  echo "panel_after=$(panel_installed_version)"
  log "done"
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
  local tag=$1 want current arch asset tmp mode
  printf '%s' "$tag" | grep -Eq "$TAG_RE" || refuse "wings-update: tag must look like v1.0.0-rc.1 (got '$tag')"
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
  verify_sha256 "$tmp/$asset" "$tmp/checksums.txt" "$asset"

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
  panel-upgrade)
    [ "$#" -eq 3 ] || [ "$#" -eq 4 ] || usage
    shift
    cmd_panel_upgrade "$@"
    ;;
  wings-update)
    [ "$#" -eq 2 ] || usage
    cmd_wings_update "$2"
    ;;
  *)
    usage
    ;;
esac
