# Panel-host helper for Pelican (`skeleton-key-pelican-host.sh`)

Skeleton Key's Pelican tools `panel_version`, `panel_prepare_runtime`, `panel_upgrade` and `wings_update` need root on the **panel host**: switching the PHP runtime when a panel release raises the PHP floor, running the panel upgrade itself (artisan/composer as the panel user, permissions), and replacing the Wings daemon binary. Skeleton Key's SSH user must **not** get general sudo for that. Instead you install this one script, root-owned and non-writable, and grant **one** passwordless sudoers rule for it alone. That rule is the whole root grant: the script accepts exactly four fixed subcommands, validates every argument with a strict pattern before doing anything, never passes an argument to a shell unquoted, is idempotent, and refuses to run if it is not root-owned/non-writable.

Nothing here is installed automatically. Skeleton Key never writes to `/usr/local/sbin` or `/etc/sudoers.d`; when the helper or the rule is missing, the tools stop and print these steps.

## One-time install (as an admin on the panel host)

1. Copy `scripts/host/skeleton-key-pelican-host.sh` from this repo to the panel host (e.g. `scp` it to your admin user's home there).
2. If the panel is not at `/var/www/pelican` owned by `www-data`, or Wings is not `/usr/local/bin/wings` / unit `wings`, edit the constants at the top of the script **before** installing it (`PANEL_ROOT`, `PANEL_USER`, `WINGS_BIN`, `WINGS_UNIT`). They are deliberately not overridable at run time.
3. Install it root-owned and non-writable:

   ```bash
   sudo install -o root -g root -m 0755 skeleton-key-pelican-host.sh /usr/local/sbin/skeleton-key-pelican-host.sh
   ```

4. Grant Skeleton Key's SSH user (the `username` of the ssh target's vault credential — replace `<ssh-user>` with it, literally) passwordless sudo for **that script only**:

   ```bash
   echo '<ssh-user> ALL=(root) NOPASSWD: /usr/local/sbin/skeleton-key-pelican-host.sh' | sudo tee /etc/sudoers.d/skeleton-key-pelican-host >/dev/null && sudo chmod 0440 /etc/sudoers.d/skeleton-key-pelican-host && sudo visudo -cf /etc/sudoers.d/skeleton-key-pelican-host
   ```

   `visudo -cf` must print `parsed OK`. If it reports a syntax error, re-run the command with the placeholder replaced; a broken drop-in grants nothing.

5. Check it from the SSH user's side (or just run `panel_version` from Skeleton Key — its "Host helper:" line says whether the rule works):

   ```bash
   sudo -n /usr/local/sbin/skeleton-key-pelican-host.sh status
   ```

The Pelican target itself needs its `sshTarget` option pointing at the registered **ssh** target for this host (`update_target`).

## What each subcommand does

| Subcommand | Effect |
|---|---|
| `status` | Read-only. Prints `key=value` lines: panel version, installed PHP versions, the `php` CLI default, active `php*-fpm` units, the `fastcgi_pass` socket the panel's nginx site uses, Wings version and unit state. Runs as root because `wings version` is root-only on a typical install. |
| `php-prepare <8.N>` | Adds `ppa:ondrej/php` if no apt source has it; installs `php8.N` plus `fpm cli gd mysql mbstring bcmath xml curl zip intl sqlite3` in one apt transaction (naming `-fpm` there keeps apt from pulling in apache); makes `php8.N` the CLI default; rewrites `fastcgi_pass unix:/run/php/php8.X-fpm.sock` → `php8.N` **only in nginx files that mention `PANEL_ROOT`** (a sibling server block proxying to Wings is never touched), keeping a `.bak-skeleton-key` copy; runs `nginx -t` and restores the backups if it fails; restarts `php8.N-fpm` and nginx. The previous PHP release stays installed and running as the rollback point. |
| `panel-upgrade <version> <vX.Y.Z[-pre]> [--skip-backup]` | Refuses unless `config/app.php` says the panel is on exactly `<version>` (stale picture). Then, **before anything touches the panel**: downloads `panel.tar.gz` + `checksum.txt` for the tag over https only and verifies the SHA-256, and runs `composer check-platform-reqs --lock --no-dev` on the new release's lock file (PHP version and extensions). Then the database backup (sqlite copy, or `mysqldump` with the password passed via `MYSQL_PWD` inside the panel user's shell — never on a command line) unless `--skip-backup`, and Pelican's documented sequence: `artisan down`, extract, `chmod -R 755 storage bootstrap/cache`, `composer install --no-dev --optimize-autoloader`, `migrate --seed --force`, `optimize:clear`, `queue:restart`, `artisan up`. artisan, composer and tar run as `PANEL_USER`, never root. Stops at the first failed step and reports it, whether the panel was left in maintenance mode, the backup path and the run log. Ignores SIGHUP, so a dropped SSH session cannot kill a half-done upgrade. |
| `wings-update <vX.Y.Z[-pre]>` | Downloads `wings_linux_<arch>` and `checksums.txt` for that GitHub release over https only, verifies the SHA-256, test-runs the binary, swaps `/usr/local/bin/wings` atomically (previous binary kept as `wings.prev`, mode preserved), restarts the `wings` unit and rolls back automatically if it is not active afterwards. Running game servers keep running; panel consoles reconnect. |
| anything else | Exits 2 with usage. Exit 1 means a step failed; exit 2 means refused (usage, bad argument, not root, integrity check, stale version). |

Step-by-step output of `panel-upgrade` is written to a root-only log under `/var/log/skeleton-key/`; the SSH channel carries only `key=value` lines and short progress messages.

## The upgrade story, end to end

1. `panel_version` — one read: installed vs latest panel release, host PHP vs the release's `composer.json` requirement, the nginx socket, Wings vs its latest release, and whether this helper + rule are in place.
2. `panel_prepare_runtime` with the `phpVersion` that read reports (e.g. `8.4`) — refuses a version the release does not allow, refuses if the **installed** panel could not run on it, no-op if already met.
3. `panel_upgrade` with the installed version as `expectVersion` (optionally `release` to pin a tag) — refuses up front, before maintenance mode, when the PHP requirement is not met; otherwise runs `panel-upgrade` above.
4. `wings_update` with the installed Wings version as `expectVersion` and the tag `panel_version` reported — Pelican ships panel and Wings in lockstep, so do this after the panel is on the matching release.

## Rolling back by hand

- PHP: `sudo update-alternatives --set php /usr/bin/php8.OLD`, restore the site file from its `.bak-skeleton-key` copy, `sudo nginx -t && sudo systemctl restart nginx`. The old `php8.OLD-fpm` is still running.
- Panel: the database backup path is in the tool result (`storage/pelican-db-backup-<timestamp>.*`); restore it and re-extract the previous release's `panel.tar.gz`, then `php artisan up`. If an upgrade stopped mid-way, the panel is in maintenance mode until `php artisan up` runs in the panel root.
- Wings: `sudo mv /usr/local/bin/wings.prev /usr/local/bin/wings && sudo systemctl restart wings`.
