import { describe, it, expect } from "vitest";
import { checkCommand, checkReadonly, splitCompound, READONLY_ALLOW } from "./command-policy.js";

describe("command policy deny-list", () => {
  it("blocks recursive force rm in any flag order", () => {
    expect(checkCommand("rm -rf /").allowed).toBe(false);
    expect(checkCommand("rm -fr /var/log").allowed).toBe(false);
    expect(checkCommand("sudo rm  -Rf  /data").allowed).toBe(false);
  });

  it("blocks filesystem and disk destroyers", () => {
    expect(checkCommand("mkfs.ext4 /dev/sda1").allowed).toBe(false);
    expect(checkCommand("dd if=/dev/zero of=/dev/sda").allowed).toBe(false);
    expect(checkCommand("wipefs -a /dev/sdb").allowed).toBe(false);
  });

  it("blocks power-state changes and fork bombs", () => {
    expect(checkCommand("shutdown -h now").allowed).toBe(false);
    expect(checkCommand("reboot").allowed).toBe(false);
    expect(checkCommand(":(){ :|:& };:").allowed).toBe(false);
  });

  it("allows ordinary read commands", () => {
    expect(checkCommand("tail -n 100 /var/log/syslog").allowed).toBe(true);
    expect(checkCommand("systemctl restart nginx").allowed).toBe(true);
    expect(checkCommand("docker ps").allowed).toBe(true);
  });

  it("honors an extra per-target deny pattern", () => {
    const res = checkCommand("systemctl stop firewalld", { deny: ["systemctl stop"] });
    expect(res.allowed).toBe(false);
  });

  it("enforces allowlist mode for readonly commands", () => {
    expect(checkCommand("cat /etc/hosts", { allow: READONLY_ALLOW }).allowed).toBe(true);
    expect(checkCommand("ip addr", { allow: READONLY_ALLOW }).allowed).toBe(true);
    // Not on the readonly allowlist:
    expect(checkCommand("systemctl restart nginx", { allow: READONLY_ALLOW }).allowed).toBe(false);
    expect(checkCommand("echo hi > /tmp/x", { allow: READONLY_ALLOW }).allowed).toBe(false);
  });

  it("rejects empty commands", () => {
    expect(checkCommand("   ").allowed).toBe(false);
  });
});

describe("read-only policy: every command of a compound line is vetted", () => {
  const ok = (cmd: string) => expect(checkReadonly(cmd), cmd).toMatchObject({ allowed: true });
  const no = (cmd: string) => expect(checkReadonly(cmd).allowed, cmd).toBe(false);

  it("refuses a state-changing command chained after an allowlisted one", () => {
    no("ls; systemctl stop pvestatd");
    no("cat /etc/hosts && qm stop 100");
    no("ls || pvesm remove nvme");
    no("ls\nsystemctl restart pveproxy");
    no("cat /etc/pve/storage.cfg | tee /etc/pve/storage.cfg");
    no("ls |& sh");
  });

  it("refuses substitution, subshells, backgrounding and file redirects", () => {
    no("cat $(systemctl stop pvestatd)");
    no('cat "$(id)"');
    no("cat `id`");
    no("ls (systemctl stop x)");
    no("ls & systemctl stop x");
    no("cat /etc/hosts > /etc/motd");
    no("cat /etc/hosts >> /root/x");
    no("ls &> /tmp/out");
    no("ls >& /tmp/out");
    no("cat < /etc/shadow");
    no("cat <<EOF");
    no("diff <(ls) /x");
    no("cat /dev/nullx > /dev/nullx");
    no("cat 'unterminated");
  });

  it("allows read-only pipelines, chains and harmless redirects", () => {
    ok("lspci -nn | grep -i -E 'nvme|non-volatile'");
    ok("journalctl -k -b -1 | grep -i nvme");
    ok("dmesg -T | grep -i nvme | tail -n 20");
    ok("ls /dev/nvme* 2>/dev/null || ls /dev/sd*");
    ok("lsblk -o NAME,SIZE && findmnt /mnt/pve/nvme");
    ok("cat /etc/os-release >/dev/null 2>&1");
    ok("ls &>/dev/null");
    ok("grep -rn 'a;b && c > d' /etc/pve/");
    ok('grep -rn "nvme:" /etc/pve/qemu-server/ /etc/pve/lxc/');
    ok("systemctl list-units --all | grep -i nvme");
  });

  it("allows the Proxmox / hardware inspection commands", () => {
    for (const cmd of [
      "lspci", "lsblk", "lsusb", "lscpu", "findmnt", "blkid", "lvs", "vgs -o +vg_free", "pvs",
      "pveversion -v", "pvesm status", "pvesm list local-lvm", "qm config 101", "qm status 100", "qm list",
      "pct list", "pvecm status", "pvesh get /cluster/tasks --limit 50", "nvme list", "nvme smart-log /dev/nvme0",
      "systemctl is-enabled ksmtuned", "systemctl cat mnt-pve-nvme.mount", "zfs list", "smartctl -a /dev/sda",
    ]) ok(cmd);
  });

  it("allows UPS status queries but not the NUT commands that change state", () => {
    for (const cmd of [
      "upsc ups@localhost", "upsc ups@localhost ups.status", "upsc -l", "upsc -L 192.168.1.20", "upsc -c ups",
      "upsc ups 2>&1 | grep -E 'battery|ups.(status|load)'", "apcaccess", "apcaccess status",
    ]) ok(cmd);
    for (const cmd of [
      "upscmd ups beeper.disable", "upscmd -u admin ups shutdown.return", "upsrw -s ups.delay.shutdown=20 ups",
      "upsc ups; upscmd ups test.battery.start", "upsmon -c fsd", "upsdrvctl stop",
    ]) no(cmd);
  });

  it("allows the PVE upgrade checklists, failed-unit listing and kernel-module reads", () => {
    for (const cmd of [
      "pve8to9", "pve8to9 --full", "pve7to8 --full", "pve8to9 --full 2>&1 | grep -E 'FAIL|WARN'",
      "systemctl --failed", "systemctl --failed --no-pager --no-legend", "systemctl --failed --plain | wc -l", "pve8to9 >/dev/null 2>&1", "systemctl --failed 2>/dev/null",
      "modinfo r8125", "modinfo -F version r8169", "modinfo -k 7.0.14-pve r8125", "dkms status", "dkms status -m r8125",
    ]) ok(cmd);
    for (const cmd of [
      "pve8to9 --fix", "pve8to9 2>&1 --force", "pve8to9 >/dev/null --force", "pve8to9 --full --force", "pve8to9; apt dist-upgrade", "pve9to10",
      "systemctl --failed restart pvestatd", "systemctl --failed --now stop pvestatd", "systemctl --failed; systemctl reset-failed",
      "systemctl reset-failed", "dkms install r8125/9.016.01", "dkms remove r8125/9.016.01 --all", "dkms build r8125",
      "modprobe -r r8169", "insmod r8125.ko", "rmmod r8169", "depmod -a",
    ]) no(cmd);
  });

  it("refuses mutating subcommands of the Proxmox / hardware tools", () => {
    for (const cmd of [
      "pvesm remove nvme", "pvesm set nvme --disable 1", "qm set 100 --delete unused0", "qm stop 100",
      "pct destroy 101", "pvesh set /nodes/pve/config", "pvesh create /x", "nvme format /dev/nvme0",
      "systemctl stop pvestatd", "systemctl daemon-reload", "zfs destroy rpool/x", "zpool scrub rpool",
    ]) no(cmd);
  });

  it("refuses the write modes of allowlisted read commands", () => {
    for (const cmd of [
      "find /var/log -name '*.gz' -delete", "find / -exec rm {} ;", "find / -fprint /etc/x",
      "ip link set dev vmbr0 down", "ip addr add 10.0.0.1/24 dev vmbr0", "ip route del default", "ip -batch /tmp/x",
      "ip l s dev vmbr0 down", "ip a a 10.0.0.1/24 dev vmbr0", "ip r d default", "ip link dev x", "ip -force link set x up",
      "dmesg -Tc", "ss -4K dst 10.0.0.1",
      "date -s '2020-01-01'", "date 010100002020", "hostname evil", "hostname -F /etc/x",
      "dmesg -c", "dmesg -C", "dmesg --clear", "journalctl --vacuum-time=1s", "journalctl --rotate",
      "ss -K dst 10.0.0.1", "arp -d 192.168.0.1", "env systemctl stop x", "smartctl -t long /dev/sda",
      "smartctl -s off /dev/sda", "sort -o /etc/passwd /tmp/x", "ping -f 192.168.0.1",
    ]) no(cmd);
  });

  it("still allows the ordinary read forms of those commands", () => {
    for (const cmd of [
      "find /etc -name '*.mount'", "ip a", "ip -br a", "ip -4 route show", "ip link show", "ip route", "ip route get 1.1.1.1", "ip -s link ls", "date", "date +%s", "hostname", "hostname -I",
      "dmesg -T", "dmesg --level=err", "journalctl -u pvestatd -n 50", "journalctl --list-boots", "ss -tlnp",
      "arp -a", "env", "smartctl -x /dev/sda", "hostname -f", "dmesg -e", "smartctl -d sat -a /dev/sda", "sort", "ping -c 3 192.168.0.1",
    ]) ok(cmd);
  });

  it("names the offending command of a compound line", () => {
    expect(checkReadonly("lsblk | sh").reason).toContain("`sh`");
  });
});

describe("splitCompound", () => {
  it("keeps quoted separators inside one command", () => {
    expect(splitCompound(`grep -E 'a|b;c' x | wc -l`)).toEqual({ segments: ["grep -E 'a|b;c' x", "wc -l"] });
    expect(splitCompound(`grep "a && b" x`)).toEqual({ segments: [`grep "a && b" x`] });
    expect(splitCompound(String.raw`find . -name x \; ; ls`)).toEqual({ segments: [String.raw`find . -name x \;`, "ls"] });
  });
});

describe("allowlist mode applies to per-target allowPatterns too", () => {
  it("a target allowlist can no longer be bypassed by chaining", () => {
    const opts = { allow: ["^\\s*docker\\s+ps\\b"] };
    expect(checkCommand("docker ps", opts).allowed).toBe(true);
    expect(checkCommand("docker ps; docker rm -f web", opts).allowed).toBe(false);
  });

  it("without an allowlist (run_command), compound commands are unaffected", () => {
    expect(checkCommand("cd /opt/app && docker compose pull > /tmp/pull.log 2>&1").allowed).toBe(true);
  });
});
