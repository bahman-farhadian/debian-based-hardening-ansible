# Debian-based Hardening Ansible

Ansible project for Debian-family server hardening with two stages:
- Stage 1: run Lynis and collect a baseline report.
- Stage 2: apply modular hardening roles through one orchestrator role.

This repository is organized for maintainability and later Galaxy publishing.

## Supported targets

- Debian 12
- Debian 13
- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS

## Project layout

- `playbooks/01_lynis_scan.yml` stage 1 Lynis scan
- `playbooks/10_os_hardening.yml` stage 2 hardening entrypoint
- `playbooks/site.yml` runs both stages
- `group_vars/all.yml` central project variables
- `inventories/hosts.yml` inventory
- `roles/os_hardening` stage 2 orchestrator role
- `roles/boot_hardening` boot target and runlevel compatibility controls
- `roles/prep_baseline` idempotent replacement for bootstrap shell prep
- `roles/network_identity` DNS, resolv.conf and hosts identity controls
- `roles/file_permissions_hardening` restrictive permissions for SSH and cron paths
- `roles/*_hardening` modular hardening roles
- `artifacts/lynis/<host>/` collected Lynis outputs
- `Makefile` common run commands

## Full feature review

Current stage 2 hardening includes:

- `common_repos` manages Debian repository components (`main contrib non-free non-free-firmware`) with mirror URL variables and fact-based suite mapping (`12->bookworm`, `13->trixie`).
- `boot_hardening` applies server boot defaults and Debian 13 runlevel compatibility updates for systemd/utmp.
- `prep_baseline` replaces bootstrap scripting: installs baseline admin packages, sets shell defaults, configures aliases/prompts, and can bootstrap root authorized keys.
- `network_identity` manages hostname, `/etc/hosts`, and optional `/etc/resolv.conf`.
- `package_hardening` enables unattended upgrades, update/upgrade flows, `debsums`, and residual package cleanup.
- `service_hardening` applies systemd drop-in restrictions to selected services to improve service-level hardening posture (`BOOT-5264` related).
- `firewall` manages iptables/ip6tables policy, backend selection (`nft`/`legacy` handling), runtime restore, persistent rules, optional service-port allow list, and optional IPv4 forwarding/NAT mode.
- `kernel_hardening` applies sysctl/kernel hardening controls with optional module loading lock.
- `auth_hardening` applies password/account policy baseline.
- `banner_hardening` applies local and SSH legal banners.
- `ssh_hardening` applies SSH daemon hardening, key-only root policy option, login output cleanup, and operational limits.
- `fail2ban` configures SSH brute-force protection.
- `auditd` installs/enables audit daemon and deploys baseline audit rules.
- `accounting_hardening` enables process accounting and sysstat collection.
- `integrity_hardening` installs and configures AIDE plus malware scanner baseline.
- `compiler_hardening` restricts compiler execution to root.
- `file_permissions_hardening` tightens permissions on sensitive files/paths.
- `session_logging` configures SSH session logs, per-command SSH logs, log rotation, and optional remote rsyslog forwarding.

## Control node setup

Install dependencies:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git openssh-client
```

Create virtual environment and install Ansible:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip wheel
pip install "ansible-core==2.17.*" ansible-lint
ansible-playbook --version
```

## Inventory

Edit `inventories/hosts.yml`.
Set host alias under `hardening_targets`.
Set `ansible_host` to target hostname.
Set `ansible_user` to the SSH user.

Single inventory template:

```yaml
all:
  children:
    hardening_targets:
      hosts:
        target-node-01:
          ansible_host: change-me-host-or-ip
          ansible_user: change-me-ssh-user
          ansible_port: 22
        # target-node-02:
        #   ansible_host: change-me-host-or-ip-2
        #   ansible_user: change-me-ssh-user
        #   ansible_port: 22
```

For multiple VMs, add more host blocks under `hardening_targets.hosts`.
Ansible runs them simultaneously (up to fork count).

## Debian suite selection (12/13)

Repository suite selection is automatic from gathered facts:

- Debian 12 uses `bookworm`
- Debian 13 uses `trixie`

If you need to force a suite, set:

```yaml
apt_debian_release_override: "trixie"
```

Quick verification on target:

```bash
grep -E '^(URIs|Suites|Components):' /etc/apt/sources.list.d/debian.sources
```

Debian 13 runlevel compatibility:

- `boot_hardening` enforces server default target (`multi-user.target`).
- If Debian 13 lacks utmp/systemd runlevel units, it deploys a compatibility `runlevel` shim at `/usr/local/sbin/runlevel`.
- Verify with:

```bash
runlevel
who -r
systemctl get-default
command -v runlevel
```

All baseline hardening variables are centralized in `group_vars/all.yml`.
The defaults in `group_vars/all.yml` are tuned to avoid the common drop from 88 to 87
related to DNS identity (`NETW-2705` / `NAME-4028`) and residual packages (`PKGS-7346`).

Run all hosts in inventory:

```bash
make harden
```

Run one host only:

```bash
make harden LIMIT=target-node-01
```

Increase parallelism for many hosts:

```bash
make harden FORKS=20
```

## Local secrets file (git-ignored)

For sensitive values (for example GRUB password plaintext), use a local override file:

```bash
cp group_vars/local_secrets.yml.example group_vars/local_secrets.yml
```

`group_vars/local_secrets.yml` is ignored by git and is auto-loaded by all playbooks.
Keep real secret values only in that local file, not in `group_vars/all.yml`.

## Primary user rename and SSH keys

Template VMs often start with a default user such as `qwerty` (UID `1000`).
The prep role can rename that user, move its home directory, and install SSH keys for both root and the primary user.

Set these in `group_vars/all.yml`:

```yaml
prep_primary_user_uid: "1000"
prep_primary_user_desired_name: "adminops"
prep_primary_user_authorized_keys:
  - "ssh-ed25519 AAAA... adminops-key"
prep_root_authorized_keys:
  - "ssh-ed25519 AAAA... root-key"
```

Behavior:

- If `prep_primary_user_desired_name` is set and differs from the detected UID user, the account is renamed.
- Home is moved to `/home/<new-user>` and ownership is corrected.
- `~/.ssh/authorized_keys` is managed for root and primary user when key lists are provided.

## Quick runbook

This project supports the same hardening flow on Debian 12 and Debian 13.
For hardening, users only need to run `playbooks/10_os_hardening.yml` (via `make harden`).

Recommended sequence:

```bash
make ping
make harden LIMIT=target-node-01
```

Then change SSH port settings:
- Set `ssh_port` in `group_vars/all.yml` (example: `2222`).
- Set the same value for host `ansible_port` in `inventories/hosts.yml`.

Continue:

```bash
make reboot LIMIT=target-node-01
make scan LIMIT=target-node-01
make score
```

This sequence is the standard execution order:
`make ping` -> `make harden` -> change SSH port -> `make reboot` -> `make scan` -> `make score`.

By default, firewall rules also keep the current inventory SSH port allowed during migration (`firewall_allow_current_ansible_port: true`).

If hardening fails with a dpkg/apt lock error caused by `unattended-upgrades`, run `make harden` again.
Package install tasks now wait/retry on apt locks automatically.

Connectivity test:

```bash
ansible -i inventories/hosts.yml hardening_targets -m ping
```

Service hardening verification:

```bash
ansible -i inventories/hosts.yml hardening_targets -b -m shell -a "systemd-analyze security ssh.service fail2ban.service rsyslog.service cron.service | sed -n '1,200p'"
ansible -i inventories/hosts.yml hardening_targets -b -m shell -a "for u in ssh.service fail2ban.service rsyslog.service cron.service unattended-upgrades.service; do echo \"== $u ==\"; systemctl cat \"$u\" | grep -E 'NoNewPrivileges=|PrivateTmp=|ProtectKernel|ProtectControlGroups=|RestrictSUIDSGID=|LockPersonality=|RestrictRealtime=|RestrictNamespaces=' || true; done"
```

Optional service reduction for `BOOT-5264`:
- Some baseline services (for example mail transport units like `exim4.service`) may not be needed in your VM role.
- Add them to `service_hardening_disable_units` to stop and disable them.

```yaml
service_hardening_disable_units:
  - exim4.service
```

Stage 1 baseline scan:

```bash
ansible-playbook playbooks/01_lynis_scan.yml
grep '^hardening_index=' artifacts/lynis/*/lynis-report.dat
grep '^suggestion\[\]=' artifacts/lynis/*/lynis-report.dat
```

Stage 2 hardening:

```bash
ansible-playbook playbooks/10_os_hardening.yml
ansible -i inventories/hosts.yml hardening_targets -b -m reboot
```

Stage 2 hardening with root SSH key bootstrap:

```bash
ansible-playbook playbooks/10_os_hardening.yml -e 'prep_root_authorized_keys=["ssh-ed25519 AAAA... your-key-comment"]'
```

Stage 2 hardening with primary-user rename and both SSH key sets:

```bash
ansible-playbook playbooks/10_os_hardening.yml -e 'prep_primary_user_desired_name=adminops prep_primary_user_authorized_keys=["ssh-ed25519 AAAA... adminops-key"] prep_root_authorized_keys=["ssh-ed25519 AAAA... root-key"]'
```

Re-scan after hardening:

```bash
ansible-playbook playbooks/01_lynis_scan.yml
grep '^hardening_index=' artifacts/lynis/*/lynis-report.dat
grep '^suggestion\[\]=' artifacts/lynis/*/lynis-report.dat
```

Run staged workflow via `site.yml`:

```bash
ansible-playbook playbooks/site.yml -e run_lynis_scan=true -e run_os_hardening=true
```

## Firewall service ports and forwarding

This project uses default-drop firewall policy. Any service port not explicitly allowed will be blocked.

Allow common service ports (example: NGINX and MariaDB) in `group_vars/all.yml`:

```yaml
firewall_allowed_tcp_ports:
  - 80
  - 443
  - 3306
```

Allow IPv6 service ports (if needed):

```yaml
firewall_allowed_tcp_ports_v6:
  - 80
  - 443
```

Enable bastion/router mode with IPv4 forwarding (and optional NAT):

```yaml
firewall_forward_ipv4_enabled: true
firewall_forward_ipv4_lan_interface: "<lan-interface>"
firewall_forward_ipv4_wan_interface: "<wan-interface>"
firewall_forward_ipv4_lan_cidr: "<lan-cidr>"
firewall_nat_ipv4_enabled: true
```

Apply and validate:

```bash
make harden
ansible -i inventories/hosts.yml hardening_targets -b -m shell -a "sysctl net.ipv4.ip_forward; iptables -S FORWARD; iptables -t nat -S POSTROUTING"
```

Critical production note:

- Do not run first-time hardening directly on production servers carrying live traffic.
- This role can immediately close ports that are not explicitly allowed and cause downtime.
- Always pre-declare required ports/forwarding, test on staging, and apply in a maintenance window.

## Makefile commands

Basic targets:

```bash
make help
make venv
make ping
make scan
make harden
make reboot
make score
make suggestions
make ssh-check
make gap-report
make runtime-check
```

`make reboot` runs `ansible -i inventories/hosts.yml hardening_targets -b -m reboot` and performs a controlled reboot of all hosts in `hardening_targets`.

Supported switches:

- `INVENTORY=<path>` use a different inventory file
- `GROUP=<group>` change target group (default `hardening_targets`)
- `LIMIT=<host_or_group>` run only selected hosts
- `FORKS=<n>` parallelism for multi-host runs
- `EXTRA_VARS='<k=v ...>'` pass playbook variables
- `TAGS=<tag1,tag2>` run only matching tags
- `SKIP_TAGS=<tag1,tag2>` skip matching tags
- `CHECK=true` run in check mode
- `DIFF=true` show template/file diffs
- `EXTRA_ARGS='<raw args>'` append raw Ansible CLI args

End-user examples:

```bash
# Harden all hosts in the inventory
make harden

# Harden one VM only
make harden LIMIT=target-node-01

# Harden many VMs with higher parallelism
make harden FORKS=20

# Run dry-run with diffs
make harden CHECK=true DIFF=true

# Override variables for one run
make harden EXTRA_VARS='ssh_port=2222 firewall_allowed_tcp_ports=[80,443]'

# Run only firewall-related tagged tasks
make harden TAGS=firewall

# Skip session logging tasks
make harden SKIP_TAGS=session_logging

# Run scan on one host
make scan LIMIT=target-node-01
```

## Idempotency check

Run stage 2 twice on the same host.
For a strict idempotency check, disable dist-upgrade during validation.
Use host aliases from `inventories/hosts.yml` directly.

```bash
ansible-playbook playbooks/10_os_hardening.yml -l target-node-01 -e package_hardening_run_dist_upgrade=false
ansible-playbook playbooks/10_os_hardening.yml -l target-node-01 -e package_hardening_run_dist_upgrade=false
```

Expected result on second run:
- no config drift
- recap close to `changed=0`

## SSH policy and banner behavior

Current SSH baseline:

- Root login allowed by key only (`PermitRootLogin prohibit-password`)
- Password authentication disabled
- MOTD/copyright text disabled for cleaner SSH login output
- Login banner enabled via `Banner /etc/issue.net`
- PAM MOTD lines removed from SSH PAM stack for cleaner login output

Banner text variables:

- `banner_issue_text` for `/etc/issue`
- `banner_issue_net_text` for `/etc/issue.net`

Re-apply hardening to update banner/SSH behavior:

```bash
ansible-playbook playbooks/10_os_hardening.yml
```

Verify effective SSH settings:

```bash
ansible -i inventories/hosts.yml hardening_targets -b -m shell -a "sshd -T | egrep 'permitrootlogin|passwordauthentication|banner|printmotd|printlastlog|loglevel|maxauthtries|maxsessions'"
```

Verify SSH MOTD cleanup:

```bash
ansible -i inventories/hosts.yml hardening_targets -b -m shell -a "grep -n pam_motd /etc/pam.d/sshd || true; wc -c /etc/motd"
```

## Per-command SSH logging

The project logs every interactive SSH command entered in Bash sessions.

- Hook file: `/etc/profile.d/99-ssh-command-logging.sh`
- Command log file: `/var/log/ssh_commands.log`
- Session/auth log file: `/var/log/ssh_sessions.log`
- Default retention: 30 days via `/etc/logrotate.d/ssh-session-log`
- Remote forwarding: when `remote_syslog_enabled=true`, both logs are still eligible for forwarding through rsyslog
- Scope: interactive Bash SSH sessions (`SSH_CONNECTION` present)
- Note: sensitive values typed in commands can appear in logs; prefer secret files or vault-backed workflows

Validation flow:

1. Apply hardening (`make harden` or `ansible-playbook playbooks/10_os_hardening.yml`).
2. Start a new SSH login session and run a few commands.
3. Check latest command audit lines:

```bash
ansible -i inventories/hosts.yml hardening_targets -b -m shell -a "tail -n 30 /var/log/ssh_commands.log"
```

4. Confirm rsyslog rules and logrotate settings:

```bash
ansible -i inventories/hosts.yml hardening_targets -b -m shell -a "sed -n '1,200p' /etc/rsyslog.d/30-ssh-session-logging.conf; sed -n '1,200p' /etc/logrotate.d/ssh-session-log"
```

## Security logs to review regularly

Recommended log files on each target:

- `/var/log/auth.log` SSH authentication, sudo usage, and login failures.
- `/var/log/ssh_sessions.log` dedicated SSH session activity log (from this project).
- `/var/log/ssh_commands.log` per-command SSH audit trail for interactive Bash sessions.
- `/var/log/fail2ban.log` ban/unban activity and brute-force mitigation.
- `/var/log/audit/audit.log` kernel audit trail (auditd events and watched files).
- `/var/log/syslog` service-level system events.
- `/var/log/lynis.log` and `/var/log/lynis-report.dat` latest Lynis scan details.

Useful review commands:

```bash
ansible -i inventories/hosts.yml hardening_targets -b -m shell -a "tail -n 100 /var/log/auth.log /var/log/ssh_sessions.log /var/log/ssh_commands.log /var/log/fail2ban.log /var/log/audit/audit.log /var/log/syslog 2>/dev/null"
ansible -i inventories/hosts.yml hardening_targets -b -m shell -a "grep -Ei 'failed|invalid|error|denied|ban' /var/log/auth.log /var/log/fail2ban.log /var/log/audit/audit.log 2>/dev/null | tail -n 100"
```

## Why score may stop around 80s

Lynis score does not increase only by adding many tasks. It depends on weighted tests, and several remaining items are manual or environment-specific.

Common blockers from your latest report:

- `KRNL-5830` reboot required warning (run reboot after kernel/sysctl/package changes)
- `FIRE-4512/FIRE-4513` appears when firewall rules are not active in runtime
- `BOOT-5122` GRUB password setup (manual decision with secure boot flow)
- `FILE-6310` separate partitions for `/home`, `/tmp`, `/var` (storage layout change)
- `NAME-4028` and `NAME-4404` DNS/hosts values depend on your network design
- `LOGG-2154` external log server requires your SIEM/log host endpoint
- `SSH-7408` non-default SSH port is optional policy choice
- `KRNL-6000` `kernel.modules_disabled=1` is optional high-impact hardening

Hardening tasks now also target previously open items:

- `AUTH-9282`: existing-account expiry policy applied by default
- `PKGS-7370`: `debsums` periodic check configured (`CRON_CHECK`)
- `PKGS-7392`: dist-upgrade pass enabled in stage 2
- `FINT-4402`: AIDE checksum algorithm set to `sha512`, AIDE DB initialized
- `HRDN-7222`: compiler binaries restricted to root
- `KRNL-6000`: extended sysctl set applied
- `PKGS-7346`: residual `rc` packages purged by default
- `NAME-4028/NAME-4404/NETW-2705`: managed hosts/resolv controls via `network_identity`

To push from high-80s toward 90, these policy changes usually matter most:

- Set host FQDN and search domain values explicitly in `group_vars/all.yml` or host vars.
- Change SSH to a non-default port and match firewall allow rules.
- Enable external log forwarding with `remote_syslog_enabled=true` and your log host.
- Consider `kernel_lock_module_loading=true` only after validating all required modules are already loaded.

## Path to 90 from current 88

Based on your latest unresolved findings, the realistic levers are:

- `LOGG-2154`: forward logs to an external log host.
- Optional if still present in your report: `SSH-7408` and `KRNL-6000`.

Recommended sequence:

1. SSH port migration in two runs (only if your report still shows `SSH-7408`):
First run:
Keep `ansible_port: 22` in `inventories/hosts.yml`.
Set `ssh_port: 2222` (or your chosen port) in `group_vars/all.yml`.
Run `make harden`.
Second run:
Change `ansible_port` in `inventories/hosts.yml` to the same new SSH port.
Run `make harden` again.

2. Enable remaining high-impact controls in `group_vars/all.yml`:
`remote_syslog_enabled: true`
`remote_syslog_host: <your-log-server-hostname>`
Optional:
`kernel_lock_module_loading: true`
Only enable `kernel_lock_module_loading: true` after confirming firewall backends still initialize correctly on your kernel.

3. Reboot and validate:

```bash
make harden
make reboot
make runtime-check
make scan
make score
make gap-report
```

Notes:

- `kernel_lock_module_loading: true` is one-way until reboot and can break workloads that need late module loading.
- `FIRE-4513` is advisory about potentially unused firewall rules and may remain depending on runtime traffic patterns.
- `BOOT-5122` (GRUB password) and `FILE-6310` (separate partitions) are mostly manual/infrastructure controls.

## kernel_lock_module_loading explained

`kernel_lock_module_loading` controls whether the playbook writes `kernel.modules_disabled=1`.
When this value is `1`, the kernel refuses loading any new modules until the next reboot.

Why this can improve score:

- Lynis `KRNL-6000` expects module loading to be locked on hardened systems.

Why this is risky:

- Drivers or kernel features that are not already loaded cannot be loaded later.
- Firewall backends, storage/network drivers, or virtualization features may fail if they depend on late module loads.

What users should do:

1. Keep `kernel_lock_module_loading: false` during normal rollout and validation.
2. Run hardening and verify workload health:
`make harden`
`make reboot`
`make runtime-check`
3. If everything is stable, set `kernel_lock_module_loading: true` in `group_vars/all.yml`.
4. Apply and reboot again:
`make harden`
`make reboot`
5. Re-run scan and confirm impact:
`make scan`
`make gap-report`

If issues appear after enabling it, set `kernel_lock_module_loading: false` and reboot to restore normal module loading behavior.

## Important variables in `group_vars/all.yml`

- `run_lynis_scan`
- `run_os_hardening`
- `apt_repository_url`, `apt_security_repository_url`
- `apt_debian_release_override`
- `prep_enabled`
- `boot_hardening_enabled`
- `boot_set_default_target`
- `boot_default_target`
- `boot_fix_runlevel_debian13`
- `boot_runlevel_compat_wrapper_enabled`
- `prep_root_authorized_keys`
- `prep_manage_primary_user`
- `prep_primary_user_uid`
- `prep_primary_user_desired_name`
- `prep_primary_user_authorized_keys`
- `network_identity_manage_hosts`
- `network_identity_manage_resolv_conf`
- `network_identity_primary_ipv4`
- `network_identity_nameservers`
- `network_identity_fqdn`
- `network_identity_manage_loopback_fqdn`
- `network_identity_manage_hosts_via_template`
- `ssh_allow_root_login`
- `ssh_allow_password_auth`
- `ssh_disable_pam_motd`
- `ssh_clean_login_output`
- `ssh_print_last_log`
- `firewall_enable_extra_input_hardening`
- `firewall_allow_current_ansible_port`
- `firewall_allow_ssh_from_anywhere`
- `firewall_allowed_ssh_cidrs`
- `firewall_allowed_tcp_ports` and `firewall_allowed_udp_ports`
- `firewall_allowed_tcp_ports_v6` and `firewall_allowed_udp_ports_v6`
- `firewall_forward_ipv4_enabled`
- `firewall_forward_ipv4_lan_interface`, `firewall_forward_ipv4_wan_interface`, `firewall_forward_ipv4_lan_cidr`
- `firewall_nat_ipv4_enabled`
- `package_hardening_run_dist_upgrade`
- `package_hardening_purge_removed_packages`
- `service_hardening_enabled`
- `service_hardening_units`
- `service_hardening_disable_units`
- `apt_lock_timeout`, `apt_package_retries`, `apt_package_retry_delay`
- `auth_apply_to_existing_local_users`
- `auth_apply_to_root`
- `kernel_sysctl_dropin_path`
- `kernel_lock_module_loading` (high impact, default false)
- `file_permissions_hardening_enabled`
- `integrity_initialize_aide`
- `remote_syslog_enabled` and `remote_syslog_host`
- `ssh_session_log_file` and `ssh_session_logrotate_days`
- `ssh_command_logging_enabled`
- `ssh_command_log_file` and `ssh_command_logrotate_days`
- `ssh_command_log_facility`, `ssh_command_log_priority`, `ssh_command_logger_tag`
- `grub_superuser`
- `grub_password_plaintext` (set in `group_vars/local_secrets.yml`)
- `grub_password_pbkdf2_hash` (set in `group_vars/local_secrets.yml`)

## Galaxy readiness direction

Stage 2 is now orchestrated through `roles/os_hardening`, with modular sub-roles.
This keeps the role graph clear and makes migration to Galaxy publishing cleaner.

Next practical step before Galaxy publish:
- add per-role `README.md` and `meta/main.yml` for each role
- add Molecule tests for Debian 12 and Ubuntu 22.04/24.04
