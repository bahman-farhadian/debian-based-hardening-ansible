VENV ?= .venv
INVENTORY ?= inventories/hosts.yml
GROUP ?= hardening_targets
ANSIBLE ?= $(VENV)/bin/ansible
ANSIBLE_PLAYBOOK ?= $(VENV)/bin/ansible-playbook
LIMIT ?=
FORKS ?=
TAGS ?=
SKIP_TAGS ?=
EXTRA_VARS ?=
CHECK ?= false
DIFF ?= false
EXTRA_ARGS ?=

BOOL_TRUE := 1 true yes TRUE YES

LIMIT_ARG := $(if $(LIMIT),-l $(LIMIT),)
FORKS_ARG := $(if $(FORKS),--forks $(FORKS),)
TAGS_ARG := $(if $(TAGS),--tags $(TAGS),)
SKIP_TAGS_ARG := $(if $(SKIP_TAGS),--skip-tags $(SKIP_TAGS),)
EXTRA_VARS_ARG := $(if $(EXTRA_VARS),-e "$(EXTRA_VARS)",)
CHECK_ARG := $(if $(filter $(CHECK),$(BOOL_TRUE)),--check,)
DIFF_ARG := $(if $(filter $(DIFF),$(BOOL_TRUE)),--diff,)
PLAY_ARGS := $(LIMIT_ARG) $(FORKS_ARG) $(TAGS_ARG) $(SKIP_TAGS_ARG) $(EXTRA_VARS_ARG) $(CHECK_ARG) $(DIFF_ARG) $(EXTRA_ARGS)
ADHOC_ARGS := $(LIMIT_ARG) $(FORKS_ARG) $(EXTRA_ARGS)

.PHONY: help venv ping scan harden reboot site score suggestions ssh-check gap-report runtime-check

help:
	@echo "Targets: venv ping scan harden reboot site score suggestions ssh-check gap-report runtime-check"
	@echo "Switches:"
	@echo "  INVENTORY=<file>      GROUP=<group>        LIMIT=<host_or_group>"
	@echo "  FORKS=<n>             TAGS=<tag1,tag2>     SKIP_TAGS=<tag1,tag2>"
	@echo "  EXTRA_VARS='<k=v ...>' CHECK=true           DIFF=true"
	@echo "  EXTRA_ARGS='<raw-ansible-args>'"

venv:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip wheel
	$(VENV)/bin/pip install "ansible-core==2.17.*" ansible-lint

ping:
	$(ANSIBLE) -i $(INVENTORY) $(ADHOC_ARGS) $(GROUP) -m ping

scan:
	$(ANSIBLE_PLAYBOOK) playbooks/01_lynis_scan.yml $(PLAY_ARGS)

harden:
	$(ANSIBLE_PLAYBOOK) playbooks/10_os_hardening.yml $(PLAY_ARGS)

reboot:
	$(ANSIBLE) -i $(INVENTORY) $(ADHOC_ARGS) $(GROUP) -b -m reboot

site:
	$(ANSIBLE_PLAYBOOK) playbooks/site.yml -e "run_os_hardening=true" $(PLAY_ARGS)

score:
	grep '^hardening_index=' artifacts/lynis/*/lynis-report.dat

suggestions:
	grep '^suggestion\[\]=' artifacts/lynis/*/lynis-report.dat

ssh-check:
	$(ANSIBLE) -i $(INVENTORY) $(ADHOC_ARGS) $(GROUP) -b -m shell -a "sshd -T | egrep 'permitrootlogin|passwordauthentication|banner|printmotd|printlastlog|loglevel|maxauthtries|maxsessions'"

gap-report:
	grep -E '^hardening_index=|^warning\[]=|^suggestion\[]=|^details\[]=(KRNL-6000|SSH-7408|FIRE-4513|NETW-2705|NAME-4028|NAME-4404|LOGG-2154|BOOT-5122|FILE-6310|PKGS-7346|ACCT-9630)' artifacts/lynis/*/lynis-report.dat

runtime-check:
	$(ANSIBLE) -i $(INVENTORY) $(ADHOC_ARGS) $(GROUP) -b -m shell -a "echo '== sshd -T =='; sshd -T | egrep 'port|permitrootlogin|passwordauthentication|banner|printmotd|printlastlog|maxauthtries|maxsessions|loglevel'; echo '== issue.net =='; sed -n '1,120p' /etc/issue.net; echo '== pam_motd refs =='; grep -n pam_motd /etc/pam.d/sshd || true; echo '== ssh command hook =='; ls -l /etc/profile.d/99-ssh-command-logging.sh 2>/dev/null || true; echo '== rsyslog ssh logging =='; sed -n '1,200p' /etc/rsyslog.d/30-ssh-session-logging.conf 2>/dev/null || true; echo '== last ssh command logs =='; tail -n 20 /var/log/ssh_commands.log 2>/dev/null || true; echo '== firewall v4 =='; iptables -S; echo '== firewall v6 =='; ip6tables -S; echo '== dns =='; cat /etc/resolv.conf; echo '== hosts =='; cat /etc/hosts; echo '== sysctl =='; sysctl fs.protected_fifos kernel.modules_disabled; echo '== audit rules =='; auditctl -l || true; echo '== residual rc packages =='; dpkg -l | awk '/^rc/{print $$2}'"
