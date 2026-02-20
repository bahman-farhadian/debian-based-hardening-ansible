VENV ?= .venv
INVENTORY ?= inventories/hosts.yml
GROUP ?= hardening_targets
ANSIBLE ?= $(VENV)/bin/ansible
ANSIBLE_PLAYBOOK ?= $(VENV)/bin/ansible-playbook

.PHONY: venv ping scan harden reboot site score suggestions ssh-check gap-report runtime-check

venv:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip wheel
	$(VENV)/bin/pip install "ansible-core==2.17.*" ansible-lint

ping:
	$(ANSIBLE) -i $(INVENTORY) $(GROUP) -m ping

scan:
	$(ANSIBLE_PLAYBOOK) playbooks/01_lynis_scan.yml

harden:
	$(ANSIBLE_PLAYBOOK) playbooks/10_os_hardening.yml

reboot:
	$(ANSIBLE) -i $(INVENTORY) $(GROUP) -b -m reboot

site:
	$(ANSIBLE_PLAYBOOK) playbooks/site.yml -e run_os_hardening=true

score:
	grep '^hardening_index=' artifacts/lynis/*/lynis-report.dat

suggestions:
	grep '^suggestion\[\]=' artifacts/lynis/*/lynis-report.dat

ssh-check:
	$(ANSIBLE) -i $(INVENTORY) $(GROUP) -b -m shell -a "sshd -T | egrep 'permitrootlogin|passwordauthentication|banner|printmotd|printlastlog|loglevel|maxauthtries|maxsessions'"

gap-report:
	grep -E '^hardening_index=|^warning\[]=|^suggestion\[]=|^details\[]=(KRNL-6000|SSH-7408|FIRE-4513|NETW-2705|NAME-4028|NAME-4404|LOGG-2154|BOOT-5122|FILE-6310|PKGS-7346|ACCT-9630)' artifacts/lynis/*/lynis-report.dat

runtime-check:
	$(ANSIBLE) -i $(INVENTORY) $(GROUP) -b -m shell -a "echo '== sshd -T =='; sshd -T | egrep 'port|permitrootlogin|passwordauthentication|banner|printmotd|printlastlog|maxauthtries|maxsessions|loglevel'; echo '== issue.net =='; sed -n '1,120p' /etc/issue.net; echo '== pam_motd refs =='; grep -n pam_motd /etc/pam.d/sshd || true; echo '== firewall v4 =='; iptables -S; echo '== firewall v6 =='; ip6tables -S; echo '== dns =='; cat /etc/resolv.conf; echo '== hosts =='; cat /etc/hosts; echo '== sysctl =='; sysctl fs.protected_fifos kernel.modules_disabled; echo '== audit rules =='; auditctl -l || true; echo '== residual rc packages =='; dpkg -l | awk '/^rc/{print $$2}'"
