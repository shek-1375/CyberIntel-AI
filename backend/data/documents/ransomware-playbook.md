# Ransomware Response Playbook (Windows / Active Directory environments)

_Sample document for CyberIntel AI. A generic playbook written for demonstration._

## 1. How ransomware operators typically get in

The most common initial-access routes seen in human-operated ransomware incidents are:

- **Exploiting internet-facing systems** — VPN appliances, firewalls, file-transfer servers and remote management tools with known vulnerabilities (ATT&CK T1190). Vulnerabilities listed in CISA KEV deserve emergency patching.
- **Valid accounts** — stolen or brute-forced credentials for VPN, RDP or cloud identity (T1078, T1110), frequently bought from initial access brokers.
- **Phishing** — malicious attachments or links that load a loader such as a malicious document or ISO, leading to a Cobalt Strike or similar implant (T1566).
- **Exposed RDP** — Remote Desktop directly reachable from the internet (T1133 External Remote Services).

## 2. Typical attack chain after entry

1. Discovery of the domain with tools like AdFind, BloodHound or built-in `net` and `nltest` commands (T1087, T1482).
2. Credential access by dumping LSASS memory or the NTDS.dit database (T1003).
3. Lateral movement via RDP, SMB/PsExec or WMI (T1021).
4. Data staging and exfiltration to cloud storage with tools such as Rclone, enabling double extortion (T1567.002).
5. Defense evasion: disabling antivirus and EDR, clearing event logs (T1562, T1070).
6. Inhibiting recovery by deleting volume shadow copies with `vssadmin delete shadows /all /quiet` or `wmic shadowcopy delete`, and deleting backups (T1490).
7. Mass encryption, often pushed via Group Policy or PsExec (T1486).

## 3. Containment (first hours)

- Isolate affected hosts at the network layer or via EDR network containment; do not power them off if memory forensics may be needed.
- Disable compromised accounts and reset the passwords of privileged accounts. Reset the KRBTGT account password twice, with replication time between resets, if domain compromise is suspected.
- Block known command-and-control domains and IPs at the firewall and DNS.
- Take backups offline to protect them from encryption.
- Preserve evidence: event logs, EDR telemetry, memory images and ransom notes.

## 4. Eradication and recovery

- Identify the initial access vector and close it (patch, disable the account, remove the exposure).
- Rebuild compromised domain controllers and servers from known-good media rather than cleaning them.
- Restore data from offline or immutable backups, validating that backups predate the intrusion.
- Monitor closely for re-entry for at least 30 days.

## 5. Prevention controls that matter most

- Patch internet-facing systems quickly, prioritising CISA KEV entries.
- Enforce phishing-resistant MFA on VPN, email, cloud and all privileged access.
- Keep offline or immutable backups and test restoration regularly. Protecting volume shadow copies and backup consoles prevents the recovery-inhibition step.
- Apply tiered administration and Local Administrator Password Solution (LAPS); avoid domain admins logging on to workstations.
- Enable Credential Guard and LSASS protection (RunAsPPL) to hinder credential dumping.
- Alert on `vssadmin delete shadows`, `bcdedit /set recoveryenabled no`, and mass file renames.
