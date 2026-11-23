# Advisory Summary: MOVEit Transfer SQL Injection (CVE-2023-34362)

_Sample document for CyberIntel AI. Educational summary; verify affected and fixed versions against the Progress Software advisory._

## Overview

CVE-2023-34362 is a critical SQL injection vulnerability in the web application of Progress MOVEit Transfer, a managed file transfer (MFT) product. An unauthenticated attacker can send crafted HTTP requests that inject SQL into the MOVEit database, leading to unauthorized access, data theft and, in combination with other weaknesses, remote code execution. NVD rates it CVSS v3.1 9.8 (critical). The weakness is CWE-89 (improper neutralization of special elements used in an SQL command).

## Threat activity

Exploitation began around 27 May 2023, before a patch was available, making it a zero-day. The campaign was attributed to the CL0P ransomware and extortion group (also tracked as TA505 / Lace Tempest). Rather than encrypting systems, the actors focused on mass data theft followed by extortion, affecting hundreds of organizations including government agencies, universities, airlines and payroll providers, often through third-party suppliers.

## Observed tradecraft

- Exploitation of the public-facing MOVEit web interface over HTTPS.
- Deployment of a web shell, tracked as LEMURLOOT, written in ASP.NET and commonly named `human2.aspx` in the MOVEit `wwwroot` directory, imitating the legitimate `human.aspx` file.
- The web shell required a specific password value in the `X-siLock-Comment` HTTP header and could list files, create administrative accounts and download stored files.
- Bulk exfiltration of files stored in MOVEit over the existing HTTPS channel.

## Remediation

1. Apply the vendor patch for your release line (patched builds were released for 2021.0.x, 2021.1.x, 2022.0.x, 2022.1.x and 2023.0.x; confirm the exact build in the vendor advisory). Later fixes addressed follow-on SQL injection bugs CVE-2023-35036 and CVE-2023-35708, so install the latest cumulative update.
2. If you cannot patch immediately, block HTTP and HTTPS traffic to MOVEit Transfer from the internet.
3. Check for indicators of compromise: unexpected `.aspx` files (especially `human2.aspx`), new or unknown administrator accounts, and large unexplained downloads.
4. Rotate credentials for MOVEit service accounts and any accounts stored in its database.
5. Treat any data stored in MOVEit during the exposure window as potentially stolen and begin breach-notification assessment.

## Detection

- Web server logs: requests to `human2.aspx`, or any request carrying an `X-siLock-Comment` header.
- File integrity monitoring on the MOVEit `wwwroot` directory.
- Spikes in outbound data volume from the MFT server.
- Creation of database users or accounts named `Health Check Service`.

## ATT&CK mapping

- T1190 Exploit Public-Facing Application
- T1505.003 Server Software Component: Web Shell
- T1136 Create Account
- T1567 Exfiltration Over Web Service / T1041 Exfiltration Over C2 Channel
- T1657 Financial Theft (extortion)
