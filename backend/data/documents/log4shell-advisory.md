# Advisory Summary: Log4Shell (CVE-2021-44228) — Apache Log4j 2 Remote Code Execution

_Sample document for CyberIntel AI. Educational summary; verify details against the Apache and CISA advisories before operational use._

## Overview

CVE-2021-44228, widely known as Log4Shell, is a critical remote code execution vulnerability in Apache Log4j 2, a very common Java logging library. It carries a CVSS v3.1 base score of 10.0. Log4j 2 versions 2.0-beta9 through 2.14.1 are affected. The flaw was publicly disclosed on 9 December 2021, and CISA added it to the Known Exploited Vulnerabilities catalog on 10 December 2021.

## Root cause

Log4j supports "lookups" — expressions inside log messages that are evaluated when the message is logged. The JNDI lookup (`${jndi:...}`) lets a logged string cause the application to contact a remote LDAP, RMI or DNS server. If an attacker can get a crafted string logged — through an HTTP header such as User-Agent, a form field, a chat message or a username — the vulnerable server connects to an attacker-controlled LDAP server, which can return a reference to a remote Java class that is then loaded and executed. The weakness is classified as CWE-502 (deserialization of untrusted data) and CWE-917 (expression language injection).

## Exploitation in the wild

Mass scanning began within hours of disclosure. Observed post-exploitation activity included coin-miner deployment, botnet enrollment, Cobalt Strike beacons, and ransomware access brokers establishing footholds. Because the payload only needs to reach a log statement, internal systems that log data originating from the internet (for example via a proxy) were also exposed.

## Fixed versions

- 2.15.0 disabled remote JNDI lookups by default but was incomplete (CVE-2021-45046).
- 2.16.0 removed message lookups and disabled JNDI by default.
- 2.17.0 fixed an uncontrolled recursion denial of service (CVE-2021-45105).
- 2.17.1 fixed a JDBC appender issue (CVE-2021-44832). Upgrade to 2.17.1 or later on Java 8; 2.12.4 for Java 7; 2.3.2 for Java 6.

## Mitigation

1. Inventory every application and appliance that bundles log4j-core (check SBOMs, scan JAR files including nested "fat" JARs).
2. Upgrade log4j-core to a fixed version; apply vendor patches for commercial products.
3. If patching is impossible immediately, remove the JndiLookup class from the classpath: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`.
4. Restrict outbound LDAP, RMI and DNS egress from servers; most servers never need to initiate LDAP connections to the internet.
5. Deploy WAF rules for `${jndi:` patterns as a temporary layer, knowing attackers use obfuscation such as `${${lower:j}ndi:` and `${${::-j}${::-n}di:`.

## Detection

- Search web, proxy and application logs for `${jndi:ldap`, `${jndi:rmi`, `${jndi:dns` and obfuscated variants.
- Alert on Java processes making outbound LDAP (389/636) or RMI (1099) connections.
- Alert on java.exe or java spawning shells (cmd.exe, powershell.exe, /bin/sh, bash), curl or wget.
- Hunt for unexpected new files in application directories after December 2021.

## ATT&CK mapping

- T1190 Exploit Public-Facing Application (initial access)
- T1059 Command and Scripting Interpreter (execution after exploitation)
- T1105 Ingress Tool Transfer (downloading payloads)
- T1496 Resource Hijacking (coin miners)
