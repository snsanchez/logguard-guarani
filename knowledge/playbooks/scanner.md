# Scanner Detection

## Description

This category covers evidence of automated vulnerability or network scanning tools probing the SIU Guaraní web infrastructure, as distinct from directory enumeration specifically. Scanners typically test a broad set of known vulnerability signatures (CVEs, common misconfigurations, default credentials) across many endpoints rather than mutating a single wordlist against paths.

## Typical Indicators

- Distinctive User-Agent strings from known scanning tools (`Nikto`, `Nessus`, `OpenVAS`, `Acunetix`, `sqlmap`, `Nmap Scripting Engine`, `masscan`, `Qualys`) — again a weak/spoofable indicator that should be corroborated with behavior.
- Requests probing default or well-known vulnerable paths unrelated to SIU Guaraní's actual application (e.g. WordPress `wp-login.php`, phpMyAdmin paths, Struts endpoints) — a strong indicator when the platform does not run those technologies.
- Broad-spectrum probing: many distinct vulnerability signatures tested against the same handful of endpoints in rapid succession.
- Malformed or protocol-violating requests (invalid HTTP methods, oversized headers, unusual `Content-Length` mismatches) consistent with fuzzing.
- Source IP with no prior legitimate session history suddenly generating high-volume varied requests.

## Possible Impact

- Primarily reconnaissance; direct impact is limited unless the scanner identifies and the attacker (or the tool itself) exploits a real weakness.
- Resource exhaustion / performance degradation on the target server if scan volume is high.
- Serves as a strong early-warning signal that the source IP may escalate to targeted exploitation.

## Investigation

1. Enumerate all distinct signatures/paths probed by the source IP and check whether any correspond to technology actually deployed by SIU Guaraní (false positives are common here).
2. Check response codes: a scanner receiving consistent 404/501 responses found nothing of value; any 200 on a known-vulnerable path requires urgent follow-up.
3. Review scan duration and breadth (single endpoint vs. entire application) to gauge attacker sophistication and intent.
4. Check threat intelligence / IP reputation for the source (if such lookups are available offline via a maintained local blocklist).
5. Determine if the same IP previously appeared in other categories (brute force, SQLi) — scanning is often followed by targeted attacks from the same or related infrastructure.

## Containment

- Block the source IP at the perimeter if scan volume or signature diversity exceeds policy thresholds.
- Ensure the WAF/IPS signature set is current for the scanning patterns observed.
- No action should be taken against the scanning source beyond blocking/monitoring; do not attempt to interact with or probe the source back.

## Recovery

- No system recovery is typically needed unless a scan-identified weakness was separately confirmed as exploited (in which case follow the relevant specific playbook, e.g. SQL Injection or Path Traversal).
- Update the local indicator list with the scanning IP and any newly observed tool signatures for future correlation.

## False Positives

- Authorized internal or third-party security assessments not communicated to the SOC in advance.
- Uptime/monitoring services and CDN health checks that resemble broad probing but originate from known infrastructure providers.
- Misconfigured internal tools that repeatedly request nonexistent resources.

## References

- OWASP Testing Guide – Information Gathering (WSTG-INFO series).
- MITRE ATT&CK – T1595 Active Scanning; T1595.002 Active Scanning: Vulnerability Scanning.
- CISA guidance on identifying and responding to reconnaissance activity.
