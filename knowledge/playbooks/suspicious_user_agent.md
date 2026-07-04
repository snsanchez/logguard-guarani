# Suspicious User-Agent

## Description

This category covers requests bearing User-Agent strings that are anomalous, malformed, empty, associated with known offensive tooling, or inconsistent with the rest of the request (e.g. claiming to be a browser while missing browser-typical headers). The User-Agent header is client-supplied and trivially forgeable, so it should be treated as a supporting signal, not standalone proof of malicious intent — this distinction should be preserved in any report generated from this category.

## Typical Indicators

- Empty or missing User-Agent header on requests to sensitive endpoints.
- Known tooling signatures: `curl/`, `python-requests/`, `Go-http-client/`, `libwww-perl/`, scanner/exploit-framework strings (`sqlmap`, `Nikto`, `Metasploit`), or literal placeholder strings (`Mozilla` alone, or clearly fake strings).
- Outdated or internally inconsistent User-Agent strings (e.g. claiming a browser/OS combination that does not exist, or a version far outside real-world release history).
- User-Agent inconsistent with other headers typically sent by that claimed client (e.g. claims to be Chrome but lacks `Accept`, `Accept-Language`, or `sec-ch-ua` headers usually sent by that browser).
- Same source IP alternating between multiple unrelated User-Agent strings across a short session (UA rotation, often used to evade naive filtering).

## Possible Impact

- On its own, no direct technical impact — this is a contextual/behavioral signal.
- When correlated with other indicators (e.g. SQLi payloads, enumeration patterns), raises confidence that the traffic is automated/adversarial rather than a genuine user error.

## Investigation

1. Treat this as a corroborating signal: check what other activity is associated with the same source IP/session in the same time window.
2. Determine if the UA corresponds to a legitimate automation client the institution knowingly operates (internal monitoring, API integrations, mobile app backend).
3. Check UA consistency across the full session; frequent rotation from one IP is more suspicious than a single static non-browser UA.
4. If the UA matches a known offensive tool, cross-reference the request paths/payloads for that tool's typical behavior (e.g. sqlmap UA plus SQL syntax in parameters).

## Containment

- Do not block based on User-Agent alone, since it is easily spoofed and legitimate automation may share similar strings; use it to prioritize triage of the associated request/session instead.
- If combined with other confirmed malicious indicators, apply containment per the relevant specific playbook (SQLi, Scanner Detection, etc.).
- Consider requiring authenticated API access for legitimate automated clients so their traffic is distinguishable from anonymous scripted traffic going forward.

## Recovery

- No direct recovery action tied to this indicator alone.
- If used to identify a legitimate but unauthenticated internal integration, work with the relevant team to migrate it to an authenticated, allow-listed channel.

## False Positives

- Legitimate API consumers, health-check systems, RSS readers, or internal scripts using library-default User-Agent strings.
- Privacy-focused browsers or browser extensions that intentionally minimize or randomize the User-Agent string.
- Older or unusual but legitimate client software (older institutional systems, embedded devices) with non-standard UA strings.

## References

- OWASP Testing Guide – general reconnaissance/fingerprinting guidance (WSTG-INFO-02).
- MITRE ATT&CK – T1592 Gather Victim Host Information (adversary-side reconnaissance context); note the User-Agent itself is a defender-side detection artifact, not an ATT&CK technique.
- RFC 9110 (HTTP Semantics) – Section 10.1.5, definition of the User-Agent header field.
