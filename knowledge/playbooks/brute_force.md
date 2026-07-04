# Brute Force

## Description

Brute force attacks involve repeated authentication attempts against a login endpoint using different credential combinations (credential stuffing, password spraying, or dictionary attacks) in an attempt to gain unauthorized access to a SIU Guaraní account (student, faculty, or administrative).

## Typical Indicators

- Multiple HTTP requests (typically POST) to the login endpoint from a single source IP within a short time window, with varying usernames and/or passwords.
- High ratio of authentication-failure responses (HTTP 401/403, or 200 with a login-failure page/body size signature) followed by a single differing response (potential success).
- Password spraying pattern: one or a small set of passwords tried against many distinct usernames from the same source, at a slower rate designed to evade per-account lockouts.
- Credential stuffing pattern: many distinct username/password pairs, often sourced from known breach lists, tried at high volume — frequently distributed across multiple source IPs.
- Consistent request timing (fixed intervals) indicating automation rather than human typing behavior.

## Possible Impact

- Account takeover if valid credentials are guessed or matched from a breached credential set, leading to unauthorized access to academic records.
- If successful against an administrative or faculty account, potential unauthorized grade modification or access to broader student data.
- Account lockouts / denial of service for legitimate users if the target account's lockout policy is triggered by the attack.

## Investigation

1. Identify the targeted account(s): a single account (targeted brute force) vs. many accounts (spraying/stuffing).
2. Determine whether any attempt resulted in a successful authentication (differing response size/status/redirect target from the failure pattern) — this is the single most important triage step.
3. If a successful login is found, immediately review the subsequent session's activity (pages accessed, data exported, records modified).
4. Check source IP(s) for prior reconnaissance activity (scanner detection, enumeration) that may have preceded the attempt.
5. Cross-reference the targeted username(s) against known-privileged accounts to prioritize response.

## Containment

- If a successful compromise is confirmed or strongly suspected, force a password reset and invalidate active sessions for the affected account, following the institution's account-recovery procedure.
- Apply or verify rate-limiting/account lockout policy on the authentication endpoint.
- Block or rate-limit the source IP(s) at the perimeter if the volume is high and concentrated.
- Enable or verify CAPTCHA/MFA on the login flow if not already present, as a policy recommendation to the system owner (not an immediate technical fix the SOC can apply unilaterally).

## Recovery

- Force password resets for any accounts confirmed or suspected compromised.
- Review and, if necessary, tighten the account lockout threshold and authentication rate limits.
- Notify affected users per the institution's incident notification policy.
- Audit account activity logs for the affected accounts over an extended window to rule out earlier undetected compromise.

## False Positives

- Legitimate users who forgot their password and are retrying manually (typically low volume, irregular timing, single account).
- Shared NAT/proxy environments (e.g. a university computer lab) where many legitimate login attempts originate from the same IP, mimicking spraying patterns.
- Automated password managers or SSO integrations retrying due to a misconfiguration rather than malicious intent.

## References

- OWASP Top 10 2021 – A07:2021 Identification and Authentication Failures.
- OWASP Testing Guide – Testing for Weak Lock Out Mechanism / Brute Force (WSTG-ATHN-03).
- MITRE ATT&CK – T1110 Brute Force (including T1110.001 Password Guessing, T1110.003 Password Spraying, T1110.004 Credential Stuffing).
