# SQL Injection

## Description

SQL Injection (SQLi) occurs when an attacker manipulates application input to alter the structure of a backend SQL query, allowing unauthorized data access, data modification, or in severe cases, command execution on the database server. In SIU Guaraní deployments, SQLi typically targets query parameters used to filter academic records (student IDs, course codes, grades) that are concatenated into SQL statements without proper parameterization. This is a fact-based description of the vulnerability class, not an assumption specific to any single deployment.

## Typical Indicators

- Apache access log entries containing SQL syntax fragments in the query string or POST body: `UNION SELECT`, `OR 1=1`, `' OR '1'='1`, `SLEEP(`, `BENCHMARK(`, `information_schema`, stacked queries (`;--`, `;#`).
- Repeated requests to the same endpoint with incrementally mutated payloads (typical of tools like sqlmap), often identifiable by a distinctive User-Agent (e.g. `sqlmap/...`) — note the User-Agent is trivially spoofable and should be treated as a weak indicator only.
- HTTP 500 responses correlated with injected payloads, suggesting the query broke and may have returned a database error to the client.
- Abnormally long query strings or parameter values compared to the endpoint's historical baseline.

## Possible Impact

- Unauthorized read access to student records, grades, or personal data (confidentiality breach, potential data protection/privacy violation).
- Unauthorized modification of academic records (integrity breach) — e.g. grade tampering.
- In blind/time-based scenarios, slow but systematic data exfiltration.
- If database privileges are misconfigured, potential lateral movement to the underlying OS (this is an assumption dependent on environment hardening, not a guaranteed outcome).

## Investigation

1. Confirm the payload actually reached the application layer (check if a WAF or reverse proxy already blocked it — look for the matching status code, e.g. 403).
2. Correlate the source IP across the full session: request frequency, sequence of endpoints touched, and whether payloads escalated in sophistication over time.
3. Cross-reference application/database logs (if available) for the same timestamp window to determine whether the query executed successfully or returned an error.
4. Check whether the targeted parameter/endpoint has known unsafe query construction (manual code review of the relevant controller, if source access is available).
5. Determine scope: was this a single probing request, or part of a systematic scan (many parameters/endpoints tested)?

## Containment

- Block or rate-limit the offending source IP at the perimeter (firewall/WAF), following existing incident response authorization procedures.
- If a WAF is present, verify and, if needed, tighten the ruleset covering SQLi signatures for the affected endpoint.
- Temporarily disable or restrict the affected endpoint/parameter if active exploitation is confirmed and a patch is not immediately available.
- Preserve logs and any database error output for forensic review before rotation/deletion.

## Recovery

- Patch the vulnerable code path to use parameterized queries/prepared statements or an ORM with safe query building; this is the durable fix, not a WAF rule alone.
- Apply least-privilege database accounts for the application (no `DROP`/`ALTER` rights for read-only interfaces).
- Review recent data for signs of tampering if successful exploitation is confirmed (e.g. unexpected grade changes, unexpected record exports).
- Re-enable the endpoint only after the fix is verified in a staging environment.

## False Positives

- Legitimate academic content containing SQL-like keywords (e.g. a course named "Introduction to SQL" or a forum post pasting example queries).
- Automated vulnerability scanners run by the institution's own security team without prior notice to the SOC.
- Overly broad heuristic/regex rules flagging common words that coincide with SQL keywords (e.g. "UNION" in a student union context).

## References

- OWASP Top 10 2021 – A03:2021 Injection.
- OWASP Testing Guide – Testing for SQL Injection (WSTG-INPV-05).
- MITRE ATT&CK – T1190 Exploit Public-Facing Application.
- Apache HTTP Server documentation – mod_log_config (access log format reference).
