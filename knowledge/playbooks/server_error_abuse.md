# Server Error Abuse

## Description

This category covers patterns where an attacker deliberately triggers server-side errors (HTTP 5xx) to fingerprint the application stack, extract information from verbose error/debug output (stack traces, file paths, SQL fragments), or probe for exploitable edge cases in error handling. This differs from an isolated organic 500 error, which reflects a defect rather than intentional probing.

## Typical Indicators

- Repeated requests from a single source IP with deliberately malformed input (unexpected data types, oversized payloads, unusual encoding, null bytes) correlated with HTTP 500/502/503 responses.
- A pattern of systematically varying one parameter at a time across many requests, consistent with an attacker mapping which inputs trigger errors.
- Error responses with unusually large body size compared to the endpoint's typical error page, suggesting verbose debug output (stack traces) is being returned.
- Spikes in 5xx rate concentrated on specific endpoints rather than distributed across the whole application (suggests a targeted weakness rather than general instability).

## Possible Impact

- Information disclosure through verbose error messages (file paths, framework/library versions, database structure, internal IP addresses).
- Fingerprinting that enables a more targeted subsequent attack (e.g. discovering the exact ORM or database in use to craft a working SQLi payload).
- If errors are triggered at high volume, potential resource exhaustion / partial denial of service.

## Investigation

1. Sample several of the error responses (if response bodies are logged/available) to determine whether they leak sensitive internal details.
2. Determine whether the error pattern is concentrated on one endpoint/parameter (suggests targeted probing) or spread broadly (may suggest a scanner or a genuine application-wide defect).
3. Check whether the request payloads correlate with known attack primitives (SQLi, path traversal) that happened to fail rather than succeed — server errors are frequently a byproduct of a failed exploitation attempt, not a distinct attack type on its own.
4. Review whether debug mode or verbose error reporting is enabled in the production configuration (a configuration issue independent of the specific requests observed).

## Containment

- Ensure the application is configured to return generic error pages in production (disable debug/verbose error output) — this is a configuration hardening step, not an active blocking action, but should be flagged for urgent remediation.
- Block or rate-limit the source IP if the error-triggering pattern is high-volume and clearly deliberate.
- Correlate with other categories (SQLi, Path Traversal) and apply their containment steps if the underlying payload matches those patterns.

## Recovery

- Disable verbose/debug error reporting in the production environment if found enabled; route detailed errors to internal logs only.
- Fix the specific input-handling defect that allowed the error to be triggered, if identified.
- Review recent logs for any evidence that leaked information (from prior verbose errors) was subsequently used in a targeted attack.

## False Positives

- Genuine application bugs triggered by legitimate but unusual user input (e.g. edge-case data entry), with no repeated systematic pattern.
- Third-party integrations sending malformed requests due to their own misconfiguration rather than malicious intent.
- Load-testing or QA activity conducted against the production or a shared environment without SOC notification.

## References

- OWASP Top 10 2021 – A05:2021 Security Misconfiguration (verbose error handling).
- OWASP Testing Guide – Testing for Error Handling (WSTG-ERRH-01, WSTG-ERRH-02).
- MITRE ATT&CK – T1592 Gather Victim Host Information (fingerprinting via error responses is a common sub-goal, not a distinct top-level technique).
- Apache HTTP Server documentation – ErrorDocument directive and custom error page configuration.
