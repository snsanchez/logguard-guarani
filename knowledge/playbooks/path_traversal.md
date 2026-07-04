# Path Traversal

## Description

Path Traversal (also known as Directory Traversal) exploits insufficient input sanitization in file path handling, allowing an attacker to access files or directories outside the web root by injecting relative path sequences. In an SIU Guaraní context, this typically targets endpoints that serve or reference files by parameter (document downloads, report exports, template includes).

## Typical Indicators

- Requests containing `../`, `..\\`, URL-encoded variants (`%2e%2e%2f`, `%2e%2e/`, `..%c0%af`), or double-encoded sequences (`%252e%252e%252f`) in the URL path or query string.
- Attempts to reach known sensitive files: `/etc/passwd`, `web.config`, `.htaccess`, `wp-config.php` (even if not applicable to the stack, these appear in generic scans), or application configuration files.
- Repeated requests with varying encoding of the same traversal depth (`../`, `../../`, `../../../`), consistent with automated fuzzing.
- HTTP 400/403/404 responses to traversal attempts, indicating the web server or filesystem rejected the path, versus HTTP 200 with unexpected content length, which may indicate success.

## Possible Impact

- Disclosure of configuration files containing credentials, database connection strings, or secret keys.
- Disclosure of source code, enabling further vulnerability discovery.
- In write-capable contexts (e.g. file upload combined with traversal), potential arbitrary file write — this is a compounded scenario and should be treated as an assumption unless a write primitive is separately confirmed.

## Investigation

1. Check the HTTP response status and content length for the specific request; a 200 with non-trivial body size on a traversal attempt warrants immediate escalation.
2. Identify which endpoint/parameter accepted the file path input and review whether it performs path canonicalization or a whitelist check.
3. Search logs for prior or subsequent requests from the same source IP targeting other file-serving endpoints.
4. If a successful read is suspected, determine which file was targeted and assess what sensitive data it may contain.
5. Verify whether the web server's own directory permissions would have prevented access even if the application logic failed (defense-in-depth check).

## Containment

- Block the source IP if traversal attempts are repeated or targeted at sensitive paths.
- Verify and, if needed, tighten WAF/reverse-proxy rules for encoded traversal sequences (including double-encoding).
- If a specific endpoint is confirmed vulnerable, temporarily disable file-serving functionality for that endpoint until remediated.
- Restrict the web server process's filesystem permissions to the minimum required directories (defense in depth, independent of the application fix).

## Recovery

- Fix the vulnerable code to canonicalize paths (resolve `..` sequences) and validate the result against an allow-list of permitted directories/files, rather than relying on blacklist filtering alone.
- Rotate any credentials or secrets present in files that may have been disclosed.
- Audit file access logs (OS-level, if available) to confirm whether the targeted file was actually read by the web server process.
- Re-enable the endpoint only after validation logic is verified.

## False Positives

- Automated link checkers or crawlers that mis-resolve relative URLs, producing benign `../` sequences without malicious intent.
- Legitimate applications using literal filenames that happen to contain a double dot (rare, but possible in uploaded filenames).
- Institutional vulnerability scans conducted without SOC notification.

## References

- OWASP Top 10 2021 – A01:2021 Broken Access Control (Path Traversal is commonly classified here).
- OWASP Testing Guide – Testing Directory Traversal / File Include (WSTG-ATHZ-01).
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory.
- MITRE ATT&CK – T1190 Exploit Public-Facing Application.
