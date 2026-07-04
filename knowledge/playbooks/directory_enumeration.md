# Directory Enumeration

## Description

Directory (content) enumeration is a reconnaissance technique where an attacker systematically requests common paths and filenames — using wordlists — to discover hidden directories, backup files, administrative panels, or unlinked resources on a web server. It precedes exploitation rather than constituting exploitation itself.

## Typical Indicators

- A high volume of requests from a single source IP in a short time window, targeting many distinct paths that do not correspond to normal navigation (e.g. `/admin`, `/backup`, `/.git`, `/config.php.bak`, `/test`, `/old`).
- Sequential or wordlist-pattern requests (alphabetical, common CMS paths, numeric suffixes).
- High ratio of HTTP 404 responses relative to 200s for a single source IP — legitimate users rarely generate sustained 404 volume.
- User-Agent strings associated with enumeration tools (`dirb`, `gobuster`, `ffuf`, `dirbuster`, `wfuzz`), though this is a weak/spoofable indicator.
- Requests with no `Referer` header and no accompanying static asset requests (no CSS/JS/image fetches), inconsistent with a real browser session.

## Possible Impact

- Discovery of unlinked administrative interfaces, backup files, or exposed configuration, which can enable a follow-on targeted attack.
- Information disclosure if enumerated paths return directory listings or backup content directly.
- Typically a precursor event; on its own, low direct impact, but high value as an early-warning signal.

## Investigation

1. Aggregate all requests from the source IP over the session window and review the path list for a wordlist pattern.
2. Check the 404/200 ratio and total request volume against the endpoint's normal traffic baseline.
3. Identify any paths that returned 200 or 301/302 — these deserve individual review, since they confirm real resources were found.
4. Check timing between requests; sub-second intervals confirm automation.
5. Correlate with subsequent activity from the same IP (e.g. did enumeration precede a targeted SQLi or path traversal attempt on a discovered path?).

## Containment

- Rate-limit or temporarily block the source IP if request volume exceeds acceptable thresholds.
- Ensure sensitive paths discovered during the scan (if any responded with 200) are reviewed for whether they should be protected by authentication.
- Verify robots.txt and server configuration are not inadvertently listing sensitive paths.

## Recovery

- Remove or properly authenticate any exposed administrative/backup resources identified during the review.
- Disable directory listing at the web server configuration level (`Options -Indexes` in Apache) if not already disabled.
- Document discovered paths in the asset inventory so they can be monitored going forward.

## False Positives

- Legitimate crawlers (search engine bots) generating high request volume with varied paths; verify via reverse DNS/User-Agent against known good bot ranges.
- Institutional monitoring or uptime-checking tools probing multiple health-check endpoints.
- Browser extensions or link-preview services that prefetch multiple resources rapidly.
- Authorized penetration testing conducted without prior SOC notification.

## References

- OWASP Testing Guide – Map Application Architecture / Enumerate Applications on Webserver (WSTG-INFO-04).
- MITRE ATT&CK – T1595.003 Active Scanning: Wordlist Scanning.
- Apache HTTP Server documentation – mod_autoindex and Options directive.
