# SQL Injection

## Description

Attempts to manipulate SQL queries through user-controlled input.

## Possible Impact

- Authentication bypass
- Data disclosure
- Data modification
- Remote code execution (application dependent)

## Investigation

- Review affected URL.
- Inspect application logs.
- Correlate with database logs.
- Verify authentication attempts.

## Containment

- Validate WAF logs.
- Block malicious IP if confirmed.
- Review vulnerable endpoint.

## References

- OWASP A03:2021
- MITRE ATT&CK T1190
