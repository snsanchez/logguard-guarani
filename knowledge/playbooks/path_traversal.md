# Path Traversal

## Description

Attempts to access files outside the intended directory.

## Possible Impact

- Sensitive file disclosure
- Credential exposure
- Configuration leakage

## Investigation

- Review requested paths.
- Search for repeated traversal attempts.
- Verify application permissions.

## Containment

- Validate filesystem exposure.
- Review Apache configuration.
- Apply input validation.

## References

- MITRE T1190
