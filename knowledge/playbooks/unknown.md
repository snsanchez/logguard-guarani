# Unknown Event

## Description

This is a catch-all category for events that the upstream heuristics/scoring/SVM pipeline flagged as anomalous but that do not cleanly match any of the defined attack categories (SQL Injection, Path Traversal, Directory Enumeration, Scanner Detection, Suspicious User-Agent, Brute Force, Server Error Abuse). The AI SOC agent's role here is explicitly to report the anomaly transparently and request human classification, not to guess a category to force a fit — this is a factual constraint of the architecture, not a stylistic preference.

## Typical Indicators

- Statistical anomaly flagged by the ML/SVM stage (unusual feature combination, low confidence across all trained classes, or a score near the decision boundary between two categories).
- Traffic patterns that are novel relative to the training data (new endpoint suddenly receiving unusual traffic, unfamiliar parameter names, an unrecognized payload structure).
- Combinations of otherwise-benign indicators that are individually unremarkable but jointly unusual (e.g. normal-looking request but from a geolocation or time-of-day never seen for that account).

## Possible Impact

- Unknown by definition. Impact must be assessed case-by-case; the report should explicitly state that impact could not be determined by the automated pipeline and requires analyst judgment.
- Could represent a novel attack technique not covered by the existing heuristics, a benign but unusual legitimate use case, or a data/labeling gap in the ML model.

## Investigation

1. Present the analyst with the full enriched event context (raw log line, all extracted features, heuristic scores, and the ML model's confidence/probability distribution across known classes) rather than a forced single-category verdict.
2. Compare the event against recent similar "unknown" events to check for an emerging pattern that may warrant a new detection category.
3. Manually inspect the raw request/response for recognizable attack syntax that the automated parser may have missed (e.g. an encoding scheme not covered by existing heuristics).
4. Check whether the source IP or account has any history in other confirmed categories.
5. If a genuine new attack pattern is confirmed, document it for potential addition to the heuristics/scoring layer and this knowledge base — this is a recommendation for the human team, not an action the AI agent performs autonomously.

## Containment

- Apply conservative, generic containment proportional to confidence: increased monitoring of the source IP/account is appropriate at low confidence; only escalate to blocking if independent human review confirms malicious intent.
- Do not take irreversible action (e.g. permanent IP bans, account suspension) based solely on an "Unknown" classification without human confirmation.

## Recovery

- No specific recovery steps apply until the event is reclassified; recovery actions should follow the playbook of whichever category the event is ultimately confirmed to belong to.
- If the event is confirmed benign, feed the classification back into the pipeline's training/heuristics as a labeled example to reduce future false "unknown" flags (a process recommendation, not something the AI agent executes itself).

## False Positives

- Legitimate but rare application features that are simply underrepresented in the training data (e.g. a seasonal enrollment period generating traffic patterns not seen during model training).
- New legitimate integrations or endpoints added to the system after the model was last trained.
- Sensor/parsing errors (malformed log lines, encoding issues) that produce nonsensical feature values unrelated to any real security event.

## References

- NIST SP 800-61 Rev. 2 – Computer Security Incident Handling Guide (general triage and escalation practices for ambiguous events).
- MITRE ATT&CK – no single mapping applies; analysts should consult the framework broadly once the event is manually characterized.
- OWASP Testing Guide – general principle of manual verification following automated detection (applies broadly, no single WSTG reference).
