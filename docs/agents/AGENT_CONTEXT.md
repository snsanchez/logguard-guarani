# Agent Context

Read this file before making changes.

Project: LogGuard Guaraní

Author: Santiago Sánchez

Purpose:<>

Educational defensive security project for analyzing Apache logs from SIU Guaraní systems.

Important constraints:

- Defensive use only.
- Focus on explainability.
- Prefer simple and maintainable code.
- Keep architecture modular.
- Avoid introducing unnecessary frameworks.

Future AI architecture

The AI agent is NOT responsible for detecting attacks.

Detection is performed by:

- parser
- heuristics
- scoring
- ML classifier

The AI agent receives only enriched events.

Its responsibility is:

- explain the event
- estimate impact
- suggest defensive actions
- prioritize incidents
- generate SOC-style reports

The AI agent must never:

- modify infrastructure
- execute commands
- recommend offensive actions
- assume information not present in the event

Future plans:

- Real-time log processing.
- Kubernetes experimentation.

When suggesting code:

- Explain why.
- Prefer minimal modifications.
- Respect existing project structure.
