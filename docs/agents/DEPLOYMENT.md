# Deployment

Development:

Python virtual environment.

Production:

Docker or Podman containers.

Container requirements:

- Run as non-root user.
- Read-only source code.
- Logs mounted through volumes.

Example:

podman run \
-v /logs:/data \
logguard-guarani:latest

Future:

Kubernetes deployment for testing and educational environments.
