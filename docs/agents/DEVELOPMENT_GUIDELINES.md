# Development Guidelines

General principles:

- Simplicity over complexity.
- Prefer standard library when possible.
- Avoid unnecessary dependencies.
- Security first.
- Educational value is important.

Code style:

- Clear function names.
- Small modules.
- Explicit imports.
- No hidden side effects.

When modifying the project:

- Preserve backward compatibility.
- Do not remove CLI options without discussion.
- Prefer incremental changes.
- Keep Docker images reproducible.

Machine learning:

- Models must be explainable.
- Avoid black-box architectures.
- SVM is preferred over deep learning for now.
