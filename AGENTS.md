# AGENTS.md

## General Principles

- Implement the work requested by the user. Avoid expanding the feature scope or inventing product requirements.
- Preserve the existing architecture where practical. Reuse established code and avoid unnecessary abstractions or duplicate implementations.

## Code Quality

- Follow the project's existing coding conventions and keep module responsibilities clear.
- Prefer verified implementations and introduce dependencies only when needed.
- Keep changes focused on the requested outcome.

## Correctness and Testing

- Add appropriate tests for substantive code changes and cover important boundary conditions.
- Run tests and report their actual results. Never invent test results or remove valid assertions to make a test pass.
- Do not hide compilation errors or warnings.

## Security

- Do not commit passwords, tokens, keys, or other sensitive data.
- Validate untrusted input, avoid unsafe defaults, and do not expand permissions without authorization.
- Clearly report security risks you discover.

## Documentation

- Update documentation when important behavior changes.
- Distinguish implemented, partially implemented, and unimplemented capabilities. Do not overstate support.
- Preserve references to applicable standards and external technical sources.

## Git Workflow

- Use a separate feature branch and Conventional Commits. Merge changes through a pull request that describes the changes and test results.
- Ensure CI passes before merging. Do not modify `main` without user authorization.
- Do not modify Rulesets or branch protection, or force-push, without authorization.
- Merge only with explicit authorization from the project maintainer.

## AI Collaboration

- AI-generated code requires review and is not automatically considered acceptable.
- Be able to explain and review significant implementations. Do not fabricate human review records or test evidence.
- The project maintainer is responsible for final acceptance.

## Local Maintainer Instructions

- If `PRIVATE_AGENTS.md` exists at the repository root, read it before starting work and treat it as supplementary local maintainer instructions.
- Do not modify or delete that file unless the maintainer explicitly requests it. Do not copy its contents into public documentation, commits, or pull requests, and never commit the file.
- If the file does not exist, follow this public `AGENTS.md` and the user's explicit task instructions.
