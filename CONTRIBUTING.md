# Contributing

Thank you for your interest in Agentic Blockchain Forensics. This guide describes how to set up a development environment, propose changes, and keep forensic evidence and secrets out of the repository.

## Development environment

1. Use **WSL2 Ubuntu 22.04** for the full stack (Python AI service, Node API, and Electron UI).
2. Create a Python 3.11 virtual environment and install dependencies from `requirements.txt`.
3. Install Node.js dependencies in `backend-node/` and `ui/`.
4. Copy `backend-node/.env.example` to `backend-node/.env` and configure `OLLAMA_HOST` as needed.
5. Prefer mock-ledger mode (`USE_REAL_FABRIC=false`) for local iteration unless you intentionally exercise Hyperledger Fabric.

See the [README](README.md) for the complete setup and run instructions.

## Branch and commit conventions

- Create a focused branch for each change (for example, `docs/security-policy` or `fix/report-preview`).
- Prefer [Conventional Commits](https://www.conventionalcommits.org/): `feat`, `fix`, `docs`, `chore`, `refactor`, `test`.
- Keep commits small and reviewable. Avoid mixing unrelated documentation and code changes.
- Do not rewrite published history on shared branches.

## Validation before opening a pull request

- Confirm the AI service health endpoint responds on port `8000`.
- Confirm the Node API health endpoint responds on port `3000`.
- Smoke-test the Electron UI against a disposable local case when UI behaviour changes.
- Run relevant automated tests when Python or API behaviour is affected (`pytest` for the AI service).
- Ensure no secrets, absolute personal paths, or forensic images are included in the diff.

## Forensic data and secrets

- Never commit disk images, case databases, ChromaDB stores, generated reports, or `.env` files.
- Use the placeholders under `data/` (`.gitkeep` files) rather than real evidence.
- Scrub screenshots and logs of host usernames, credentials, and private network endpoints before sharing.

## Pull requests

- Describe the problem, the approach, and how you validated the change.
- Link related issues when applicable.
- Keep the scope limited so reviewers can assess risk to evidence integrity and offline operation.
