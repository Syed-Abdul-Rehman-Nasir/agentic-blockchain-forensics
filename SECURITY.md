# Security Policy

Agentic Blockchain Forensics is a research prototype for offline digital investigation. This document explains how to report security concerns and what is in scope.

## Supported versions

Security fixes are considered for the currently published `main` branch of this repository. Older snapshots and experimental forks are not actively maintained.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**. Do not open a public issue that includes exploit details, credentials, or sample evidence containing personal data.

Include, where possible:

- A clear description of the issue and affected component (UI, Node API, AI service, chaincode, or documentation).
- Steps to reproduce in a local mock-ledger environment.
- Impact assessment (confidentiality, integrity, availability, or chain-of-custody trust).
- Any suggested remediation.

You can contact the maintainer through the GitHub profile associated with this repository. Allow reasonable time for triage before any public discussion.

## Out of scope

- Issues that require committing real forensic images, case databases, or investigator credentials.
- Social-engineering against investigators or third-party services.
- Denial-of-service against external infrastructure you do not own.

## Repository hygiene

- Never commit `.env` files, Fabric private keys, or service credentials.
- Never commit disk images, ChromaDB corpora, SQLite case databases, or generated investigation reports that contain real evidence.
- Prefer mock ledger mode for reproduction cases unless a Fabric-specific defect is being reported.

## Design expectations

The system is intended to keep analysis results durable even when blockchain submission fails. Reports that show ledger unavailability wiping forensic results are treated as high priority.
