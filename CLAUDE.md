# CLAUDE.md — AI Assistant Guide for Veeam-Port-Checker

## Project Overview

**Veeam-Port-Checker** is a tool designed to verify that all required network ports for Veeam Backup & Replication are reachable between infrastructure components. Veeam solutions depend on dozens of specific TCP/UDP ports being open across backup servers, proxies, repositories, and managed hosts. This tool automates that validation process.

**Repository:** https://github.com/NextHeberg/Veeam-Port-Checker
**License:** MIT
**Status:** Early-stage — initial skeleton only, no implementation yet.

---

## Repository State (as of 2026-03-04)

```
Veeam-Port-Checker/
├── LICENSE          # MIT License, copyright NextHeberg 2026
├── README.md        # Project title only (to be expanded)
└── CLAUDE.md        # This file
```

There is currently **no source code**. The repository was created with a single initial commit. All implementation work is ahead.

---

## Project Purpose and Scope

### What it does
- Accepts a list of Veeam component pairs (source → destination, port, protocol)
- Attempts TCP/UDP connections to verify port reachability
- Reports open, closed, filtered, or timed-out ports
- Covers all official Veeam port requirements from Veeam documentation

### Target users
- Veeam administrators preparing new deployments
- Network engineers auditing firewall rules for Veeam environments
- Automation/CI pipelines validating infrastructure readiness before Veeam installation

### Veeam port reference
Veeam Backup & Replication requires ports such as:
- **9392** — Veeam Backup Service
- **9401** — Veeam Backup Cloud Gateway
- **2500–3300** — Data transfer channels (transport service)
- **135, 445** — Windows remote management (WMI, SMB)
- **6160, 6162** — Veeam Installer Service / Agent
- **443** — HTTPS for vCenter, ESXi, cloud endpoints
- **22** — SSH for Linux hosts

Refer to the official Veeam Help Center for the complete and up-to-date port list.

---

## Development Guidelines

### Language and runtime
No language has been decided yet. Likely candidates based on the Veeam ecosystem:
- **PowerShell** — native Windows, ideal for Veeam admin audiences
- **Python 3.x** — cross-platform, good library support for networking
- **Go** — single binary, easy distribution

When a language is chosen, update this file with:
- Minimum version requirement
- How to install dependencies
- How to run the tool
- How to run tests

### Coding conventions (to adopt once language is chosen)
- Keep functions small and single-purpose
- Separate networking logic from output/reporting logic
- Provide both machine-readable (JSON/CSV) and human-readable output formats
- Handle timeouts gracefully — a timed-out port is not the same as a refused connection
- Log verbosity should be controllable via a flag (`--verbose` / `-v`)
- Avoid hardcoding IP addresses or port lists in business logic; keep them in configuration or constants files

### Configuration
- Port definitions should live in a structured file (e.g., `ports.json`, `ports.yaml`, or a constants module) so they can be updated without touching core logic
- User-supplied targets (hosts, IPs) should come from CLI arguments or an input file, never hardcoded

### Error handling
- Network errors (timeout, refused, unreachable) must be caught and reported per port, not as fatal crashes
- Invalid input (bad IP format, unknown hostname) should produce a clear error message and exit with a non-zero code

---

## Workflow for AI Assistants

### Before making changes
1. Read all existing source files before modifying anything
2. Understand the current structure — do not assume files exist that aren't listed above
3. Check for any new files added since this CLAUDE.md was written using `git status` or by listing the directory

### Branching
- Development branches follow the pattern: `claude/<task-id>`
- The `master` branch is the main branch — only merge when work is complete and tested
- Never force-push to `master`

### Commits
- Write commit messages in the imperative mood: "Add port scanner module", not "Added..."
- One logical change per commit
- Reference issue numbers where applicable: "Fix timeout handling (#12)"

### Adding features
- Prefer editing existing files over creating new ones when extending functionality
- Do not add configuration options or flags unless they are needed for the current task
- Do not add comments explaining *what* the code does if the code is already self-explanatory; only comment *why* when the reason is non-obvious

### Testing
- Every new function that contains logic should have a corresponding unit test
- Network calls must be mockable/testable without a live Veeam environment
- Tests should live in a `tests/` directory (or language-idiomatic equivalent)

### Security
- Never hardcode credentials, tokens, or sensitive data
- Do not log sensitive information (passwords, keys) even in verbose mode
- Validate and sanitise all user-supplied host/IP inputs before using them in network calls

---

## Key Decisions to Document

When each of the following decisions is made, update this file:

| Decision | Status |
|---|---|
| Implementation language | Not decided |
| CLI argument parsing library | Not decided |
| Output formats supported | Not decided |
| Packaging/distribution method | Not decided |
| CI/CD platform | Not decided |
| Minimum OS support | Not decided |

---

## Updating This File

This CLAUDE.md should be updated whenever:
- A language or framework is chosen
- The project structure changes significantly
- New development conventions are established
- New dependencies are added
- The scope of the project changes
