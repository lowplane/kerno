# Kerno Project Governance

## Overview

Kerno is an open-source project maintained by [Lowplane](https://github.com/lowplane) and governed by a small group of maintainers who are responsible for the project's technical direction, release management, and community health.

## Roles

### Users

Anyone who uses Kerno. Users are encouraged to participate by:
- Filing issues and feature requests
- Participating in discussions
- Providing feedback on releases

### Contributors

Anyone who contributes to Kerno through code, documentation, tests, reviews, or other means. Contributors are recognized in release notes and the CONTRIBUTORS file.

### Maintainers

Maintainers have write access to the repository and are responsible for:
- Reviewing and merging pull requests
- Triaging issues
- Making architectural decisions
- Cutting releases
- Enforcing the Code of Conduct

**Current Maintainers:**

| Name | GitHub | Focus Area |
|------|--------|------------|
| Shivam Kumar | [@btwshivam](https://github.com/btwshivam) | Project lead, core engine, eBPF programs |

### Becoming a Maintainer

Maintainers are invited based on sustained, high-quality contributions. The criteria are:

1. **Consistent contributions** over 3+ months
2. **Deep understanding** of at least one subsystem (BPF, collectors, doctor, CLI, dashboard)
3. **Good judgment** in code reviews
4. **Alignment** with project goals and values
5. **Nomination** by an existing maintainer + approval by majority of maintainers

## Decision Making

- **Day-to-day decisions** (bug fixes, minor features, documentation): Any maintainer can approve and merge.
- **Significant changes** (new subsystems, API changes, dependency additions): Require approval from 2+ maintainers.
- **Architectural decisions** (fundamental design changes, license changes, governance changes): Require consensus among all maintainers. Discussed in GitHub Discussions or issues with at least 7 days for review.

## Conflict Resolution

1. Technical disagreements are resolved through discussion on the relevant issue or PR.
2. If consensus cannot be reached, the project lead (Shivam Kumar) makes the final decision.
3. As the project grows, we will transition to a formal voting process.

## Code of Conduct

All participants in the Kerno community are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Changes to Governance

This document may be amended by consensus of all maintainers. Proposed changes must be open for review for at least 14 days.
