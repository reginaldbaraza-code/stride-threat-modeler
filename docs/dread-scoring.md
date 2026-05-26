# DREAD Risk Scoring Guide

## Overview

DREAD is a qualitative risk assessment model used to prioritize identified threats. Each threat is scored across five dimensions on a scale of 1–10, producing a total score of 5–50.

## Dimensions

### Damage (1–10)

*How bad is it if the threat is exploited?*

| Score | Impact |
|-------|--------|
| 1–3 | Minor inconvenience, no data loss |
| 4–6 | Partial data exposure, service degradation |
| 7–8 | Significant data breach, extended outage |
| 9–10 | Complete system compromise, all data exposed |

### Reproducibility (1–10)

*How easy is it to reproduce the attack?*

| Score | Difficulty |
|-------|-----------|
| 1–3 | Requires specific timing, race conditions, or rare state |
| 4–6 | Reproducible with some effort and knowledge |
| 7–8 | Easily reproducible with basic tools |
| 9–10 | Trivially reproducible, automated |

### Exploitability (1–10)

*How much skill and tooling is needed?*

| Score | Skill Level |
|-------|------------|
| 1–3 | Nation-state capabilities, custom tooling |
| 4–6 | Experienced attacker, available tools |
| 7–8 | Intermediate skills, common tools (Burp, nmap) |
| 9–10 | No special skills, browser-only attack |

### Affected Users (1–10)

*What percentage of users are impacted?*

| Score | Scope |
|-------|-------|
| 1–3 | Single user in rare conditions |
| 4–6 | Subset of users (one tenant, one region) |
| 7–8 | Most users or all users of a feature |
| 9–10 | All users, all tenants |

### Discoverability (1–10)

*How easy is it to discover the vulnerability?*

| Score | Visibility |
|-------|-----------|
| 1–3 | Requires source code access or deep internal knowledge |
| 4–6 | Discoverable through targeted testing |
| 7–8 | Visible in public documentation or API responses |
| 9–10 | Obvious from the URL bar or public interface |

## Severity Mapping

| Total Score | Severity | Action |
|-------------|----------|--------|
| 40–50 | Critical | Fix immediately, block release |
| 30–39 | High | Fix before next release |
| 20–29 | Medium | Schedule for upcoming sprint |
| 10–19 | Low | Add to backlog |
| 5–9 | Informational | Document and monitor |

## Using DREAD in Practice

### Team Scoring Sessions

In a real threat modeling session, DREAD scores should be discussed by the team:

1. Present each identified threat
2. Each team member scores independently
3. Discuss disagreements (they often reveal misunderstandings)
4. Agree on final scores
5. Use scores to prioritize the remediation backlog

### Automated vs Manual Scoring

This tool provides heuristic auto-scoring as a starting point. The heuristics use the STRIDE category and initial severity to estimate DREAD dimensions. For production use, refine scores manually during team review sessions using `DreadScorer.manual_score()`.

### Limitations of DREAD

- Subjective — different teams may score differently
- "Discoverability" is debated (some argue you should assume everything is discoverable)
- Doesn't account for business context or threat actor capability
- Better for relative prioritization than absolute risk measurement

### Alternatives

- **CVSS** — Common Vulnerability Scoring System (more granular, industry standard)
- **FAIR** — Factor Analysis of Information Risk (quantitative, financial focus)
- **Risk Rating** — OWASP Risk Rating Methodology (likelihood × impact)
