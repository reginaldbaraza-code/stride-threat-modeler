# STRIDE Threat Modeling Methodology

## Overview

STRIDE is a threat classification framework developed at Microsoft in 1999 by Loren Kohnfelder and Praerit Garg. It provides a systematic approach to identifying security threats by categorizing them into six types based on the security property they violate.

## The Six Categories

### Spoofing (violates Authentication)

**What it is:** An attacker pretends to be someone or something else to gain unauthorized access.

**Examples:**
- Using stolen credentials to log in as another user
- Forging JWT tokens to impersonate a service
- DNS spoofing to redirect traffic
- Man-in-the-middle presenting a fake certificate

**Key question:** *Can an attacker pretend to be this component or its users?*

**Mitigations:** Multi-factor authentication, mutual TLS, certificate pinning, strong session management.

### Tampering (violates Integrity)

**What it is:** An attacker modifies data — at rest, in transit, or in memory — without authorization.

**Examples:**
- SQL injection modifying database records
- MITM altering API responses
- Modifying config files on a compromised server
- Altering log entries to cover tracks

**Key question:** *Can an attacker modify data processed or stored by this component?*

**Mitigations:** Input validation, parameterized queries, HMAC/digital signatures, TLS, file integrity monitoring.

### Repudiation (violates Non-repudiation)

**What it is:** A user or system performs an action and later denies it, with no way to prove otherwise.

**Examples:**
- No audit trail for admin actions
- Logs stored on the same server (attacker can delete them)
- No timestamps on financial transactions
- Missing identity in log entries

**Key question:** *Can someone perform an action and deny it?*

**Mitigations:** Centralized audit logging, tamper-proof log storage, digital signatures, timestamps.

### Information Disclosure (violates Confidentiality)

**What it is:** Data is exposed to unauthorized parties — through leaks, breaches, or misconfiguration.

**Examples:**
- Stack traces in production error responses
- PII stored without encryption
- API over-fetching returning unnecessary fields
- Credentials committed to git repositories

**Key question:** *Can an attacker access data they shouldn't?*

**Mitigations:** Encryption (at rest and in transit), access controls, data classification, error sanitization.

### Denial of Service (violates Availability)

**What it is:** An attacker makes a system unavailable to legitimate users.

**Examples:**
- Volumetric DDoS attack
- Resource exhaustion via large file uploads
- Slowloris keeping connections open
- Regex denial of service (ReDoS)

**Key question:** *Can an attacker make this component unavailable?*

**Mitigations:** Rate limiting, WAF, auto-scaling, circuit breakers, request size limits.

### Elevation of Privilege (violates Authorization)

**What it is:** An attacker gains capabilities beyond what they're authorized for.

**Examples:**
- IDOR allowing access to other users' data
- Missing authorization checks on admin endpoints
- JWT role manipulation
- Container escape to host system

**Key question:** *Can an attacker gain higher access than intended?*

**Mitigations:** RBAC/ABAC, least privilege, server-side authorization checks, tenant isolation.

## The Process

### Adam Shostack's Four Questions

1. **What are we building?** — Create a system model (DFD, architecture diagram)
2. **What can go wrong?** — Apply STRIDE to each element systematically
3. **What are we going to do about it?** — Define mitigations for each threat
4. **Did we do a good job?** — Review the model and iterate

### How This Tool Applies STRIDE

The analyzer walks through every component and data flow:

- For each **component**, it checks security properties (authentication, authorization, logging, encryption, input validation, hardening) and generates threats for missing controls.
- For each **data flow**, it checks encryption, protocol, data classification, and trust boundary crossings.
- Each threat is scored with **DREAD** for prioritization.
- Results are output as a structured report with actionable mitigations.

## When to Use STRIDE

STRIDE works best when applied:

- **Early in development** — during design/architecture phase
- **Before major changes** — new features, integrations, infrastructure changes
- **Periodically** — as part of security review cycles
- **After incidents** — to identify systemic gaps

## Limitations

- STRIDE is a classification system, not a complete methodology
- It doesn't quantify risk (that's what DREAD adds)
- It works at the architecture level, not code level
- It requires security knowledge to apply effectively
- It doesn't cover all threat types (e.g., social engineering, physical security)

## Further Reading

- Microsoft Threat Modeling Tool documentation
- Adam Shostack, "Threat Modeling: Designing for Security" (Wiley, 2014)
- OWASP Threat Modeling Process
