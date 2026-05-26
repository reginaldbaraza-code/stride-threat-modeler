"""
Threat Knowledge Base.

A curated catalog of common threats organized by STRIDE category,
with recommended mitigations and references.

This serves as:
1. Educational reference for learning STRIDE
2. Input for the automated analyzer (future enhancement)
3. Template for threat descriptions in reports

Usage:
    db = ThreatKnowledgeBase()
    spoofing_threats = db.get_threats_by_category("Spoofing")
    mitigations = db.get_mitigations("auth_bypass")
"""

from dataclasses import dataclass, field


@dataclass
class ThreatTemplate:
    """A template for a common threat pattern."""

    id: str
    category: str
    name: str
    description: str
    indicators: list[str]
    mitigations: list[str]
    references: list[str] = field(default_factory=list)
    severity_range: str = "Medium-High"


# Curated threat catalog
THREAT_CATALOG: list[ThreatTemplate] = [
    # === SPOOFING ===
    ThreatTemplate(
        id="S01",
        category="Spoofing",
        name="Authentication Bypass",
        description=(
            "An attacker bypasses the authentication mechanism to gain "
            "access without valid credentials. This can occur through "
            "default credentials, broken auth logic, or session manipulation."
        ),
        indicators=[
            "No authentication on endpoints",
            "Default credentials in use",
            "Session tokens without expiration",
            "Missing MFA for admin access",
        ],
        mitigations=[
            "Implement OAuth 2.0 / OpenID Connect",
            "Enforce MFA for privileged operations",
            "Use strong session management with token rotation",
            "Disable default accounts and credentials",
            "Implement account lockout after failed attempts",
        ],
        references=[
            "OWASP Authentication Cheatsheet",
            "CWE-287: Improper Authentication",
        ],
        severity_range="High-Critical",
    ),
    ThreatTemplate(
        id="S02",
        category="Spoofing",
        name="Token/Session Hijacking",
        description=(
            "An attacker steals or forges authentication tokens to "
            "impersonate a legitimate user. Common vectors include "
            "XSS to steal cookies, network sniffing, or predictable tokens."
        ),
        indicators=[
            "Tokens transmitted over HTTP",
            "Long-lived tokens without rotation",
            "Missing HttpOnly/Secure cookie flags",
            "Tokens in URL parameters",
        ],
        mitigations=[
            "Use HTTPS everywhere",
            "Set HttpOnly, Secure, and SameSite cookie flags",
            "Implement token rotation and short expiration",
            "Never put tokens in URLs or logs",
            "Bind tokens to client fingerprint (IP, User-Agent)",
        ],
        severity_range="High-Critical",
    ),
    ThreatTemplate(
        id="S03",
        category="Spoofing",
        name="Service Impersonation",
        description=(
            "An attacker impersonates a legitimate service in a "
            "microservices architecture to intercept or redirect traffic."
        ),
        indicators=[
            "No mutual TLS between services",
            "Services trust based on network location only",
            "No service identity verification",
        ],
        mitigations=[
            "Implement mutual TLS (mTLS) for service-to-service",
            "Use service mesh with identity (Istio, Linkerd)",
            "Verify service certificates on each connection",
        ],
        severity_range="High",
    ),

    # === TAMPERING ===
    ThreatTemplate(
        id="T01",
        category="Tampering",
        name="SQL Injection",
        description=(
            "An attacker injects malicious SQL through user input "
            "to modify database queries, potentially reading, modifying, "
            "or deleting data."
        ),
        indicators=[
            "String concatenation in SQL queries",
            "No input validation on user-facing fields",
            "Raw user input in database operations",
        ],
        mitigations=[
            "Use parameterized queries / prepared statements",
            "Implement input validation with allowlists",
            "Use an ORM with automatic parameterization",
            "Apply principle of least privilege for DB accounts",
        ],
        references=["CWE-89: SQL Injection", "OWASP SQL Injection Prevention"],
        severity_range="High-Critical",
    ),
    ThreatTemplate(
        id="T02",
        category="Tampering",
        name="Man-in-the-Middle (MITM)",
        description=(
            "An attacker intercepts and modifies data in transit "
            "between two components, potentially altering requests, "
            "responses, or injecting malicious content."
        ),
        indicators=[
            "HTTP used instead of HTTPS",
            "No certificate validation",
            "Mixed content on web pages",
        ],
        mitigations=[
            "Enforce TLS 1.3 (minimum 1.2) for all connections",
            "Implement HSTS headers",
            "Use certificate pinning for critical connections",
            "Validate certificate chains",
        ],
        severity_range="High",
    ),

    # === REPUDIATION ===
    ThreatTemplate(
        id="R01",
        category="Repudiation",
        name="Missing Audit Trail",
        description=(
            "The system lacks logging for security-relevant events, "
            "making it impossible to trace who performed what action "
            "and when. This hampers incident response and forensics."
        ),
        indicators=[
            "No centralized logging",
            "Missing timestamps on actions",
            "No actor identity in log entries",
            "Logs stored on the same system they audit",
        ],
        mitigations=[
            "Implement structured audit logging (who, what, when, where, outcome)",
            "Send logs to a centralized, tamper-proof SIEM",
            "Log all authentication events (success and failure)",
            "Log all authorization decisions and data access",
            "Implement log integrity protection (signing, write-once storage)",
        ],
        severity_range="Medium-High",
    ),

    # === INFORMATION DISCLOSURE ===
    ThreatTemplate(
        id="I01",
        category="Information Disclosure",
        name="Sensitive Data Exposure",
        description=(
            "Sensitive data (PII, credentials, financial data) is "
            "exposed through unencrypted storage, verbose errors, "
            "logging, or API responses."
        ),
        indicators=[
            "PII in log files",
            "Credentials in config files or repos",
            "Stack traces in production error responses",
            "API responses including unnecessary fields",
        ],
        mitigations=[
            "Encrypt sensitive data at rest and in transit",
            "Implement field-level encryption for PII",
            "Sanitize error responses in production",
            "Use API response filtering to return only needed fields",
            "Scan repos for accidentally committed secrets",
        ],
        references=["CWE-200: Exposure of Sensitive Information"],
        severity_range="High-Critical",
    ),

    # === DENIAL OF SERVICE ===
    ThreatTemplate(
        id="D01",
        category="Denial of Service",
        name="Resource Exhaustion",
        description=(
            "An attacker causes the system to consume excessive resources "
            "(CPU, memory, disk, connections) through crafted requests, "
            "making the service unavailable to legitimate users."
        ),
        indicators=[
            "No rate limiting on API endpoints",
            "Unlimited file upload sizes",
            "Complex queries without timeouts",
            "No connection pooling limits",
        ],
        mitigations=[
            "Implement rate limiting per client/IP/user",
            "Set request size limits and timeouts",
            "Use connection pooling with limits",
            "Implement circuit breakers for downstream calls",
            "Configure auto-scaling for elastic capacity",
        ],
        severity_range="Medium-High",
    ),

    # === ELEVATION OF PRIVILEGE ===
    ThreatTemplate(
        id="E01",
        category="Elevation of Privilege",
        name="Insecure Direct Object Reference (IDOR)",
        description=(
            "An attacker manipulates object identifiers (e.g., user IDs, "
            "file paths) to access resources belonging to other users "
            "or tenants."
        ),
        indicators=[
            "Sequential/predictable resource IDs in URLs",
            "No ownership checks on resource access",
            "Client-side only authorization checks",
        ],
        mitigations=[
            "Use UUIDs instead of sequential IDs",
            "Implement server-side ownership verification on every request",
            "Use tenant-scoped queries (WHERE tenant_id = :tenant)",
            "Never trust client-supplied identity claims for authorization",
        ],
        references=["CWE-639: Authorization Bypass Through User-Controlled Key"],
        severity_range="High-Critical",
    ),
    ThreatTemplate(
        id="E02",
        category="Elevation of Privilege",
        name="Privilege Escalation via Role Manipulation",
        description=(
            "An attacker modifies their role or permissions through "
            "API manipulation, parameter tampering, or exploiting "
            "missing server-side checks."
        ),
        indicators=[
            "Role information stored client-side (JWT without server validation)",
            "Missing authorization checks on admin endpoints",
            "Role assignment through user-controllable parameters",
        ],
        mitigations=[
            "Validate roles server-side on every request",
            "Implement RBAC with principle of least privilege",
            "Separate admin endpoints behind additional auth",
            "Audit and alert on role changes",
        ],
        severity_range="High-Critical",
    ),
]


class ThreatKnowledgeBase:
    """Query interface for the threat catalog."""

    def __init__(self):
        self._catalog = THREAT_CATALOG

    def get_all(self) -> list[ThreatTemplate]:
        """Return all threat templates."""
        return self._catalog

    def get_by_category(self, category: str) -> list[ThreatTemplate]:
        """Get threats for a specific STRIDE category."""
        return [t for t in self._catalog if t.category.lower() == category.lower()]

    def get_by_id(self, threat_id: str) -> ThreatTemplate | None:
        """Get a specific threat by ID."""
        for t in self._catalog:
            if t.id == threat_id:
                return t
        return None

    def search(self, keyword: str) -> list[ThreatTemplate]:
        """Search threats by keyword in name or description."""
        keyword = keyword.lower()
        return [
            t for t in self._catalog
            if keyword in t.name.lower() or keyword in t.description.lower()
        ]
