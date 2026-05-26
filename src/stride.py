"""
STRIDE Threat Identification Engine.

For each component and data flow in the model, systematically checks
for threats in all six STRIDE categories based on the component's
security properties.

The logic:
    - No authentication? → Spoofing risk
    - No encryption? → Tampering + Information Disclosure risk
    - No logging? → Repudiation risk
    - Internet-facing without hardening? → Denial of Service risk
    - No authorization? → Elevation of Privilege risk

Each rule produces a Threat object with a description, severity,
and recommended mitigation. Threats can then be scored with DREAD
for prioritization.

Usage:
    analyzer = StrideAnalyzer()
    threats = analyzer.analyze(threat_model)
"""

from dataclasses import dataclass
from enum import Enum

from src.model import (
    ThreatModel,
    Component,
    DataFlow,
    ComponentType,
    DataClassification,
)


class StrideCategory(Enum):
    """The six STRIDE threat categories."""

    SPOOFING = "Spoofing"
    """Impersonating a user, system, or service to gain unauthorized access."""

    TAMPERING = "Tampering"
    """Malicious modification of data at rest or in transit."""

    REPUDIATION = "Repudiation"
    """Ability to deny having performed an action, due to lack of audit trails."""

    INFORMATION_DISCLOSURE = "Information Disclosure"
    """Exposure of data to unauthorized parties."""

    DENIAL_OF_SERVICE = "Denial of Service"
    """Making a system or service unavailable to legitimate users."""

    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"
    """Gaining capabilities beyond what is authorized (e.g., user → admin)."""


@dataclass
class Threat:
    """
    A single identified security threat.

    Attributes:
        id: Unique identifier (e.g., "THR-001").
        category: Which STRIDE category this threat belongs to.
        title: Short summary of the threat.
        description: Detailed explanation of the threat scenario.
        target: Name of the component or data flow affected.
        severity: Initial severity estimate (refined by DREAD scoring).
        mitigation: Recommended security controls to address this threat.
        status: Current status (Open, Mitigated, Accepted, Transferred).
        dread_score: Populated after DREAD scoring (0-50).
    """

    id: str
    category: StrideCategory
    title: str
    description: str
    target: str
    severity: str = "Medium"
    mitigation: str = ""
    status: str = "Open"
    dread_score: int = 0

    def __str__(self) -> str:
        return f"[{self.id}] {self.category.value} — {self.title} ({self.severity})"


class StrideAnalyzer:
    """
    Analyzes a ThreatModel and produces a list of identified Threats.

    The analyzer walks through every component and data flow in the model,
    applying STRIDE-specific rules based on the element's security properties.

    Rules are intentionally explicit — each rule maps to a specific
    security property gap. This makes the analysis deterministic and
    auditable: you can trace every finding back to a specific property.

    Usage:
        analyzer = StrideAnalyzer()
        threats = analyzer.analyze(my_threat_model)

        for threat in threats:
            print(f"{threat.category.value}: {threat.title}")
    """

    def __init__(self):
        self._threat_counter = 0

    def analyze(self, model: ThreatModel) -> list[Threat]:
        """
        Run full STRIDE analysis on the threat model.

        Analyzes all components and data flows, returning a list
        of identified threats sorted by initial severity.
        """
        self._threat_counter = 0
        threats = []

        for component in model.components:
            threats.extend(self._analyze_component(component))

        for flow in model.dataflows:
            threats.extend(self._analyze_dataflow(flow))

        return threats

    def _next_id(self) -> str:
        """Generate the next sequential threat ID."""
        self._threat_counter += 1
        return f"THR-{self._threat_counter:03d}"

    # =========================================================================
    # Component Analysis Rules
    # =========================================================================

    def _analyze_component(self, comp: Component) -> list[Threat]:
        """Apply all STRIDE rules to a single component."""
        threats = []
        threats.extend(self._check_spoofing(comp))
        threats.extend(self._check_tampering(comp))
        threats.extend(self._check_repudiation(comp))
        threats.extend(self._check_denial_of_service(comp))
        threats.extend(self._check_elevation_of_privilege(comp))
        threats.extend(self._check_information_disclosure_component(comp))
        return threats

    def _check_spoofing(self, comp: Component) -> list[Threat]:
        """
        SPOOFING — Can an attacker pretend to be this component or its users?

        Checks:
        - Processes without authentication
        - Internet-facing components without strong auth
        """
        threats = []

        if comp.component_type == ComponentType.PROCESS and not comp.has_authentication:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.SPOOFING,
                title=f"Missing authentication on {comp.name}",
                description=(
                    f"'{comp.name}' does not implement authentication. "
                    f"An attacker could impersonate legitimate users or services "
                    f"to gain unauthorized access to this component's functionality."
                ),
                target=comp.name,
                severity="High" if comp.is_internet_facing else "Medium",
                mitigation=(
                    "Implement authentication using industry standards (OAuth 2.0, "
                    "OpenID Connect, SAML 2.0, or mTLS for service-to-service). "
                    "Validate all incoming identity claims. Consider multi-factor "
                    "authentication for sensitive operations."
                ),
            ))

        if comp.is_internet_facing and comp.has_authentication and not comp.is_hardened:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.SPOOFING,
                title=f"Internet-facing auth without hardening: {comp.name}",
                description=(
                    f"'{comp.name}' is internet-facing with authentication but lacks "
                    f"hardening. Attackers could exploit credential stuffing, brute force, "
                    f"or session hijacking to impersonate legitimate users."
                ),
                target=comp.name,
                severity="High",
                mitigation=(
                    "Implement account lockout policies, rate limiting on auth endpoints, "
                    "CAPTCHA for repeated failures, session token rotation, and secure "
                    "cookie flags (HttpOnly, Secure, SameSite)."
                ),
            ))

        return threats

    def _check_tampering(self, comp: Component) -> list[Threat]:
        """
        TAMPERING — Can an attacker modify data in this component?

        Checks:
        - Datastores without encryption at rest
        - Processes without input validation
        """
        threats = []

        if comp.component_type == ComponentType.DATASTORE and not comp.has_encryption_at_rest:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.TAMPERING,
                title=f"Unencrypted data store: {comp.name}",
                description=(
                    f"Data in '{comp.name}' is not encrypted at rest. An attacker with "
                    f"access to the storage layer (compromised credentials, insider threat, "
                    f"or physical access) could modify data without detection."
                ),
                target=comp.name,
                severity="High" if comp.handles_pii else "Medium",
                mitigation=(
                    "Enable encryption at rest using AES-256 or equivalent. "
                    "Implement data integrity checks (checksums, HMACs) to detect "
                    "unauthorized modifications. Use database audit logging to "
                    "track all write operations."
                ),
            ))

        if comp.component_type == ComponentType.PROCESS and not comp.has_input_validation:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.TAMPERING,
                title=f"Missing input validation on {comp.name}",
                description=(
                    f"'{comp.name}' does not perform input validation. Attackers could "
                    f"inject malicious payloads (SQL injection, XSS, command injection) "
                    f"to manipulate data processing or corrupt stored data."
                ),
                target=comp.name,
                severity="High" if comp.is_internet_facing else "Medium",
                mitigation=(
                    "Implement strict input validation using allowlists. Sanitize all "
                    "user input before processing. Use parameterized queries for database "
                    "operations. Apply Content Security Policy (CSP) headers for web UIs."
                ),
            ))

        return threats

    def _check_repudiation(self, comp: Component) -> list[Threat]:
        """
        REPUDIATION — Can someone deny performing an action?

        Checks:
        - Processes without audit logging
        - Components handling PII without logging
        """
        threats = []

        if comp.component_type == ComponentType.PROCESS and not comp.has_logging:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.REPUDIATION,
                title=f"Insufficient logging on {comp.name}",
                description=(
                    f"'{comp.name}' does not implement audit logging. Malicious actions "
                    f"performed through this component cannot be traced, attributed, "
                    f"or proven. This also hampers incident response and forensics."
                ),
                target=comp.name,
                severity="High" if comp.handles_pii else "Medium",
                mitigation=(
                    "Implement structured audit logging for all state-changing operations. "
                    "Each log entry should include: timestamp, actor identity, action "
                    "performed, affected resource, source IP, and outcome (success/failure). "
                    "Send logs to a tamper-proof centralized logging service (e.g., SIEM). "
                    "Ensure logs cannot be modified or deleted by application users."
                ),
            ))

        return threats

    def _check_denial_of_service(self, comp: Component) -> list[Threat]:
        """
        DENIAL OF SERVICE — Can an attacker make this component unavailable?

        Checks:
        - Internet-facing components without hardening
        - Components without rate limiting indicators
        """
        threats = []

        if comp.is_internet_facing and not comp.is_hardened:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.DENIAL_OF_SERVICE,
                title=f"Internet-facing without hardening: {comp.name}",
                description=(
                    f"'{comp.name}' is exposed to the internet without hardening measures. "
                    f"It is vulnerable to volumetric attacks (DDoS), application-layer "
                    f"attacks (Slowloris, resource exhaustion), and abuse from automated bots."
                ),
                target=comp.name,
                severity="High",
                mitigation=(
                    "Implement rate limiting per client/IP. Deploy a Web Application Firewall "
                    "(WAF) with DDoS protection. Use a CDN for static assets. Configure "
                    "auto-scaling for compute resources. Set maximum request size limits. "
                    "Implement circuit breakers for downstream dependencies."
                ),
            ))

        if comp.is_internet_facing and comp.component_type == ComponentType.PROCESS:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.DENIAL_OF_SERVICE,
                title=f"Resource exhaustion risk on {comp.name}",
                description=(
                    f"Internet-facing process '{comp.name}' could be targeted with "
                    f"requests designed to consume excessive memory, CPU, or disk "
                    f"(e.g., large file uploads, complex queries, regex bombs)."
                ),
                target=comp.name,
                severity="Medium",
                mitigation=(
                    "Set resource quotas (memory, CPU, connections). Implement request "
                    "timeouts. Limit upload sizes. Use async processing for heavy operations. "
                    "Monitor resource utilization and alert on anomalies."
                ),
            ))

        return threats

    def _check_elevation_of_privilege(self, comp: Component) -> list[Threat]:
        """
        ELEVATION OF PRIVILEGE — Can a user gain higher access than allowed?

        Checks:
        - Processes without authorization
        - Components handling PII without access controls
        """
        threats = []

        if comp.component_type == ComponentType.PROCESS and not comp.has_authorization:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                title=f"Missing authorization on {comp.name}",
                description=(
                    f"'{comp.name}' does not enforce authorization checks. An authenticated "
                    f"user could access resources or perform actions beyond their privilege "
                    f"level (e.g., accessing another tenant's data, modifying admin settings)."
                ),
                target=comp.name,
                severity="Critical" if comp.handles_pii else "High",
                mitigation=(
                    "Implement role-based access control (RBAC) or attribute-based access "
                    "control (ABAC). Enforce the principle of least privilege. Check "
                    "authorization on every request, not just at the UI level. For "
                    "multi-tenant systems, enforce tenant isolation at the data layer."
                ),
            ))

        if comp.component_type == ComponentType.DATASTORE and comp.handles_pii:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                title=f"PII datastore access control: {comp.name}",
                description=(
                    f"'{comp.name}' handles PII and requires strict access controls. "
                    f"Without proper access restrictions, any service or user with "
                    f"database connectivity could access sensitive personal data."
                ),
                target=comp.name,
                severity="High",
                mitigation=(
                    "Implement database-level access controls with dedicated service accounts "
                    "per application. Use row-level security for multi-tenant data. Restrict "
                    "direct database access — all queries should go through the application "
                    "layer. Implement data masking for non-production environments."
                ),
            ))

        return threats

    def _check_information_disclosure_component(self, comp: Component) -> list[Threat]:
        """
        INFORMATION DISCLOSURE — Can data leak from this component?

        Checks:
        - PII handlers without encryption
        - Internet-facing components that may expose internal details
        """
        threats = []

        if comp.handles_pii and comp.component_type == ComponentType.DATASTORE:
            if not comp.has_encryption_at_rest:
                threats.append(Threat(
                    id=self._next_id(),
                    category=StrideCategory.INFORMATION_DISCLOSURE,
                    title=f"PII stored without encryption: {comp.name}",
                    description=(
                        f"'{comp.name}' stores personally identifiable information without "
                        f"encryption at rest. A data breach (stolen backups, compromised "
                        f"storage) would expose raw PII, likely triggering GDPR or other "
                        f"regulatory notification requirements."
                    ),
                    target=comp.name,
                    severity="Critical",
                    mitigation=(
                        "Encrypt all PII at rest using AES-256. Implement key management "
                        "with regular rotation. Consider field-level encryption for the "
                        "most sensitive fields. Classify data per GDPR categories and "
                        "apply appropriate controls per classification."
                    ),
                ))

        if comp.is_internet_facing and comp.component_type == ComponentType.PROCESS:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.INFORMATION_DISCLOSURE,
                title=f"Information leakage via error responses: {comp.name}",
                description=(
                    f"Internet-facing process '{comp.name}' could expose internal "
                    f"details (stack traces, database schemas, internal IPs, software "
                    f"versions) through verbose error responses or debug endpoints."
                ),
                target=comp.name,
                severity="Medium",
                mitigation=(
                    "Return generic error messages to clients. Log detailed errors "
                    "server-side only. Disable debug endpoints in production. Remove "
                    "server version headers. Implement custom error pages."
                ),
            ))

        return threats

    # =========================================================================
    # Data Flow Analysis Rules
    # =========================================================================

    def _analyze_dataflow(self, flow: DataFlow) -> list[Threat]:
        """Apply STRIDE rules to a data flow, with extra scrutiny for boundary crossings."""
        threats = []

        # Unencrypted flow crossing trust boundary — critical
        if flow.crosses_trust_boundary and not flow.is_encrypted:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.INFORMATION_DISCLOSURE,
                title=f"Unencrypted data across trust boundary: {flow.name}",
                description=(
                    f"Data flow '{flow.name}' from '{flow.source.name}' to "
                    f"'{flow.destination.name}' crosses a trust boundary without "
                    f"encryption. Data classification: {flow.data_classification.value}. "
                    f"An attacker positioned on the network could intercept and read "
                    f"the transmitted data."
                ),
                target=flow.name,
                severity="Critical" if flow.data_classification in (
                    DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED
                ) else "High",
                mitigation=(
                    "Encrypt data in transit using TLS 1.3 (minimum TLS 1.2). "
                    "Validate server certificates. Consider certificate pinning "
                    "for service-to-service communication."
                ),
            ))

        # Tampering risk on boundary crossings
        if flow.crosses_trust_boundary:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.TAMPERING,
                title=f"Data integrity risk at boundary: {flow.name}",
                description=(
                    f"Data flow '{flow.name}' crosses a trust boundary from "
                    f"'{flow.source.name}' to '{flow.destination.name}'. "
                    f"Data could be modified in transit by a man-in-the-middle "
                    f"attacker or a compromised intermediary."
                ),
                target=flow.name,
                severity="High" if flow.data_classification in (
                    DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED
                ) else "Medium",
                mitigation=(
                    "Use HMAC or digital signatures for data integrity verification. "
                    "Implement mutual TLS (mTLS) for service-to-service communication. "
                    "Validate message integrity at the receiving end."
                ),
            ))

        # Auth token in unencrypted flow
        if flow.has_auth_token and not flow.is_encrypted:
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.SPOOFING,
                title=f"Auth credentials in unencrypted flow: {flow.name}",
                description=(
                    f"Data flow '{flow.name}' carries authentication tokens over "
                    f"an unencrypted channel. Credentials could be intercepted "
                    f"and replayed to impersonate the authenticated user."
                ),
                target=flow.name,
                severity="Critical",
                mitigation=(
                    "Never transmit credentials over unencrypted channels. Use TLS "
                    "for all flows carrying auth tokens. Implement token expiration "
                    "and rotation. Use short-lived tokens where possible."
                ),
            ))

        # Sensitive data over non-HTTPS
        if (flow.data_classification in (DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED)
                and flow.protocol.value == "http"):
            threats.append(Threat(
                id=self._next_id(),
                category=StrideCategory.INFORMATION_DISCLOSURE,
                title=f"Sensitive data over HTTP: {flow.name}",
                description=(
                    f"Data flow '{flow.name}' transmits {flow.data_classification.value} "
                    f"data using plain HTTP. This data is readable by anyone with "
                    f"network access between source and destination."
                ),
                target=flow.name,
                severity="Critical",
                mitigation="Switch to HTTPS immediately. Redirect all HTTP to HTTPS.",
            ))

        return threats
