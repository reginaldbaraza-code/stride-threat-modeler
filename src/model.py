"""
Core data model for defining system architectures.

Users describe their system using these building blocks,
then the STRIDE engine analyzes them for threats.

Inspired by OWASP pytm but simplified and modernized with
pure Python dataclasses — no external dependencies needed.

Usage:
    tm = ThreatModel(name="My App")
    server = Component(name="API Server", component_type=ComponentType.PROCESS)
    tm.add_component(server)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ComponentType(Enum):
    """Types of system components in a Data Flow Diagram."""

    PROCESS = "process"
    """Application, service, API endpoint, or function that processes data."""

    DATASTORE = "datastore"
    """Database, file system, cache, message queue, or any persistent storage."""

    EXTERNAL_ENTITY = "external"
    """User, browser, third-party service, or anything outside your control."""

    LAMBDA = "lambda"
    """Serverless function or ephemeral compute (AWS Lambda, Azure Functions)."""


class DataClassification(Enum):
    """Data sensitivity levels — drives severity scoring in STRIDE analysis."""

    PUBLIC = "public"
    """Publicly available information. Exposure has no impact."""

    INTERNAL = "internal"
    """Internal company data. Not meant for public consumption."""

    CONFIDENTIAL = "confidential"
    """Business-sensitive data. Exposure could cause financial or reputational harm."""

    RESTRICTED = "restricted"
    """PII, financial data, health records. Subject to regulatory requirements (GDPR, etc.)."""


class Protocol(Enum):
    """Communication protocols used in data flows."""

    HTTPS = "https"
    HTTP = "http"
    GRPC = "grpc"
    SQL = "sql"
    AMQP = "amqp"
    WEBSOCKET = "websocket"
    SSH = "ssh"
    SMTP = "smtp"
    INTERNAL = "internal"


@dataclass
class Component:
    """
    A system component — the nodes in a Data Flow Diagram.

    Security properties on this component drive the STRIDE analysis.
    Setting a property to False doesn't mean it's insecure — it means
    the analyzer should CHECK whether it's a risk.

    Attributes:
        name: Human-readable identifier for this component.
        component_type: What kind of element this is (process, datastore, external).
        description: Free-text description of what this component does.
        is_hardened: Whether security hardening has been applied (patching, config, etc.).
        handles_pii: Whether this component processes personally identifiable information.
        is_internet_facing: Whether this component is directly reachable from the internet.
        has_authentication: Whether this component verifies caller identity.
        has_authorization: Whether this component enforces access control / permissions.
        has_input_validation: Whether this component validates/sanitizes incoming data.
        has_logging: Whether this component produces audit logs for security events.
        has_encryption_at_rest: Whether stored data is encrypted (relevant for datastores).
        os: Operating system (e.g., "Linux", "CloudOS").
        technology: Technology stack (e.g., "Java/Spring Boot", "PostgreSQL").
    """

    name: str
    component_type: ComponentType
    description: str = ""
    is_hardened: bool = False
    handles_pii: bool = False
    is_internet_facing: bool = False
    has_authentication: bool = False
    has_authorization: bool = False
    has_input_validation: bool = False
    has_logging: bool = False
    has_encryption_at_rest: bool = False
    os: str = ""
    technology: str = ""

    def __str__(self) -> str:
        return f"{self.name} ({self.component_type.value})"


@dataclass
class TrustBoundary:
    """
    A trust boundary separates zones with different trust levels.

    In a Data Flow Diagram, trust boundaries are drawn as dashed lines
    that group related components. Data flows crossing these boundaries
    are high-priority targets for threat analysis.

    Examples:
        - Internet / DMZ boundary
        - DMZ / Internal network boundary
        - Application tier / Database tier boundary
        - User browser / Web server boundary
        - Your infrastructure / Third-party API boundary

    Attributes:
        name: Descriptive name for this boundary (e.g., "Internet / DMZ").
        description: What this boundary represents.
        components: Components that sit on the INSIDE of this boundary.
    """

    name: str
    description: str = ""
    components: list = field(default_factory=list)

    def contains(self, component: Component) -> bool:
        """Check if a component is inside this trust boundary."""
        return component in self.components

    def __str__(self) -> str:
        return f"[{self.name}] ({len(self.components)} components)"


@dataclass
class DataFlow:
    """
    Represents data moving between two components.

    Each data flow is analyzed against all six STRIDE categories.
    Flows crossing trust boundaries receive heightened scrutiny.

    Attributes:
        name: Descriptive name (e.g., "User login request").
        source: Where the data originates.
        destination: Where the data goes.
        data_description: What data is being transmitted.
        data_classification: Sensitivity level of the data.
        protocol: Communication protocol used.
        is_encrypted: Whether the data is encrypted in transit.
        has_auth_token: Whether the flow carries authentication credentials.
        crosses_trust_boundary: Whether this flow crosses a trust boundary.
    """

    name: str
    source: Component
    destination: Component
    data_description: str = ""
    data_classification: DataClassification = DataClassification.INTERNAL
    protocol: Protocol = Protocol.HTTPS
    is_encrypted: bool = True
    has_auth_token: bool = False
    crosses_trust_boundary: bool = False

    def __str__(self) -> str:
        crossing = " [CROSSES BOUNDARY]" if self.crosses_trust_boundary else ""
        return f"{self.source.name} → {self.destination.name}: {self.name}{crossing}"


@dataclass
class ThreatModel:
    """
    The top-level threat model containing all system elements.

    A ThreatModel is the complete representation of a system's
    architecture from a security perspective. It contains:
    - Components (processes, datastores, external entities)
    - Data flows (how data moves between components)
    - Trust boundaries (security zone separations)

    The four key questions of threat modeling:
    1. What are we building? → This model answers that
    2. What can go wrong? → StrideAnalyzer answers that
    3. What are we going to do about it? → Mitigations in the report
    4. Did we do a good job? → Review and iterate

    Usage:
        tm = ThreatModel(
            name="My SaaS App",
            description="Web application for process management"
        )
        tm.add_component(web_server)
        tm.add_component(database)
        tm.add_dataflow(user_to_server)
        tm.add_trust_boundary(internet_boundary)
    """

    name: str
    description: str = ""
    version: str = "1.0"
    author: str = ""
    components: list = field(default_factory=list)
    dataflows: list = field(default_factory=list)
    trust_boundaries: list = field(default_factory=list)

    def add_component(self, component: Component) -> None:
        """Add a component to the threat model."""
        if any(c.name == component.name for c in self.components):
            raise ValueError(f"Component '{component.name}' already exists in the model")
        self.components.append(component)

    def add_dataflow(self, flow: DataFlow) -> None:
        """Add a data flow to the threat model."""
        self.dataflows.append(flow)

    def add_trust_boundary(self, boundary: TrustBoundary) -> None:
        """Add a trust boundary to the threat model."""
        self.trust_boundaries.append(boundary)

    def get_boundary_crossings(self) -> list[DataFlow]:
        """Find all data flows that cross trust boundaries."""
        return [f for f in self.dataflows if f.crosses_trust_boundary]

    def get_internet_facing(self) -> list[Component]:
        """Find all components exposed to the internet."""
        return [c for c in self.components if c.is_internet_facing]

    def get_pii_handlers(self) -> list[Component]:
        """Find all components that handle PII."""
        return [c for c in self.components if c.handles_pii]

    def summary(self) -> dict:
        """Return a summary of the threat model."""
        return {
            "name": self.name,
            "version": self.version,
            "components": len(self.components),
            "dataflows": len(self.dataflows),
            "trust_boundaries": len(self.trust_boundaries),
            "boundary_crossings": len(self.get_boundary_crossings()),
            "internet_facing": len(self.get_internet_facing()),
            "pii_handlers": len(self.get_pii_handlers()),
        }
