"""
Example: Threat modeling a cloud-based process management platform.

This models an architecture similar to SAP Signavio — a multi-tenant
SaaS application for business process modeling, analysis, and optimization.

Components modeled:
    - User browser (external entity)
    - API Gateway (internet-facing, hardened)
    - Process Modeler Service (core business logic)
    - Collaboration Hub (content publishing)
    - Process Intelligence Engine (analytics/mining)
    - Primary Database (multi-tenant, PII)
    - Event Log Storage (object storage)
    - Identity Provider (external SSO)

Run:
    python examples/signavio_like_app.py

This produces:
    - Console output with all identified threats
    - Markdown report at examples/outputs/saas_report.md
    - Mermaid DFD at examples/outputs/saas_dfd.mmd
"""

import os
import sys

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.model import (
    ThreatModel,
    Component,
    ComponentType,
    DataFlow,
    TrustBoundary,
    DataClassification,
    Protocol,
)
from src.stride import StrideAnalyzer
from src.dread import DreadScorer
from src.diagram import generate_mermaid_dfd, save_mermaid
from src.report import generate_report


# =============================================================================
# System Definition
# =============================================================================

tm = ThreatModel(
    name="Cloud Process Management Platform",
    description=(
        "Multi-tenant SaaS application for business process modeling, "
        "analysis, and optimization. Users create BPMN process diagrams, "
        "publish them via a collaboration hub, and run process mining "
        "analytics on uploaded event logs. Deployed on cloud infrastructure "
        "with SSO integration for enterprise customers."
    ),
    version="1.0",
    author="Reginald Baraza",
)

# -----------------------------------------------------------------------------
# Components
# -----------------------------------------------------------------------------

browser = Component(
    name="User Browser",
    component_type=ComponentType.EXTERNAL_ENTITY,
    description="End user accessing the platform via web browser (Chrome, Firefox, Edge)",
    is_internet_facing=True,
)

api_gateway = Component(
    name="API Gateway",
    component_type=ComponentType.PROCESS,
    description=(
        "Entry point for all client API requests. Handles TLS termination, "
        "request routing, rate limiting, authentication token validation, "
        "and request/response logging."
    ),
    is_internet_facing=True,
    is_hardened=True,
    has_authentication=True,
    has_authorization=True,
    has_logging=True,
    has_input_validation=True,
    technology="Kong / AWS API Gateway",
)

process_modeler = Component(
    name="Process Modeler Service",
    component_type=ComponentType.PROCESS,
    description=(
        "Core service for creating, editing, and versioning BPMN process "
        "diagrams. Supports real-time collaboration, version history, "
        "and diagram validation."
    ),
    has_authentication=True,
    has_authorization=True,
    has_logging=True,
    has_input_validation=True,
    handles_pii=False,
    technology="Java / Spring Boot",
)

collab_hub = Component(
    name="Collaboration Hub",
    component_type=ComponentType.PROCESS,
    description=(
        "Publishing and sharing platform for process documentation. "
        "Provides curated views of process landscapes, team workspaces, "
        "and notification management."
    ),
    has_authentication=True,
    has_authorization=True,
    has_logging=True,
    has_input_validation=True,
    technology="Node.js / Express",
)

process_intelligence = Component(
    name="Process Intelligence Engine",
    component_type=ComponentType.PROCESS,
    description=(
        "Analytics engine for process mining and optimization. Ingests "
        "event logs from customer systems, performs conformance checking, "
        "bottleneck analysis, and process variant discovery."
    ),
    has_authentication=True,
    has_authorization=True,
    has_logging=True,
    has_input_validation=True,
    handles_pii=True,  # Event logs often contain user/employee identifiers
    technology="Python / Apache Spark",
)

primary_db = Component(
    name="Primary Database",
    component_type=ComponentType.DATASTORE,
    description=(
        "Central relational database storing process models, user accounts, "
        "permissions, tenant configuration, and collaboration data. "
        "Multi-tenant with row-level isolation."
    ),
    has_encryption_at_rest=True,
    handles_pii=True,  # User accounts, tenant data
    technology="PostgreSQL (RDS)",
)

event_log_store = Component(
    name="Event Log Storage",
    component_type=ComponentType.DATASTORE,
    description=(
        "Object storage for uploaded event logs used in process mining. "
        "Each tenant's data is isolated by prefix/partition. Logs may "
        "contain employee names, timestamps, and operational data."
    ),
    has_encryption_at_rest=True,
    handles_pii=True,  # Employee names in event logs
    technology="AWS S3 / Azure Blob Storage",
)

cache = Component(
    name="Session Cache",
    component_type=ComponentType.DATASTORE,
    description="In-memory cache for session tokens, rate limit counters, and hot data.",
    has_encryption_at_rest=False,  # Intentionally — this is a finding opportunity
    handles_pii=False,
    technology="Redis",
)

idp = Component(
    name="Identity Provider",
    component_type=ComponentType.EXTERNAL_ENTITY,
    description=(
        "External enterprise SSO provider (SAML 2.0 / OpenID Connect). "
        "Handles user authentication, MFA, and identity federation."
    ),
)

notification_service = Component(
    name="Notification Service",
    component_type=ComponentType.PROCESS,
    description=(
        "Sends email notifications for collaboration events (diagram shared, "
        "comment added, approval requested). Uses SMTP relay."
    ),
    has_authentication=True,
    has_authorization=True,
    has_logging=False,  # Intentionally — this is a finding opportunity
    has_input_validation=True,
    technology="Python / Celery",
)

# Register all components
for comp in [
    browser, api_gateway, process_modeler, collab_hub,
    process_intelligence, primary_db, event_log_store,
    cache, idp, notification_service,
]:
    tm.add_component(comp)

# -----------------------------------------------------------------------------
# Trust Boundaries
# -----------------------------------------------------------------------------

internet_boundary = TrustBoundary(
    name="Internet / DMZ",
    description=(
        "Boundary between the public internet and the platform's DMZ. "
        "Only the API Gateway is exposed. All other services are internal."
    ),
    components=[browser, api_gateway],
)

app_data_boundary = TrustBoundary(
    name="Application / Data Tier",
    description=(
        "Boundary between application services and data stores. "
        "Services access data through connection pools with dedicated "
        "service accounts."
    ),
    components=[
        process_modeler, collab_hub, process_intelligence,
        notification_service, primary_db, event_log_store, cache,
    ],
)

external_boundary = TrustBoundary(
    name="Platform / External Services",
    description="Boundary between the platform and third-party services (IdP, SMTP).",
    components=[idp],
)

tm.add_trust_boundary(internet_boundary)
tm.add_trust_boundary(app_data_boundary)
tm.add_trust_boundary(external_boundary)

# -----------------------------------------------------------------------------
# Data Flows
# -----------------------------------------------------------------------------

flows = [
    # User → API Gateway (internet boundary crossing)
    DataFlow(
        name="User HTTPS Requests",
        source=browser,
        destination=api_gateway,
        data_description="BPMN models, user input, search queries, file uploads",
        data_classification=DataClassification.CONFIDENTIAL,
        protocol=Protocol.HTTPS,
        is_encrypted=True,
        has_auth_token=True,
        crosses_trust_boundary=True,
    ),

    # API Gateway → Backend Services
    DataFlow(
        name="Gateway → Modeler",
        source=api_gateway,
        destination=process_modeler,
        data_description="Validated API requests for BPMN operations",
        data_classification=DataClassification.INTERNAL,
        protocol=Protocol.GRPC,
        is_encrypted=True,
    ),
    DataFlow(
        name="Gateway → Collab Hub",
        source=api_gateway,
        destination=collab_hub,
        data_description="Publishing and sharing requests",
        data_classification=DataClassification.INTERNAL,
        protocol=Protocol.GRPC,
        is_encrypted=True,
    ),
    DataFlow(
        name="Gateway → Process Intelligence",
        source=api_gateway,
        destination=process_intelligence,
        data_description="Analytics queries and event log upload requests",
        data_classification=DataClassification.CONFIDENTIAL,
        protocol=Protocol.GRPC,
        is_encrypted=True,
    ),

    # Services → Data Stores (app/data boundary crossing)
    DataFlow(
        name="Modeler → Database",
        source=process_modeler,
        destination=primary_db,
        data_description="Process model CRUD, version history, permissions",
        data_classification=DataClassification.CONFIDENTIAL,
        protocol=Protocol.SQL,
        is_encrypted=True,
        crosses_trust_boundary=True,
    ),
    DataFlow(
        name="Intelligence → Event Logs",
        source=process_intelligence,
        destination=event_log_store,
        data_description="Event log read/write for process mining",
        data_classification=DataClassification.RESTRICTED,
        protocol=Protocol.HTTPS,
        is_encrypted=True,
        crosses_trust_boundary=True,
    ),
    DataFlow(
        name="Gateway → Cache",
        source=api_gateway,
        destination=cache,
        data_description="Session tokens, rate limit counters",
        data_classification=DataClassification.INTERNAL,
        protocol=Protocol.INTERNAL,
        is_encrypted=False,  # Redis typically not TLS internally — finding!
        crosses_trust_boundary=False,
    ),

    # External integrations (external boundary crossing)
    DataFlow(
        name="Gateway → Identity Provider",
        source=api_gateway,
        destination=idp,
        data_description="SAML/OIDC authentication flows, user assertions",
        data_classification=DataClassification.CONFIDENTIAL,
        protocol=Protocol.HTTPS,
        is_encrypted=True,
        has_auth_token=True,
        crosses_trust_boundary=True,
    ),
    DataFlow(
        name="Notification → SMTP",
        source=notification_service,
        destination=idp,  # Simplified — would be an SMTP relay in reality
        data_description="Email notifications with user names and process references",
        data_classification=DataClassification.INTERNAL,
        protocol=Protocol.SMTP,
        is_encrypted=True,
        crosses_trust_boundary=True,
    ),
]

for flow in flows:
    tm.add_dataflow(flow)


# =============================================================================
# Analysis
# =============================================================================

if __name__ == "__main__":
    # Run STRIDE analysis
    analyzer = StrideAnalyzer()
    threats = analyzer.analyze(tm)

    # Score with DREAD
    scorer = DreadScorer()
    scored_threats = scorer.score_all(threats)

    # Print results
    summary = tm.summary()
    print(f"\n{'=' * 70}")
    print(f"  Threat Model: {tm.name}")
    print(f"  {tm.description[:80]}...")
    print(f"{'=' * 70}")
    print(f"  Components: {summary['components']} | Data Flows: {summary['dataflows']}")
    print(f"  Trust Boundaries: {summary['trust_boundaries']} | Boundary Crossings: {summary['boundary_crossings']}")
    print(f"  Internet-Facing: {summary['internet_facing']} | PII Handlers: {summary['pii_handlers']}")
    print(f"  Total Threats: {len(scored_threats)}")
    print(f"{'=' * 70}\n")

    # Group by severity
    for severity in ["Critical", "High", "Medium", "Low"]:
        sev_threats = [t for t in scored_threats if t.severity == severity]
        if sev_threats:
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}[severity]
            print(f"  {icon} {severity} ({len(sev_threats)} findings)")
            print(f"  {'─' * 60}")
            for t in sev_threats:
                print(f"    [{t.id}] {t.category.value}")
                print(f"     → {t.title}")
                print(f"       DREAD: {t.dread_score}/50 | Target: {t.target}")
                print()

    # Generate outputs
    os.makedirs("examples/outputs", exist_ok=True)

    report_path = "examples/outputs/saas_report.md"
    generate_report(tm, scored_threats, output=report_path)
    print(f"  📄 Report: {report_path}")

    dfd_path = "examples/outputs/saas_dfd.mmd"
    save_mermaid(tm, dfd_path)
    print(f"  📊 DFD:    {dfd_path}")
    print()
