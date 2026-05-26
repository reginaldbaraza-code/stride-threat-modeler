"""
Example: Threat modeling a microservices-based REST API.

A typical e-commerce backend with API gateway, auth service,
product catalog, order processing, and payment integration.

Run:
    python examples/microservices_api.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.model import (
    ThreatModel, Component, ComponentType, DataFlow,
    TrustBoundary, DataClassification, Protocol,
)
from src.stride import StrideAnalyzer
from src.dread import DreadScorer
from src.report import generate_report

# =============================================================================
# System Definition
# =============================================================================

tm = ThreatModel(
    name="E-Commerce Microservices API",
    description=(
        "Microservices backend for an e-commerce platform. Handles user "
        "authentication, product catalog, order management, and payment "
        "processing via a third-party gateway."
    ),
    version="1.0",
    author="Reginald Baraza",
)

# --- Components ---
mobile_app = Component(
    name="Mobile App",
    component_type=ComponentType.EXTERNAL_ENTITY,
    description="iOS/Android customer app",
    is_internet_facing=True,
)

api_gw = Component(
    name="API Gateway",
    component_type=ComponentType.PROCESS,
    description="Central entry point — routing, rate limiting, JWT validation",
    is_internet_facing=True,
    is_hardened=True,
    has_authentication=True,
    has_authorization=True,
    has_logging=True,
    has_input_validation=True,
    technology="Kong",
)

auth_service = Component(
    name="Auth Service",
    component_type=ComponentType.PROCESS,
    description="User registration, login, JWT issuance, password reset",
    has_authentication=True,
    has_authorization=True,
    has_logging=True,
    has_input_validation=True,
    handles_pii=True,
    technology="Go",
)

product_service = Component(
    name="Product Catalog Service",
    component_type=ComponentType.PROCESS,
    description="CRUD for products, search, inventory checks",
    has_authentication=True,
    has_authorization=False,  # Finding: no authz on catalog — anyone can edit?
    has_logging=True,
    has_input_validation=True,
    technology="Python / FastAPI",
)

order_service = Component(
    name="Order Service",
    component_type=ComponentType.PROCESS,
    description="Order creation, status tracking, fulfillment workflow",
    has_authentication=True,
    has_authorization=True,
    has_logging=True,
    has_input_validation=False,  # Finding: missing input validation
    handles_pii=True,
    technology="Java / Spring Boot",
)

payment_gateway = Component(
    name="Payment Gateway",
    component_type=ComponentType.EXTERNAL_ENTITY,
    description="Third-party payment processor (Stripe / Adyen)",
    is_internet_facing=True,
)

user_db = Component(
    name="User Database",
    component_type=ComponentType.DATASTORE,
    description="User credentials, profiles, preferences",
    handles_pii=True,
    has_encryption_at_rest=True,
    technology="PostgreSQL",
)

product_db = Component(
    name="Product Database",
    component_type=ComponentType.DATASTORE,
    description="Product catalog, pricing, inventory",
    has_encryption_at_rest=True,
    technology="MongoDB",
)

order_db = Component(
    name="Order Database",
    component_type=ComponentType.DATASTORE,
    description="Orders, line items, shipping addresses, payment refs",
    handles_pii=True,
    has_encryption_at_rest=False,  # Finding: PII without encryption at rest
    technology="PostgreSQL",
)

message_queue = Component(
    name="Message Queue",
    component_type=ComponentType.DATASTORE,
    description="Async event bus for order events, notifications",
    has_encryption_at_rest=False,
    technology="RabbitMQ",
)

for comp in [
    mobile_app, api_gw, auth_service, product_service,
    order_service, payment_gateway, user_db, product_db,
    order_db, message_queue,
]:
    tm.add_component(comp)

# --- Trust Boundaries ---
tm.add_trust_boundary(TrustBoundary(
    name="Internet / DMZ",
    description="Public internet to API gateway boundary",
    components=[mobile_app, api_gw, payment_gateway],
))

tm.add_trust_boundary(TrustBoundary(
    name="Application / Data Tier",
    description="Service mesh to database tier",
    components=[auth_service, product_service, order_service,
                user_db, product_db, order_db, message_queue],
))

# --- Data Flows ---
flows = [
    DataFlow(
        name="Mobile → API",
        source=mobile_app, destination=api_gw,
        data_classification=DataClassification.CONFIDENTIAL,
        protocol=Protocol.HTTPS, is_encrypted=True,
        has_auth_token=True, crosses_trust_boundary=True,
    ),
    DataFlow(
        name="API → Auth",
        source=api_gw, destination=auth_service,
        data_classification=DataClassification.RESTRICTED,
        protocol=Protocol.GRPC, is_encrypted=True,
    ),
    DataFlow(
        name="API → Products",
        source=api_gw, destination=product_service,
        data_classification=DataClassification.INTERNAL,
        protocol=Protocol.GRPC, is_encrypted=True,
    ),
    DataFlow(
        name="API → Orders",
        source=api_gw, destination=order_service,
        data_classification=DataClassification.CONFIDENTIAL,
        protocol=Protocol.GRPC, is_encrypted=True,
    ),
    DataFlow(
        name="Orders → Payment",
        source=order_service, destination=payment_gateway,
        data_classification=DataClassification.RESTRICTED,
        protocol=Protocol.HTTPS, is_encrypted=True,
        has_auth_token=True, crosses_trust_boundary=True,
    ),
    DataFlow(
        name="Auth → User DB",
        source=auth_service, destination=user_db,
        data_classification=DataClassification.RESTRICTED,
        protocol=Protocol.SQL, is_encrypted=True,
        crosses_trust_boundary=True,
    ),
    DataFlow(
        name="Products → Product DB",
        source=product_service, destination=product_db,
        data_classification=DataClassification.INTERNAL,
        protocol=Protocol.SQL, is_encrypted=True,
    ),
    DataFlow(
        name="Orders → Order DB",
        source=order_service, destination=order_db,
        data_classification=DataClassification.RESTRICTED,
        protocol=Protocol.SQL, is_encrypted=True,
        crosses_trust_boundary=True,
    ),
    DataFlow(
        name="Orders → Event Queue",
        source=order_service, destination=message_queue,
        data_classification=DataClassification.CONFIDENTIAL,
        protocol=Protocol.AMQP, is_encrypted=False,  # Finding!
        crosses_trust_boundary=False,
    ),
]

for flow in flows:
    tm.add_dataflow(flow)

# =============================================================================
# Analysis
# =============================================================================

if __name__ == "__main__":
    analyzer = StrideAnalyzer()
    threats = analyzer.analyze(tm)

    scorer = DreadScorer()
    scored = scorer.score_all(threats)

    print(f"\n{'=' * 60}")
    print(f"  {tm.name}")
    print(f"  Components: {len(tm.components)} | Flows: {len(tm.dataflows)}")
    print(f"  Threats Found: {len(scored)}")
    print(f"{'=' * 60}\n")

    for t in scored:
        icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(t.severity, "⚪")
        print(f"  {icon} [{t.id}] {t.category.value} — {t.title}")
        print(f"     DREAD: {t.dread_score}/50 | Target: {t.target}")
        print()

    os.makedirs("examples/outputs", exist_ok=True)
    generate_report(tm, scored, output="examples/outputs/microservices_report.md")
    print(f"  📄 Report saved to examples/outputs/microservices_report.md")
