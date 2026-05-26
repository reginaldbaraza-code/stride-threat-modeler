"""
Example: Threat modeling a basic web application.

A minimal three-tier web app — perfect for learning STRIDE.
Deliberately includes several security gaps to demonstrate findings.

Run:
    python examples/simple_web_app.py
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

tm = ThreatModel(
    name="Simple Blog Application",
    description="A basic blog with user accounts, posts, and comments.",
    version="1.0",
    author="Reginald Baraza",
)

# --- Components (deliberately insecure for educational purposes) ---
user = Component(
    name="User Browser",
    component_type=ComponentType.EXTERNAL_ENTITY,
    is_internet_facing=True,
)

web_server = Component(
    name="Web Server",
    component_type=ComponentType.PROCESS,
    description="Handles HTTP requests, serves pages, processes forms",
    is_internet_facing=True,
    is_hardened=False,          # Not hardened
    has_authentication=True,
    has_authorization=False,    # No authorization checks
    has_input_validation=False, # No input validation
    has_logging=False,          # No logging
    technology="Python / Flask",
)

database = Component(
    name="Blog Database",
    component_type=ComponentType.DATASTORE,
    description="Stores users, posts, comments, sessions",
    handles_pii=True,           # User emails, names
    has_encryption_at_rest=False, # Not encrypted
    technology="SQLite",
)

for comp in [user, web_server, database]:
    tm.add_component(comp)

# --- Trust Boundaries ---
tm.add_trust_boundary(TrustBoundary(
    name="Internet / Server",
    description="Public internet to web server",
    components=[user, web_server],
))

# --- Data Flows ---
tm.add_dataflow(DataFlow(
    name="User → Web Server",
    source=user, destination=web_server,
    data_description="Login credentials, blog posts, comments",
    data_classification=DataClassification.CONFIDENTIAL,
    protocol=Protocol.HTTP,   # HTTP, not HTTPS!
    is_encrypted=False,       # Not encrypted!
    has_auth_token=True,      # Sends session cookie
    crosses_trust_boundary=True,
))

tm.add_dataflow(DataFlow(
    name="Web Server → Database",
    source=web_server, destination=database,
    data_description="SQL queries for user data, posts, comments",
    data_classification=DataClassification.RESTRICTED,
    protocol=Protocol.SQL,
    is_encrypted=False,
    crosses_trust_boundary=False,
))

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
    print(f"  A deliberately insecure app for learning STRIDE")
    print(f"  Components: {len(tm.components)} | Flows: {len(tm.dataflows)}")
    print(f"  Threats Found: {len(scored)}")
    print(f"{'=' * 60}\n")

    for t in scored:
        icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(t.severity, "⚪")
        print(f"  {icon} [{t.id}] {t.category.value}")
        print(f"     {t.title}")
        print(f"     DREAD: {t.dread_score}/50")
        print(f"     Fix: {t.mitigation[:80]}...")
        print()

    os.makedirs("examples/outputs", exist_ok=True)
    generate_report(tm, scored, output="examples/outputs/simple_web_app_report.md")
    print(f"  📄 Report: examples/outputs/simple_web_app_report.md")
