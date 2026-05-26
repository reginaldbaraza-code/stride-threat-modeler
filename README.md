# STRIDE Threat Modeler 🛡️

A Python framework for conducting **STRIDE-based threat models** on system architectures. Define your system as code, auto-generate Data Flow Diagrams, identify threats per STRIDE category, score risks with DREAD, and produce actionable reports.

## Why This Exists

Threat modeling is a proactive security practice — it identifies threats **before** they become vulnerabilities. But manual threat modeling is slow, inconsistent, and hard to reproduce. This framework makes it:

- **Repeatable** — Define architectures as Python code, re-run analysis anytime
- **Automated** — STRIDE rules fire against every component and data flow
- **Auditable** — JSON/Markdown reports with full threat traceability
- **Educational** — Learn STRIDE and DREAD by seeing them applied to real architectures

## STRIDE Framework

STRIDE is a threat classification model developed at Microsoft:

| Category | Threat | Example | Typical Mitigation |
|----------|--------|---------|-------------------|
| **S**poofing | Impersonating a user or system | Forged OAuth tokens | MFA, certificate validation |
| **T**ampering | Modifying data maliciously | MITM altering API payloads | TLS, HMAC, digital signatures |
| **R**epudiation | Denying an action occurred | No audit trail for deletions | Structured logging, audit trails |
| **I**nfo Disclosure | Exposing data to unauthorized parties | API leaking PII in error responses | Encryption, access controls |
| **D**enial of Service | Making systems unavailable | Volumetric DDoS attack | Rate limiting, CDN, auto-scaling |
| **E**levation of Privilege | Gaining unauthorized access | User exploiting IDOR to access admin | RBAC, least privilege, input validation |

## Quick Start

### Installation

```bash
git clone https://github.com/reginaldbaraza-code/stride-threat-modeler.git
cd stride-threat-modeler
pip install -e .
```

### Run an Example

```bash
# Threat model a SaaS process management platform
python examples/signavio_like_app.py

# Threat model a microservices API
python examples/microservices_api.py

# Generate a DFD diagram (requires graphviz)
python -m src.cli diagram examples/signavio_like_app.py --output docs/diagrams/saas_dfd.png
```

### Define Your Own System

```python
from src.model import ThreatModel, Component, ComponentType, DataFlow, TrustBoundary, DataClassification, Protocol
from src.stride import StrideAnalyzer
from src.dread import DreadScorer

# Define components
web_server = Component(
    name="Web Server",
    component_type=ComponentType.PROCESS,
    is_internet_facing=True,
    has_authentication=True,
    has_authorization=False,  # ← STRIDE will flag this
    has_logging=True,
)

database = Component(
    name="User Database",
    component_type=ComponentType.DATASTORE,
    handles_pii=True,
    has_encryption_at_rest=True,
)

# Define data flows
api_flow = DataFlow(
    name="User requests",
    source=web_server,
    destination=database,
    data_classification=DataClassification.CONFIDENTIAL,
    crosses_trust_boundary=True,
    is_encrypted=True,
)

# Build the model
tm = ThreatModel(name="My App", description="Example application")
tm.add_component(web_server)
tm.add_component(database)
tm.add_dataflow(api_flow)

# Analyze
analyzer = StrideAnalyzer()
threats = analyzer.analyze(tm)

scorer = DreadScorer()
scored = scorer.score_all(threats)

for t in sorted(scored, key=lambda x: x.dread_score, reverse=True):
    print(f"[{t.severity}] {t.category.value}: {t.title} (DREAD: {t.dread_score}/50)")
```

## DREAD Risk Scoring

Each identified threat is scored across five dimensions (1-10 each):

| Dimension | What It Measures |
|-----------|-----------------|
| **D**amage | How bad is it if exploited? |
| **R**eproducibility | How easy to reproduce? |
| **E**xploitability | How much skill/tooling needed? |
| **A**ffected Users | How many users impacted? |
| **D**iscoverability | How easy to find? |

**Total DREAD Score** = sum of all five (max 50). Severity mapping:
- 40-50: Critical
- 30-39: High
- 20-29: Medium
- 10-19: Low
- 1-9: Informational

## Project Structure

```
stride-threat-modeler/
├── src/
│   ├── model.py          # Core: System, Component, DataFlow, TrustBoundary
│   ├── stride.py          # STRIDE threat identification engine
│   ├── dread.py           # DREAD risk scoring
│   ├── diagram.py         # DFD generator (Mermaid output)
│   ├── report.py          # Markdown/HTML report generator
│   ├── threats_db.py      # Knowledge base of common threats
│   └── cli.py             # CLI interface
├── examples/
│   ├── signavio_like_app.py      # SaaS process management platform
│   ├── microservices_api.py      # Microservice architecture
│   └── simple_web_app.py         # Basic web application
├── tests/
│   ├── test_model.py
│   ├── test_stride.py
│   ├── test_dread.py
│   └── test_report.py
├── threat_knowledge/
│   ├── stride_threats.yaml       # Curated threat catalog
│   └── mitigations.yaml          # Mitigation recommendations
└── docs/
    ├── stride-methodology.md
    └── dread-scoring.md
```

## Tech Stack

- **Python 3.11+** — core language
- **PyYAML** — threat knowledge base
- **pytest** — testing framework
- **Graphviz** (optional) — DFD diagram rendering

## Related Reading

- [STRIDE Threat Model (Microsoft)](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [pytm - Pythonic Threat Modeling](https://github.com/OWASP/pytm)
- [Adam Shostack's Four Questions](https://shostack.org/resources/threat-modeling)

## License

MIT
