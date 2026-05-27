# STRIDE Threat Modeler 🛡️

A Python framework for running STRIDE-based threat models on system architectures. You describe your system in Python — components, data flows, trust boundaries — and the tool automatically identifies threats, scores them with DREAD, and generates reports.

## What It Does

1. **You define your architecture as code** — web servers, databases, APIs, data flows between them
2. **The STRIDE analyzer scans every component and flow** — checking for missing authentication, unencrypted data, absent logging, and more
3. **Each threat gets a DREAD risk score** (5–50 scale) so you know what to fix first
4. **You get a Markdown report and a Mermaid data flow diagram** ready for docs or pull requests

## What Is STRIDE?

STRIDE is a threat classification model from Microsoft. Each letter represents a category of attack:

| Letter | Threat | What goes wrong | Example |
|--------|--------|----------------|---------|
| **S** | Spoofing | Someone pretends to be a user or service | Forged login tokens |
| **T** | Tampering | Data is modified without authorization | SQL injection changing records |
| **R** | Repudiation | Actions can't be traced back to who did them | No audit log for deletions |
| **I** | Info Disclosure | Sensitive data leaks to the wrong people | API returning PII in errors |
| **D** | Denial of Service | The system becomes unavailable | DDoS attack flooding the server |
| **E** | Elevation of Privilege | A user gains access they shouldn't have | Regular user reaching admin endpoints |

## Quick Start

```bash
git clone https://github.com/reginaldbaraza-code/stride-threat-modeler.git
cd stride-threat-modeler
pip install -e ".[dev]"

# Run the SaaS platform example (models a system similar to SAP Signavio)
python examples/signavio_like_app.py

# Run the microservices example
python examples/microservices_api.py

# Run all 51 tests
pytest -v
```

The examples generate a Markdown report and a Mermaid diagram in `examples/outputs/`.

## Define Your Own System

```python
from src.model import ThreatModel, Component, ComponentType, DataFlow, DataClassification
from src.stride import StrideAnalyzer
from src.dread import DreadScorer

# Step 1: Define components with their security properties
web_server = Component(
    name="Web Server",
    component_type=ComponentType.PROCESS,
    is_internet_facing=True,
    has_authentication=True,
    has_authorization=False,  # ← STRIDE will flag this as Elevation of Privilege risk
    has_logging=True,
)

database = Component(
    name="User Database",
    component_type=ComponentType.DATASTORE,
    handles_pii=True,
    has_encryption_at_rest=True,
)

# Step 2: Define how data moves between components
api_flow = DataFlow(
    name="User requests",
    source=web_server,
    destination=database,
    data_classification=DataClassification.CONFIDENTIAL,
    crosses_trust_boundary=True,
    is_encrypted=True,
)

# Step 3: Build the model and analyze
tm = ThreatModel(name="My App", description="Example application")
tm.add_component(web_server)
tm.add_component(database)
tm.add_dataflow(api_flow)

threats = StrideAnalyzer().analyze(tm)
scored = DreadScorer().score_all(threats)

for t in sorted(scored, key=lambda x: x.dread_score, reverse=True):
    print(f"[{t.severity}] {t.category.value}: {t.title} (DREAD: {t.dread_score}/50)")
```

## DREAD Risk Scoring

Each threat is scored from 5 to 50 across five dimensions:

| Dimension | Question it answers |
|-----------|-------------------|
| **D**amage | How bad is it if this threat is exploited? |
| **R**eproducibility | How easily can an attacker reproduce this? |
| **E**xploitability | How much skill or tooling is needed? |
| **A**ffected Users | How many users would be impacted? |
| **D**iscoverability | How easy is the vulnerability to find? |

Scores map to severity: 40–50 = Critical, 30–39 = High, 20–29 = Medium, 10–19 = Low, 5–9 = Info.

## Project Structure

```
stride-threat-modeler/
├── src/
│   ├── model.py          # Core dataclasses: Component, DataFlow, TrustBoundary, ThreatModel
│   ├── stride.py          # STRIDE analyzer — scans components and flows for threats
│   ├── dread.py           # DREAD scorer — heuristic and manual risk scoring
│   ├── diagram.py         # Generates Mermaid data flow diagrams
│   ├── report.py          # Generates Markdown reports with executive summary
│   ├── threats_db.py      # 10 curated threat templates (S01–E02)
│   └── cli.py             # CLI: analyze, report, diagram, threats commands
├── examples/
│   ├── signavio_like_app.py   # 10-component SaaS platform (interview demo)
│   ├── microservices_api.py   # E-commerce microservices
│   └── simple_web_app.py      # Deliberately insecure blog for learning
├── tests/                     # 51 tests across 4 test files
├── threat_knowledge/
│   ├── stride_threats.yaml    # Threat catalog organized by STRIDE category
│   └── mitigations.yaml       # Mitigation controls mapped to STRIDE
└── docs/
    ├── stride-methodology.md  # How STRIDE works and when to use it
    └── dread-scoring.md       # DREAD scoring guide with examples
```

## Tech Stack

- **Python 3.11+**
- **PyYAML** — threat knowledge base
- **Click** — CLI interface
- **Jinja2** — report templating
- **pytest** — 51 tests

## Further Reading

- [STRIDE Threat Model (Microsoft)](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [Adam Shostack's Four Questions](https://shostack.org/resources/threat-modeling)

## License

MIT
