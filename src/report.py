"""
Threat Model Report Generator.

Generates Markdown reports from analyzed threat models.
Reports include:
- Executive summary with key metrics
- System architecture overview
- Full threat listing with STRIDE categorization
- DREAD scores and severity breakdown
- Mitigation recommendations
- Data flow analysis with boundary crossings

Usage:
    generate_report(model, threats, output="report.md")
"""

from datetime import datetime

from src.model import ThreatModel
from src.stride import Threat, StrideCategory


def generate_report(
    model: ThreatModel,
    threats: list[Threat],
    output: str = "threat_model_report.md",
) -> str:
    """
    Generate a complete Markdown threat model report.

    Args:
        model: The analyzed ThreatModel.
        threats: List of identified threats (ideally DREAD-scored).
        output: Output file path.

    Returns:
        The report content as a string (also saved to file).
    """
    sections = [
        _header(model),
        _executive_summary(model, threats),
        _system_overview(model),
        _threat_summary_table(threats),
        _threats_by_category(threats),
        _boundary_crossings(model),
        _recommendations(threats),
        _footer(),
    ]

    report = "\n\n".join(sections)

    with open(output, "w") as f:
        f.write(report)

    return report


def _header(model: ThreatModel) -> str:
    return f"""# Threat Model Report: {model.name}

**Version:** {model.version}
**Author:** {model.author or "STRIDE Threat Modeler"}
**Date:** {datetime.now().strftime("%Y-%m-%d")}
**Description:** {model.description}

---"""


def _executive_summary(model: ThreatModel, threats: list[Threat]) -> str:
    summary = model.summary()
    severity_counts = _count_by_severity(threats)

    return f"""## Executive Summary

This threat model analyzed **{summary['components']}** components and
**{summary['dataflows']}** data flows across **{summary['trust_boundaries']}**
trust boundaries.

### Key Findings

| Metric | Count |
|--------|-------|
| Total threats identified | **{len(threats)}** |
| Critical severity | **{severity_counts.get('Critical', 0)}** |
| High severity | **{severity_counts.get('High', 0)}** |
| Medium severity | **{severity_counts.get('Medium', 0)}** |
| Low severity | **{severity_counts.get('Low', 0)}** |
| Trust boundary crossings | **{summary['boundary_crossings']}** |
| Internet-facing components | **{summary['internet_facing']}** |
| PII-handling components | **{summary['pii_handlers']}** |

### Risk Distribution by STRIDE Category

| Category | Count | Highest Severity |
|----------|-------|-----------------|
{_stride_distribution_rows(threats)}"""


def _system_overview(model: ThreatModel) -> str:
    lines = ["## System Overview", "", "### Components", ""]
    lines.append("| Component | Type | Internet-Facing | PII | Auth | AuthZ | Logging |")
    lines.append("|-----------|------|:-:|:-:|:-:|:-:|:-:|")

    for comp in model.components:
        lines.append(
            f"| {comp.name} | {comp.component_type.value} | "
            f"{'✅' if comp.is_internet_facing else '❌'} | "
            f"{'✅' if comp.handles_pii else '❌'} | "
            f"{'✅' if comp.has_authentication else '❌'} | "
            f"{'✅' if comp.has_authorization else '❌'} | "
            f"{'✅' if comp.has_logging else '❌'} |"
        )

    lines.extend(["", "### Data Flows", ""])
    lines.append("| Flow | Source | Destination | Protocol | Classification | Encrypted | Boundary Crossing |")
    lines.append("|------|--------|-------------|----------|:-:|:-:|:-:|")

    for flow in model.dataflows:
        lines.append(
            f"| {flow.name} | {flow.source.name} | {flow.destination.name} | "
            f"{flow.protocol.value} | {flow.data_classification.value} | "
            f"{'✅' if flow.is_encrypted else '❌'} | "
            f"{'⚠️' if flow.crosses_trust_boundary else '—'} |"
        )

    if model.trust_boundaries:
        lines.extend(["", "### Trust Boundaries", ""])
        for boundary in model.trust_boundaries:
            comp_names = ", ".join(c.name for c in boundary.components)
            lines.append(f"- **{boundary.name}**: {boundary.description}")
            lines.append(f"  - Components: {comp_names}")

    return "\n".join(lines)


def _threat_summary_table(threats: list[Threat]) -> str:
    lines = [
        "## Threat Summary",
        "",
        "| ID | STRIDE | Severity | DREAD | Target | Title |",
        "|----|--------|----------|------:|--------|-------|",
    ]

    for t in threats:
        severity_icon = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
            "Informational": "⚪",
        }.get(t.severity, "⚪")

        lines.append(
            f"| {t.id} | {t.category.value} | {severity_icon} {t.severity} | "
            f"{t.dread_score}/50 | {t.target} | {t.title} |"
        )

    return "\n".join(lines)


def _threats_by_category(threats: list[Threat]) -> str:
    lines = ["## Detailed Findings"]

    for category in StrideCategory:
        cat_threats = [t for t in threats if t.category == category]
        if not cat_threats:
            continue

        lines.extend([
            "",
            f"### {category.value}",
            "",
        ])

        for t in cat_threats:
            lines.extend([
                f"#### {t.id}: {t.title}",
                "",
                f"- **Severity:** {t.severity} (DREAD: {t.dread_score}/50)",
                f"- **Target:** {t.target}",
                f"- **Status:** {t.status}",
                "",
                f"**Description:** {t.description}",
                "",
                f"**Mitigation:** {t.mitigation}",
                "",
                "---",
            ])

    return "\n".join(lines)


def _boundary_crossings(model: ThreatModel) -> str:
    crossings = model.get_boundary_crossings()
    if not crossings:
        return ""

    lines = [
        "## Trust Boundary Crossings",
        "",
        "Data flows crossing trust boundaries require special attention.",
        "",
    ]

    for flow in crossings:
        encrypted_status = "✅ Encrypted" if flow.is_encrypted else "❌ NOT ENCRYPTED"
        lines.extend([
            f"- **{flow.name}**: {flow.source.name} → {flow.destination.name}",
            f"  - Protocol: {flow.protocol.value} | Classification: {flow.data_classification.value}",
            f"  - Encryption: {encrypted_status}",
            "",
        ])

    return "\n".join(lines)


def _recommendations(threats: list[Threat]) -> str:
    critical = [t for t in threats if t.severity == "Critical"]
    high = [t for t in threats if t.severity == "High"]

    lines = [
        "## Priority Recommendations",
        "",
        "### Immediate Actions (Critical Findings)",
        "",
    ]

    if critical:
        for i, t in enumerate(critical, 1):
            lines.append(f"{i}. **{t.title}** — {t.mitigation[:120]}...")
    else:
        lines.append("No critical findings identified. ✅")

    lines.extend([
        "",
        "### Short-Term Actions (High Findings)",
        "",
    ])

    if high:
        for i, t in enumerate(high, 1):
            lines.append(f"{i}. **{t.title}** — {t.mitigation[:120]}...")
    else:
        lines.append("No high-severity findings identified. ✅")

    return "\n".join(lines)


def _footer() -> str:
    return f"""---

*Report generated by [STRIDE Threat Modeler](https://github.com/reginaldbaraza-code/stride-threat-modeler) on {datetime.now().strftime("%Y-%m-%d %H:%M")}*"""


# =========================================================================
# Helper functions
# =========================================================================

def _count_by_severity(threats: list[Threat]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for t in threats:
        counts[t.severity] = counts.get(t.severity, 0) + 1
    return counts


def _stride_distribution_rows(threats: list[Threat]) -> str:
    rows = []
    for category in StrideCategory:
        cat_threats = [t for t in threats if t.category == category]
        if cat_threats:
            highest = max(cat_threats, key=lambda t: t.dread_score)
            rows.append(f"| {category.value} | {len(cat_threats)} | {highest.severity} |")
        else:
            rows.append(f"| {category.value} | 0 | — |")
    return "\n".join(rows)
