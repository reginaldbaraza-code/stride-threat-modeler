"""
CLI interface for STRIDE Threat Modeler.

Commands:
    stride-tm analyze <model_file>    Run STRIDE analysis and print results
    stride-tm report <model_file>     Generate a full Markdown report
    stride-tm diagram <model_file>    Generate a Mermaid DFD diagram
    stride-tm threats                 List all threats in the knowledge base

Usage:
    pip install -e .
    stride-tm analyze examples/signavio_like_app.py
"""

import click
import importlib.util
import sys

from src.stride import StrideAnalyzer
from src.dread import DreadScorer
from src.diagram import generate_mermaid_dfd
from src.report import generate_report
from src.threats_db import ThreatKnowledgeBase


def _load_model_from_file(filepath: str):
    """
    Load a ThreatModel from a Python file.

    The file must define a variable named `tm` of type ThreatModel.
    """
    spec = importlib.util.spec_from_file_location("user_model", filepath)
    if spec is None or spec.loader is None:
        click.echo(f"Error: Could not load '{filepath}'", err=True)
        sys.exit(1)

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if not hasattr(module, "tm"):
        click.echo(
            f"Error: '{filepath}' must define a variable named 'tm' "
            f"of type ThreatModel.",
            err=True,
        )
        sys.exit(1)

    return module.tm


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """STRIDE Threat Modeler — Analyze system architectures for security threats."""
    pass


@cli.command()
@click.argument("model_file", type=click.Path(exists=True))
@click.option("--severity", "-s", default=None, help="Filter by severity (Critical/High/Medium/Low)")
@click.option("--category", "-c", default=None, help="Filter by STRIDE category")
def analyze(model_file: str, severity: str | None, category: str | None):
    """Run STRIDE analysis on a threat model and print results."""
    model = _load_model_from_file(model_file)

    analyzer = StrideAnalyzer()
    threats = analyzer.analyze(model)

    scorer = DreadScorer()
    scored = scorer.score_all(threats)

    # Apply filters
    if severity:
        scored = [t for t in scored if t.severity.lower() == severity.lower()]
    if category:
        scored = [t for t in scored if t.category.value.lower() == category.lower()]

    # Print summary
    summary = model.summary()
    click.echo(f"\n{'=' * 60}")
    click.echo(f"Threat Model: {model.name}")
    click.echo(f"Components: {summary['components']} | Flows: {summary['dataflows']} | Boundaries: {summary['trust_boundaries']}")
    click.echo(f"Threats Found: {len(scored)}")
    click.echo(f"{'=' * 60}\n")

    for t in scored:
        icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(t.severity, "⚪")
        click.echo(f"{icon} [{t.id}] {t.category.value} — {t.title}")
        click.echo(f"   Severity: {t.severity} | DREAD: {t.dread_score}/50 | Target: {t.target}")
        click.echo(f"   Mitigation: {t.mitigation[:100]}...")
        click.echo()


@cli.command()
@click.argument("model_file", type=click.Path(exists=True))
@click.option("--output", "-o", default="threat_model_report.md", help="Output file path")
def report(model_file: str, output: str):
    """Generate a full Markdown threat model report."""
    model = _load_model_from_file(model_file)

    analyzer = StrideAnalyzer()
    threats = analyzer.analyze(model)

    scorer = DreadScorer()
    scored = scorer.score_all(threats)

    generate_report(model, scored, output=output)
    click.echo(f"✅ Report saved to {output}")
    click.echo(f"   {len(scored)} threats documented across {len(model.components)} components")


@cli.command()
@click.argument("model_file", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Output file path (.mmd)")
def diagram(model_file: str, output: str | None):
    """Generate a Mermaid Data Flow Diagram."""
    model = _load_model_from_file(model_file)
    mermaid_code = generate_mermaid_dfd(model)

    if output:
        with open(output, "w") as f:
            f.write(mermaid_code)
        click.echo(f"✅ DFD saved to {output}")
    else:
        click.echo(mermaid_code)


@cli.command()
@click.option("--category", "-c", default=None, help="Filter by STRIDE category")
@click.option("--search", "-q", default=None, help="Search by keyword")
def threats(category: str | None, search: str | None):
    """List threats from the knowledge base."""
    db = ThreatKnowledgeBase()

    if search:
        results = db.search(search)
    elif category:
        results = db.get_by_category(category)
    else:
        results = db.get_all()

    if not results:
        click.echo("No threats found matching your criteria.")
        return

    for t in results:
        click.echo(f"\n[{t.id}] {t.category}: {t.name}")
        click.echo(f"  {t.description[:120]}...")
        click.echo(f"  Severity: {t.severity_range}")
        click.echo(f"  Mitigations: {len(t.mitigations)} | Indicators: {len(t.indicators)}")


if __name__ == "__main__":
    cli()
