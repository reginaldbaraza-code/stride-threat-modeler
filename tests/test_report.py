"""Tests for src.report — Markdown report generation."""

import os
import tempfile

from src.model import (
    ThreatModel, Component, ComponentType, DataFlow,
    TrustBoundary, DataClassification,
)
from src.stride import StrideAnalyzer, StrideCategory
from src.dread import DreadScorer
from src.report import generate_report


def _build_test_model():
    """Build a minimal threat model for report testing."""
    tm = ThreatModel(name="Report Test App", description="Testing report generation")

    server = Component(
        name="Web Server", component_type=ComponentType.PROCESS,
        is_internet_facing=True, has_authentication=False,
        has_logging=False, has_input_validation=False,
    )
    db = Component(
        name="Database", component_type=ComponentType.DATASTORE,
        handles_pii=True, has_encryption_at_rest=False,
    )
    tm.add_component(server)
    tm.add_component(db)

    flow = DataFlow(
        name="Query", source=server, destination=db,
        data_classification=DataClassification.RESTRICTED,
        crosses_trust_boundary=True, is_encrypted=True,
    )
    tm.add_dataflow(flow)

    boundary = TrustBoundary(
        name="App / Data", description="Test boundary",
        components=[server, db],
    )
    tm.add_trust_boundary(boundary)

    return tm


class TestReportGeneration:
    def test_report_generates_markdown(self):
        tm = _build_test_model()
        analyzer = StrideAnalyzer()
        threats = analyzer.analyze(tm)
        scorer = DreadScorer()
        scored = scorer.score_all(threats)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            path = f.name

        try:
            report = generate_report(tm, scored, output=path)
            assert "# Threat Model Report" in report
            assert "Report Test App" in report
            assert os.path.exists(path)

            with open(path) as f:
                content = f.read()
            assert content == report
        finally:
            os.unlink(path)

    def test_report_contains_executive_summary(self):
        tm = _build_test_model()
        analyzer = StrideAnalyzer()
        threats = analyzer.analyze(tm)
        scorer = DreadScorer()
        scored = scorer.score_all(threats)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            path = f.name

        try:
            report = generate_report(tm, scored, output=path)
            assert "Executive Summary" in report
            assert "Key Findings" in report
            assert "Total threats identified" in report
        finally:
            os.unlink(path)

    def test_report_contains_all_threats(self):
        tm = _build_test_model()
        analyzer = StrideAnalyzer()
        threats = analyzer.analyze(tm)
        scorer = DreadScorer()
        scored = scorer.score_all(threats)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            path = f.name

        try:
            report = generate_report(tm, scored, output=path)
            for t in scored:
                assert t.id in report
        finally:
            os.unlink(path)

    def test_report_contains_system_overview(self):
        tm = _build_test_model()
        report = generate_report(tm, [], output="/dev/null")
        assert "System Overview" in report
        assert "Web Server" in report
        assert "Database" in report

    def test_report_contains_boundary_crossings(self):
        tm = _build_test_model()
        analyzer = StrideAnalyzer()
        threats = analyzer.analyze(tm)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            path = f.name

        try:
            report = generate_report(tm, threats, output=path)
            assert "Trust Boundary Crossings" in report
        finally:
            os.unlink(path)

    def test_empty_threats_list(self):
        tm = _build_test_model()
        report = generate_report(tm, [], output="/dev/null")
        assert "Total threats identified" in report
        assert "**0**" in report

    def test_report_recommendations(self):
        tm = _build_test_model()
        analyzer = StrideAnalyzer()
        threats = analyzer.analyze(tm)
        scorer = DreadScorer()
        scored = scorer.score_all(threats)

        report = generate_report(tm, scored, output="/dev/null")
        assert "Priority Recommendations" in report
