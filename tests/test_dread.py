"""Tests for src.dread — DREAD risk scoring."""

import pytest
from src.dread import DreadScorer, DreadScores
from src.stride import Threat, StrideCategory


class TestDreadScores:
    def test_total_calculation(self):
        scores = DreadScores(damage=8, reproducibility=7, exploitability=6,
                             affected_users=9, discoverability=5)
        assert scores.total == 35

    def test_severity_critical(self):
        scores = DreadScores(damage=10, reproducibility=9, exploitability=8,
                             affected_users=8, discoverability=9)
        assert scores.severity == "Critical"

    def test_severity_high(self):
        scores = DreadScores(damage=7, reproducibility=7, exploitability=6,
                             affected_users=6, discoverability=6)
        assert scores.severity == "High"

    def test_severity_medium(self):
        scores = DreadScores(damage=5, reproducibility=5, exploitability=4,
                             affected_users=4, discoverability=5)
        assert scores.severity == "Medium"

    def test_severity_low(self):
        scores = DreadScores(damage=2, reproducibility=3, exploitability=2,
                             affected_users=2, discoverability=3)
        assert scores.severity == "Low"

    def test_severity_informational(self):
        scores = DreadScores(damage=1, reproducibility=1, exploitability=1,
                             affected_users=1, discoverability=1)
        assert scores.severity == "Informational"

    def test_to_dict(self):
        scores = DreadScores(damage=5, reproducibility=5, exploitability=5,
                             affected_users=5, discoverability=5)
        d = scores.to_dict()
        assert d["total"] == 25
        assert d["severity"] == "Medium"
        assert d["damage"] == 5


class TestDreadScorer:
    @pytest.fixture
    def scorer(self):
        return DreadScorer()

    @pytest.fixture
    def sample_threat(self):
        return Threat(
            id="THR-001",
            category=StrideCategory.SPOOFING,
            title="Test threat",
            description="A test threat",
            target="Test Component",
            severity="High",
        )

    def test_score_sets_dread_score(self, scorer, sample_threat):
        scored = scorer.score(sample_threat)
        assert scored.dread_score > 0
        assert scored.dread_score <= 50

    def test_score_updates_severity(self, scorer, sample_threat):
        scored = scorer.score(sample_threat)
        assert scored.severity in ("Critical", "High", "Medium", "Low", "Informational")

    def test_critical_severity_scores_higher(self, scorer):
        critical = Threat(
            id="T1", category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            title="Critical", description="", target="X", severity="Critical",
        )
        low = Threat(
            id="T2", category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            title="Low", description="", target="X", severity="Low",
        )
        scorer.score(critical)
        scorer.score(low)
        assert critical.dread_score > low.dread_score

    def test_score_all_sorts_descending(self, scorer):
        threats = [
            Threat(id="T1", category=StrideCategory.REPUDIATION,
                   title="Low", description="", target="X", severity="Low"),
            Threat(id="T2", category=StrideCategory.SPOOFING,
                   title="Critical", description="", target="X", severity="Critical"),
            Threat(id="T3", category=StrideCategory.TAMPERING,
                   title="Medium", description="", target="X", severity="Medium"),
        ]
        scored = scorer.score_all(threats)
        for i in range(len(scored) - 1):
            assert scored[i].dread_score >= scored[i + 1].dread_score

    def test_clamp_values(self):
        assert DreadScorer._clamp(0) == 1
        assert DreadScorer._clamp(11) == 10
        assert DreadScorer._clamp(5) == 5

    def test_all_categories_have_baselines(self, scorer):
        for category in StrideCategory:
            assert category in scorer._CATEGORY_BASELINES


class TestManualScoring:
    def test_manual_score(self):
        threat = Threat(
            id="T1", category=StrideCategory.TAMPERING,
            title="Test", description="", target="X",
        )
        scored = DreadScorer.manual_score(
            threat, damage=9, reproducibility=7,
            exploitability=6, affected_users=8, discoverability=5,
        )
        assert scored.dread_score == 35
        assert scored.severity == "High"

    def test_manual_score_validates_range(self):
        threat = Threat(
            id="T1", category=StrideCategory.TAMPERING,
            title="Test", description="", target="X",
        )
        with pytest.raises(ValueError, match="between 1 and 10"):
            DreadScorer.manual_score(
                threat, damage=11, reproducibility=5,
                exploitability=5, affected_users=5, discoverability=5,
            )

    def test_manual_score_zero_invalid(self):
        threat = Threat(
            id="T1", category=StrideCategory.TAMPERING,
            title="Test", description="", target="X",
        )
        with pytest.raises(ValueError):
            DreadScorer.manual_score(
                threat, damage=0, reproducibility=5,
                exploitability=5, affected_users=5, discoverability=5,
            )
