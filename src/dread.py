"""
DREAD Risk Scoring for Threat Prioritization.

DREAD is a qualitative risk assessment model that scores each
identified threat across five dimensions (1-10 each):

    D — Damage:          How bad is it if exploited?
    R — Reproducibility: How easy is it to reproduce the attack?
    E — Exploitability:  How much skill/effort is needed to exploit?
    A — Affected Users:  How many users are impacted?
    D — Discoverability: How easy is it to discover the vulnerability?

Total DREAD Score = D + R + E + A + D  (range: 5–50)

Severity Mapping:
    40-50: Critical
    30-39: High
    20-29: Medium
    10-19: Low
     5-9:  Informational

This module provides both:
1. Automatic scoring based on threat properties (heuristic)
2. A framework for manual scoring during threat model sessions

Usage:
    scorer = DreadScorer()
    scored_threats = scorer.score_all(threats)
    # or manually:
    scores = DreadScores(damage=8, reproducibility=7, exploitability=6,
                         affected_users=9, discoverability=5)
    print(scores.total)  # 35 → "High"
"""

from dataclasses import dataclass

from src.stride import Threat, StrideCategory


@dataclass
class DreadScores:
    """
    Individual DREAD dimension scores for a threat.

    Each score ranges from 1 (lowest risk) to 10 (highest risk).
    """

    damage: int = 5
    """How much damage is caused if the threat is exploited?
    1 = minimal impact, 10 = complete system compromise or data loss."""

    reproducibility: int = 5
    """How easy is it to reproduce the exploit?
    1 = very difficult, requires specific conditions. 10 = trivially reproducible."""

    exploitability: int = 5
    """How much skill/tooling is needed to exploit?
    1 = requires nation-state capabilities. 10 = script kiddie can do it."""

    affected_users: int = 5
    """What percentage of users are affected?
    1 = single user in rare conditions. 10 = all users."""

    discoverability: int = 5
    """How easy is it to discover the vulnerability?
    1 = requires deep internal knowledge. 10 = publicly visible."""

    @property
    def total(self) -> int:
        """Total DREAD score (5-50)."""
        return (
            self.damage
            + self.reproducibility
            + self.exploitability
            + self.affected_users
            + self.discoverability
        )

    @property
    def severity(self) -> str:
        """Map total score to severity label."""
        score = self.total
        if score >= 40:
            return "Critical"
        elif score >= 30:
            return "High"
        elif score >= 20:
            return "Medium"
        elif score >= 10:
            return "Low"
        else:
            return "Informational"

    def to_dict(self) -> dict:
        return {
            "damage": self.damage,
            "reproducibility": self.reproducibility,
            "exploitability": self.exploitability,
            "affected_users": self.affected_users,
            "discoverability": self.discoverability,
            "total": self.total,
            "severity": self.severity,
        }


class DreadScorer:
    """
    Scores threats using the DREAD model.

    Provides heuristic auto-scoring based on threat properties.
    In a real threat modeling session, scores would be discussed
    and agreed upon by the team — this provides a starting point.
    """

    # Heuristic scoring based on STRIDE category and severity
    _CATEGORY_BASELINES: dict[StrideCategory, DreadScores] = {
        StrideCategory.SPOOFING: DreadScores(
            damage=7, reproducibility=6, exploitability=6,
            affected_users=7, discoverability=5,
        ),
        StrideCategory.TAMPERING: DreadScores(
            damage=8, reproducibility=5, exploitability=5,
            affected_users=6, discoverability=4,
        ),
        StrideCategory.REPUDIATION: DreadScores(
            damage=5, reproducibility=8, exploitability=7,
            affected_users=5, discoverability=3,
        ),
        StrideCategory.INFORMATION_DISCLOSURE: DreadScores(
            damage=8, reproducibility=6, exploitability=5,
            affected_users=7, discoverability=5,
        ),
        StrideCategory.DENIAL_OF_SERVICE: DreadScores(
            damage=6, reproducibility=7, exploitability=7,
            affected_users=8, discoverability=7,
        ),
        StrideCategory.ELEVATION_OF_PRIVILEGE: DreadScores(
            damage=9, reproducibility=5, exploitability=5,
            affected_users=6, discoverability=4,
        ),
    }

    # Severity modifiers — adjust baseline scores
    _SEVERITY_MODIFIERS: dict[str, int] = {
        "Critical": 2,
        "High": 1,
        "Medium": 0,
        "Low": -1,
        "Informational": -2,
    }

    def score(self, threat: Threat) -> Threat:
        """
        Score a single threat using DREAD heuristics.

        Takes the baseline scores for the STRIDE category and
        adjusts them based on the initial severity assessment.
        Returns the threat with dread_score populated.
        """
        baseline = self._CATEGORY_BASELINES.get(
            threat.category,
            DreadScores(),
        )
        modifier = self._SEVERITY_MODIFIERS.get(threat.severity, 0)

        scores = DreadScores(
            damage=self._clamp(baseline.damage + modifier),
            reproducibility=self._clamp(baseline.reproducibility + modifier),
            exploitability=self._clamp(baseline.exploitability + modifier),
            affected_users=self._clamp(baseline.affected_users + modifier),
            discoverability=self._clamp(baseline.discoverability + modifier),
        )

        threat.dread_score = scores.total
        threat.severity = scores.severity
        threat._dread_scores = scores  # Attach for reporting
        return threat

    def score_all(self, threats: list[Threat]) -> list[Threat]:
        """Score all threats and return them sorted by DREAD score (highest first)."""
        scored = [self.score(t) for t in threats]
        scored.sort(key=lambda t: t.dread_score, reverse=True)
        return scored

    @staticmethod
    def _clamp(value: int, minimum: int = 1, maximum: int = 10) -> int:
        """Clamp a score to the valid range [1, 10]."""
        return max(minimum, min(maximum, value))

    @staticmethod
    def manual_score(
        threat: Threat,
        damage: int,
        reproducibility: int,
        exploitability: int,
        affected_users: int,
        discoverability: int,
    ) -> Threat:
        """
        Manually score a threat (for use during team sessions).

        All scores must be integers between 1 and 10.
        """
        for name, val in [
            ("damage", damage),
            ("reproducibility", reproducibility),
            ("exploitability", exploitability),
            ("affected_users", affected_users),
            ("discoverability", discoverability),
        ]:
            if not 1 <= val <= 10:
                raise ValueError(f"{name} must be between 1 and 10, got {val}")

        scores = DreadScores(
            damage=damage,
            reproducibility=reproducibility,
            exploitability=exploitability,
            affected_users=affected_users,
            discoverability=discoverability,
        )

        threat.dread_score = scores.total
        threat.severity = scores.severity
        threat._dread_scores = scores
        return threat
