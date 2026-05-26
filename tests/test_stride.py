"""Tests for src.stride — STRIDE threat identification engine."""

import pytest
from src.model import (
    ThreatModel, Component, ComponentType, DataFlow,
    DataClassification, Protocol,
)
from src.stride import StrideAnalyzer, StrideCategory


@pytest.fixture
def analyzer():
    return StrideAnalyzer()


@pytest.fixture
def insecure_server():
    return Component(
        name="Insecure Server",
        component_type=ComponentType.PROCESS,
        is_internet_facing=True,
        has_authentication=False,
        has_authorization=False,
        has_input_validation=False,
        has_logging=False,
        is_hardened=False,
    )


@pytest.fixture
def secure_server():
    return Component(
        name="Secure Server",
        component_type=ComponentType.PROCESS,
        is_internet_facing=True,
        has_authentication=True,
        has_authorization=True,
        has_input_validation=True,
        has_logging=True,
        is_hardened=True,
    )


@pytest.fixture
def pii_datastore():
    return Component(
        name="User DB",
        component_type=ComponentType.DATASTORE,
        handles_pii=True,
        has_encryption_at_rest=False,
    )


class TestSpoofing:
    def test_missing_auth_flagged(self, analyzer, insecure_server):
        tm = ThreatModel(name="Test")
        tm.add_component(insecure_server)
        threats = analyzer.analyze(tm)
        spoofing = [t for t in threats if t.category == StrideCategory.SPOOFING]
        assert len(spoofing) >= 1
        assert any("authentication" in t.title.lower() for t in spoofing)

    def test_internet_facing_no_auth_is_high(self, analyzer, insecure_server):
        tm = ThreatModel(name="Test")
        tm.add_component(insecure_server)
        threats = analyzer.analyze(tm)
        spoofing = [t for t in threats if t.category == StrideCategory.SPOOFING]
        assert any(t.severity == "High" for t in spoofing)

    def test_secure_server_no_spoofing_for_missing_auth(self, analyzer, secure_server):
        tm = ThreatModel(name="Test")
        tm.add_component(secure_server)
        threats = analyzer.analyze(tm)
        spoofing = [t for t in threats if t.category == StrideCategory.SPOOFING]
        # Secure server has auth, so no "missing auth" spoofing
        assert not any("Missing authentication" in t.title for t in spoofing)


class TestTampering:
    def test_unencrypted_datastore_flagged(self, analyzer, pii_datastore):
        tm = ThreatModel(name="Test")
        tm.add_component(pii_datastore)
        threats = analyzer.analyze(tm)
        tampering = [t for t in threats if t.category == StrideCategory.TAMPERING]
        assert len(tampering) >= 1
        assert any("encrypt" in t.title.lower() for t in tampering)

    def test_missing_input_validation_flagged(self, analyzer, insecure_server):
        tm = ThreatModel(name="Test")
        tm.add_component(insecure_server)
        threats = analyzer.analyze(tm)
        tampering = [t for t in threats if t.category == StrideCategory.TAMPERING]
        assert any("input validation" in t.title.lower() for t in tampering)


class TestRepudiation:
    def test_no_logging_flagged(self, analyzer, insecure_server):
        tm = ThreatModel(name="Test")
        tm.add_component(insecure_server)
        threats = analyzer.analyze(tm)
        repudiation = [t for t in threats if t.category == StrideCategory.REPUDIATION]
        assert len(repudiation) >= 1
        assert any("logging" in t.title.lower() for t in repudiation)


class TestDenialOfService:
    def test_internet_facing_unhardened_flagged(self, analyzer, insecure_server):
        tm = ThreatModel(name="Test")
        tm.add_component(insecure_server)
        threats = analyzer.analyze(tm)
        dos = [t for t in threats if t.category == StrideCategory.DENIAL_OF_SERVICE]
        assert len(dos) >= 1


class TestElevationOfPrivilege:
    def test_no_authorization_flagged(self, analyzer, insecure_server):
        tm = ThreatModel(name="Test")
        tm.add_component(insecure_server)
        threats = analyzer.analyze(tm)
        eop = [t for t in threats if t.category == StrideCategory.ELEVATION_OF_PRIVILEGE]
        assert any("authorization" in t.title.lower() for t in eop)

    def test_pii_datastore_access_control(self, analyzer, pii_datastore):
        tm = ThreatModel(name="Test")
        tm.add_component(pii_datastore)
        threats = analyzer.analyze(tm)
        eop = [t for t in threats if t.category == StrideCategory.ELEVATION_OF_PRIVILEGE]
        assert len(eop) >= 1


class TestDataFlowAnalysis:
    def test_unencrypted_boundary_crossing(self, analyzer):
        src = Component(name="A", component_type=ComponentType.PROCESS)
        dst = Component(name="B", component_type=ComponentType.DATASTORE)
        flow = DataFlow(
            name="Insecure Flow", source=src, destination=dst,
            data_classification=DataClassification.CONFIDENTIAL,
            is_encrypted=False,
            crosses_trust_boundary=True,
        )
        tm = ThreatModel(name="Test")
        tm.add_component(src)
        tm.add_component(dst)
        tm.add_dataflow(flow)
        threats = analyzer.analyze(tm)
        info_disc = [t for t in threats if t.category == StrideCategory.INFORMATION_DISCLOSURE]
        assert any("trust boundary" in t.title.lower() or "unencrypted" in t.title.lower()
                    for t in info_disc)

    def test_auth_token_unencrypted(self, analyzer):
        src = Component(name="Client", component_type=ComponentType.EXTERNAL_ENTITY)
        dst = Component(name="Server", component_type=ComponentType.PROCESS)
        flow = DataFlow(
            name="Login", source=src, destination=dst,
            has_auth_token=True,
            is_encrypted=False,
        )
        tm = ThreatModel(name="Test")
        tm.add_component(src)
        tm.add_component(dst)
        tm.add_dataflow(flow)
        threats = analyzer.analyze(tm)
        spoofing = [t for t in threats if t.category == StrideCategory.SPOOFING]
        assert any("credentials" in t.title.lower() or "auth" in t.title.lower()
                    for t in spoofing)

    def test_sensitive_data_over_http(self, analyzer):
        src = Component(name="A", component_type=ComponentType.PROCESS)
        dst = Component(name="B", component_type=ComponentType.PROCESS)
        flow = DataFlow(
            name="HTTP PII", source=src, destination=dst,
            data_classification=DataClassification.RESTRICTED,
            protocol=Protocol.HTTP,
        )
        tm = ThreatModel(name="Test")
        tm.add_component(src)
        tm.add_component(dst)
        tm.add_dataflow(flow)
        threats = analyzer.analyze(tm)
        assert any("HTTP" in t.title for t in threats)


class TestThreatIds:
    def test_unique_ids(self, analyzer, insecure_server, pii_datastore):
        tm = ThreatModel(name="Test")
        tm.add_component(insecure_server)
        tm.add_component(pii_datastore)
        threats = analyzer.analyze(tm)
        ids = [t.id for t in threats]
        assert len(ids) == len(set(ids)), "Threat IDs must be unique"

    def test_sequential_ids(self, analyzer, insecure_server):
        tm = ThreatModel(name="Test")
        tm.add_component(insecure_server)
        threats = analyzer.analyze(tm)
        for i, t in enumerate(threats, 1):
            assert t.id == f"THR-{i:03d}"
