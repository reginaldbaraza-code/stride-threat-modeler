"""Tests for src.model — core data model classes."""

import pytest
from src.model import (
    ThreatModel, Component, ComponentType, DataFlow,
    TrustBoundary, DataClassification, Protocol,
)


class TestComponent:
    def test_create_process(self):
        comp = Component(name="API Server", component_type=ComponentType.PROCESS)
        assert comp.name == "API Server"
        assert comp.component_type == ComponentType.PROCESS
        assert not comp.is_internet_facing
        assert not comp.handles_pii

    def test_create_datastore_with_pii(self):
        comp = Component(
            name="User DB",
            component_type=ComponentType.DATASTORE,
            handles_pii=True,
            has_encryption_at_rest=True,
        )
        assert comp.handles_pii
        assert comp.has_encryption_at_rest

    def test_str_representation(self):
        comp = Component(name="Gateway", component_type=ComponentType.PROCESS)
        assert str(comp) == "Gateway (process)"


class TestDataFlow:
    def test_create_flow(self):
        src = Component(name="Client", component_type=ComponentType.EXTERNAL_ENTITY)
        dst = Component(name="Server", component_type=ComponentType.PROCESS)
        flow = DataFlow(
            name="HTTP Request",
            source=src,
            destination=dst,
            data_classification=DataClassification.CONFIDENTIAL,
            is_encrypted=True,
        )
        assert flow.name == "HTTP Request"
        assert flow.source.name == "Client"
        assert flow.destination.name == "Server"
        assert flow.data_classification == DataClassification.CONFIDENTIAL
        assert flow.is_encrypted

    def test_boundary_crossing_display(self):
        src = Component(name="A", component_type=ComponentType.PROCESS)
        dst = Component(name="B", component_type=ComponentType.DATASTORE)
        flow = DataFlow(
            name="Query", source=src, destination=dst,
            crosses_trust_boundary=True,
        )
        assert "CROSSES BOUNDARY" in str(flow)


class TestTrustBoundary:
    def test_contains_component(self):
        comp = Component(name="Server", component_type=ComponentType.PROCESS)
        boundary = TrustBoundary(
            name="DMZ",
            description="Demilitarized zone",
            components=[comp],
        )
        assert boundary.contains(comp)

    def test_does_not_contain(self):
        comp1 = Component(name="Inside", component_type=ComponentType.PROCESS)
        comp2 = Component(name="Outside", component_type=ComponentType.PROCESS)
        boundary = TrustBoundary(name="DMZ", components=[comp1])
        assert not boundary.contains(comp2)


class TestThreatModel:
    def setup_method(self):
        self.tm = ThreatModel(name="Test App", description="Unit test model")
        self.server = Component(
            name="Server", component_type=ComponentType.PROCESS,
            is_internet_facing=True, handles_pii=True,
        )
        self.db = Component(
            name="Database", component_type=ComponentType.DATASTORE,
            handles_pii=True,
        )

    def test_add_component(self):
        self.tm.add_component(self.server)
        assert len(self.tm.components) == 1

    def test_duplicate_component_raises(self):
        self.tm.add_component(self.server)
        with pytest.raises(ValueError, match="already exists"):
            self.tm.add_component(self.server)

    def test_add_dataflow(self):
        flow = DataFlow(name="Query", source=self.server, destination=self.db)
        self.tm.add_dataflow(flow)
        assert len(self.tm.dataflows) == 1

    def test_get_internet_facing(self):
        internal = Component(name="Internal", component_type=ComponentType.PROCESS)
        self.tm.add_component(self.server)
        self.tm.add_component(internal)
        assert self.tm.get_internet_facing() == [self.server]

    def test_get_pii_handlers(self):
        self.tm.add_component(self.server)
        self.tm.add_component(self.db)
        pii = self.tm.get_pii_handlers()
        assert len(pii) == 2

    def test_get_boundary_crossings(self):
        crossing = DataFlow(
            name="Cross", source=self.server, destination=self.db,
            crosses_trust_boundary=True,
        )
        internal = DataFlow(
            name="Internal", source=self.server, destination=self.db,
            crosses_trust_boundary=False,
        )
        self.tm.add_dataflow(crossing)
        self.tm.add_dataflow(internal)
        assert len(self.tm.get_boundary_crossings()) == 1

    def test_summary(self):
        self.tm.add_component(self.server)
        self.tm.add_component(self.db)
        flow = DataFlow(
            name="Query", source=self.server, destination=self.db,
            crosses_trust_boundary=True,
        )
        self.tm.add_dataflow(flow)
        boundary = TrustBoundary(name="B1", components=[self.server])
        self.tm.add_trust_boundary(boundary)

        s = self.tm.summary()
        assert s["name"] == "Test App"
        assert s["components"] == 2
        assert s["dataflows"] == 1
        assert s["trust_boundaries"] == 1
        assert s["boundary_crossings"] == 1
        assert s["internet_facing"] == 1
        assert s["pii_handlers"] == 2
