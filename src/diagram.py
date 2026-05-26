"""
Data Flow Diagram Generator.

Generates Mermaid-syntax DFD diagrams from a ThreatModel.
Mermaid renders in GitHub README files, making these diagrams
visible directly in the repository without extra tooling.

Output format: Mermaid flowchart syntax
    - Components are styled by type (process, datastore, external)
    - Trust boundaries are shown as subgraphs
    - Data flows show protocol and classification
    - Boundary-crossing flows are highlighted

Usage:
    from src.diagram import generate_mermaid_dfd

    mermaid_code = generate_mermaid_dfd(threat_model)
    print(mermaid_code)  # Paste into any Mermaid renderer

    # Or save to file for GitHub README embedding:
    save_mermaid(threat_model, "docs/diagrams/dfd.mmd")
"""

from src.model import ThreatModel, Component, ComponentType, DataClassification


def generate_mermaid_dfd(model: ThreatModel) -> str:
    """
    Generate a Mermaid flowchart representing the system's Data Flow Diagram.

    Components are represented as:
    - Processes: rounded rectangles
    - Datastores: cylinders (database shape)
    - External entities: standard rectangles

    Data flows are arrows with labels showing protocol and data classification.
    Trust boundaries are subgraphs with dashed borders.
    """
    lines = []
    lines.append("flowchart TB")
    lines.append("")

    # Sanitize names for Mermaid IDs (no spaces, special chars)
    def node_id(name: str) -> str:
        return name.replace(" ", "_").replace("/", "_").replace("(", "").replace(")", "")

    # Track which components are inside trust boundaries
    bounded_components = set()
    for boundary in model.trust_boundaries:
        for comp in boundary.components:
            bounded_components.add(comp.name)

    # Render trust boundaries as subgraphs
    for boundary in model.trust_boundaries:
        bid = node_id(boundary.name)
        lines.append(f"    subgraph {bid}[\"{boundary.name}\"]")
        lines.append(f"        style {bid} stroke-dasharray: 5 5")
        for comp in boundary.components:
            lines.append(f"        {_render_component(comp, node_id)}")
        lines.append("    end")
        lines.append("")

    # Render unbounded components
    unbounded = [c for c in model.components if c.name not in bounded_components]
    if unbounded:
        for comp in unbounded:
            lines.append(f"    {_render_component(comp, node_id)}")
        lines.append("")

    # Render data flows
    for flow in model.dataflows:
        src = node_id(flow.source.name)
        dst = node_id(flow.destination.name)
        label = f"{flow.protocol.value.upper()}"
        if flow.data_classification != DataClassification.INTERNAL:
            label += f" [{flow.data_classification.value}]"

        if flow.crosses_trust_boundary:
            # Thick arrow for boundary crossings
            lines.append(f"    {src} ==>|{label}| {dst}")
        else:
            lines.append(f"    {src} -->|{label}| {dst}")

    lines.append("")

    # Style definitions
    lines.append("    %% Styling")
    for comp in model.components:
        nid = node_id(comp.name)
        if comp.component_type == ComponentType.EXTERNAL_ENTITY:
            lines.append(f"    style {nid} fill:#f9f,stroke:#333,stroke-width:2px")
        elif comp.component_type == ComponentType.DATASTORE:
            lines.append(f"    style {nid} fill:#bbf,stroke:#333,stroke-width:2px")
        elif comp.is_internet_facing:
            lines.append(f"    style {nid} fill:#fbb,stroke:#333,stroke-width:2px")
        else:
            lines.append(f"    style {nid} fill:#bfb,stroke:#333,stroke-width:2px")

    return "\n".join(lines)


def _render_component(comp: Component, node_id_fn) -> str:
    """Render a single component in Mermaid syntax with appropriate shape."""
    nid = node_id_fn(comp.name)
    label = comp.name
    if comp.technology:
        label += f"\\n({comp.technology})"

    if comp.component_type == ComponentType.DATASTORE:
        return f"{nid}[(\"{label}\")]"
    elif comp.component_type == ComponentType.EXTERNAL_ENTITY:
        return f"{nid}[\"{label}\"]"
    elif comp.component_type == ComponentType.LAMBDA:
        return f"{nid}{{\"{label}\"}}"
    else:
        return f"{nid}(\"{label}\")"


def save_mermaid(model: ThreatModel, filepath: str) -> None:
    """Save the Mermaid DFD to a file."""
    mermaid_code = generate_mermaid_dfd(model)
    with open(filepath, "w") as f:
        f.write(mermaid_code)


def generate_markdown_dfd(model: ThreatModel) -> str:
    """
    Generate a Markdown code block containing the Mermaid DFD.

    This renders directly in GitHub README files.
    """
    mermaid_code = generate_mermaid_dfd(model)
    return f"```mermaid\n{mermaid_code}\n```"
