MERMAID_CLASSDEFS = [
    "    classDef network fill:#fee,stroke:#c00,stroke-width:3px,color:#000",
    "    classDef execution fill:#fee,stroke:#c00,stroke-width:3px,color:#000",
    "    classDef dom fill:#fef,stroke:#90c,stroke-width:3px,color:#000",
    "    classDef storage fill:#eef,stroke:#36c,stroke-width:3px,color:#000",
    "    classDef sensitive fill:#ffe,stroke:#c90,stroke-width:3px,color:#000",
    "    classDef dynamic fill:#efe,stroke:#090,stroke-width:3px,color:#000",
]


def sanitize_label(name: str) -> str:
    return name.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def generate_mermaid_flowchart(functions: dict) -> tuple[str, bool]:
    lines = ["flowchart TD"]
    has_edges = False

    # Sequential node IDs avoid collisions with Mermaid reserved words (end, ...)
    # and JS prototype keys (constructor, __proto__) that crash the parser.
    node_ids = {name: f"n{i}" for i, name in enumerate(functions)}

    for name, func in functions.items():
        node_id = node_ids[name]
        safe_label = sanitize_label(func.name)
        node_def = f'    {node_id}["{safe_label}()"]'
        if func.side_effects:
            primary_class = sorted(func.side_effects)[0]
            node_def += f":::{primary_class}"
        lines.append(node_def)

        for call in func.calls:
            if call in node_ids:
                lines.append(f"    {node_id} --> {node_ids[call]}")
                has_edges = True

    all_writes = set()
    all_reads = set()
    for f in functions.values():
        all_writes.update(f.writes)
        all_reads.update(f.reads)
    shared_vars = all_writes.intersection(all_reads)

    shared_var_edges: dict[tuple[str, str], list[str]] = {}
    for var_name in shared_vars:
        writers = [f for f in functions.values() if var_name in f.writes]
        readers = [f for f in functions.values() if var_name in f.reads]
        for writer in writers:
            for reader in readers:
                if writer.name != reader.name:
                    key = (node_ids[writer.name], node_ids[reader.name])
                    shared_var_edges.setdefault(key, []).append(var_name)

    for (w_id, r_id), var_names in shared_var_edges.items():
        var_label = ", ".join(sorted(set(var_names)))
        lines.append(f'    {w_id} -.->|"變數: {var_label}"| {r_id}')
        has_edges = True

    lines.extend(MERMAID_CLASSDEFS)
    return "\n".join(lines), has_edges
