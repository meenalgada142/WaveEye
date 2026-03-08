# Main Tool Architecture (From `main.py`)

## 1) Entry Point

`main.py` is the single orchestrator and runs two stages in-process via `runpy`:

1. `Preprocessing/cli.py`
2. `IR_backtracking/cli.py`

It does **not** use root-level `outputs/` in this repo at runtime.  
Runtime workspace is: `~/WaveEye`.

---

## 2) Required Source Layout (Current Clean Structure)

```text
WaveEye-AXI_Lite_Protocols_c/
├── main.py
├── Preprocessing/
│   ├── cli.py
│   ├── vcd/
│   │   ├── upload_run_convert_rtl_tb.py
│   │   ├── file_manager.py
│   │   ├── vcd_converter.py
│   │   ├── clock_estimation.py
│   │   ├── detect_clocks.py
│   │   ├── inspect_vcd_structure.py
│   │   ├── list_vcd_signals.py
│   │   └── run_script.py
│   ├── rtl/
│   │   ├── classify_signals.py
│   │   ├── classify_system.py
│   │   └── check_system.py
│   └── mapping/
│       ├── mapping.py
│       ├── mapping_values.py
│       └── merge_map_signals.py
├── IR_backtracking/
│   ├── cli.py
│   ├── ir_builder.py
│   ├── IR_backtracking.py
│   ├── true_drivers.py
│   ├── rca_8.py
│   ├── rca_resolver.py
│   ├── axil4.py
│   ├── grouping.py
│   ├── analyse_interactive.py
│   ├── extract_fsm_encodings.py
│   ├── fsm_illegal_state.py
│   ├── inter_fsm.py
│   ├── alias_engine.py
│   ├── deep_backtrack.py
│   ├── cyclic_dependency_analyzer.py
│   ├── temporal_predicate_analysis.py
│   ├── capability_loader.py
│   ├── amba_axi_lite_rules.py
│   ├── rising_falling_edges.py
│   ├── stuck_signals.py
│   ├── runtime_paths.py
│   ├── utils.py
│   ├── protocols/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── loader.py
│   │   ├── axi_lite/
│   │   │   ├── __init__.py
│   │   │   ├── adapter.py
│   │   │   ├── rules.py
│   │   │   └── signal_map.py
│   │   └── dummy/
│   │       ├── __init__.py
│   │       └── adapter.py
│   ├── rca_core/
│   │   ├── __init__.py
│   │   ├── io.py
│   │   ├── engine.py
│   │   ├── contracts.py
│   │   ├── mechanism.py
│   │   ├── causal_graph.py
│   │   ├── transaction_binding.py
│   │   ├── scheduling.py
│   │   ├── predicate_backtrack.py
│   │   ├── deep_backtrack.py
│   │   ├── cyclic_dependency_analyzer.py
│   │   ├── temporal_predicate_analysis.py
│   │   └── semantic_datapath_analysis.py
│   ├── semantic_checks/
│   │   ├── memory_write_analysis.py
│   │   ├── transport_semantic_analysis.py
│   │   └── invertibility.py
│   └── reports/
│       ├── __init__.py
│       ├── console_diagnosis.py
│       ├── executive_summary.py
│       ├── failure_timeline.py
│       ├── structural_root_cause.py
│       ├── backtrack_trace.py
│       ├── rtl_fix_advisor.py
│       ├── deep_appendix.py
│       ├── signal_set.py
│       ├── evidence_filter.py
│       ├── determinism_scorer.py
│       ├── violation_reducer.py
│       ├── causal_pruner.py
│       ├── tool_differentiator.py
│       ├── llm_rca_prompt.py
│       ├── rca_explanation.py
│       └── peer_review_defense.py
└── _archive_main_tool/
    └── cleanup_20260308/
        └── ARCHIVE_MANIFEST.json
```

---

## 3) Runtime Workspace Layout (`~/WaveEye`)

```text
~/WaveEye/
├── Preprocessing/
│   ├── user_input/                  # user-provided RTL/VCD copied by main.py
│   ├── uploaded_vcds/userN/...
│   ├── vcd/                         # materialized tools
│   ├── rtl/
│   └── mapping/
└── outputs/
    └── userN/
        ├── preprocessing/
        │   ├── *_mapped.csv / all_mapped_values.csv
        │   ├── *_signals.json / *_signals.csv
        │   └── *_system.json
        └── analysis/
            ├── *_ir.json
            ├── *_backtracking.csv
            ├── *_true_drivers.csv
            ├── violations.json / violations.csv
            ├── signals.csv
            └── rca8_*.proof.json (+ appendix/output reports)
```

---

## 4) Stage Dependency Chain

### Stage 1: Preprocessing

`main.py` → `Preprocessing/cli.py` →  
`vcd/upload_run_convert_rtl_tb.py` → (`file_manager.py`, `vcd_converter.py`, `clock_estimation.py`)  
`rtl/classify_signals.py`  
`rtl/classify_system.py`  
`mapping/mapping.py` (fallback `mapping_values.py`)

### Stage 2: IR + RCA

`main.py` → `IR_backtracking/cli.py` →  
`ir_builder.py` → `semantic_checks/*`  
`IR_backtracking.py`  
`true_drivers.py`  
`axil4.py`  
`grouping.py`  
`analyse_interactive.py`  
`rca_8.py` → (`protocols/*`, `rca_core/*`, `reports/*`, `rca_resolver.py`)

Optional fallback paths triggered by CLI:

- `extract_fsm_encodings.py`
- `fsm_illegal_state.py`
- `inter_fsm.py`

---

## 5) Archived/Removed From Main Tool

Moved to:

`_archive_main_tool/cleanup_20260308/`

Includes old build artifacts, test/sample folders, duplicate distributions, cached files, and generated analysis clutter.  
Exact list is in:

- `_archive_main_tool/cleanup_20260308/ARCHIVE_MANIFEST.json`

