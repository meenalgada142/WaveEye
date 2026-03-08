# Main Tool Call Graph (File -> File)

This is the runtime file-level architecture for the cleaned main tool.

## 1) Top-Level Runtime Flow

```text
main.py
  -> Preprocessing/cli.py
  -> IR_backtracking/cli.py
```

`main.py` executes both stages via in-process `runpy` (`run_stage`).

---

## 2) Stage 1: Preprocessing File Calls

```text
Preprocessing/cli.py
  -> Preprocessing/vcd/upload_run_convert_rtl_tb.py
  -> Preprocessing/rtl/classify_signals.py
  -> Preprocessing/rtl/classify_system.py
  -> Preprocessing/mapping/mapping.py            (preferred)
  -> Preprocessing/mapping/mapping_values.py     (fallback)
  -> Preprocessing/mapping/merge_map_signals.py
```

### Nested calls inside VCD preprocessing

```text
Preprocessing/vcd/upload_run_convert_rtl_tb.py
  -> Preprocessing/vcd/file_manager.py
  -> Preprocessing/vcd/vcd_converter.py
  -> Preprocessing/vcd/clock_estimation.py
  -> Preprocessing/vcd/run_script.py   (via runpy)

Preprocessing/vcd/run_script.py
  -> Preprocessing/vcd/inspect_vcd_structure.py
  -> Preprocessing/vcd/list_vcd_signals.py
  -> Preprocessing/vcd/detect_clocks.py
  -> Preprocessing/vcd/clock_estimation.py
```

---

## 3) Stage 2: IR/RCA File Calls

### Core orchestrator

```text
IR_backtracking/cli.py
  -> IR_backtracking/ir_builder.py
  -> IR_backtracking/IR_backtracking.py
  -> IR_backtracking/true_drivers.py
  -> IR_backtracking/rca_8.py
```

### Dynamic tool loading in `IR_backtracking/cli.py`

```text
IR_backtracking/cli.py
  -> IR_backtracking/extract_fsm_encodings.py    (importlib)
  -> IR_backtracking/axil4.py                    (importlib)
  -> IR_backtracking/grouping.py                 (importlib)
  -> IR_backtracking/analyse_interactive.py      (runpy)
  -> IR_backtracking/fsm_illegal_state.py        (importlib)
  -> IR_backtracking/inter_fsm.py                (importlib)
```

### RCA engine composition

```text
IR_backtracking/rca_8.py
  -> IR_backtracking/protocols/loader.py
  -> IR_backtracking/rca_core/*                  (engine, io, mechanism, ...)
  -> IR_backtracking/semantic_checks/*           (memory/transport/invertibility)
  -> IR_backtracking/rca_resolver.py
  -> IR_backtracking/reports/__init__.py

IR_backtracking/protocols/loader.py
  -> IR_backtracking/protocols/<name>/adapter.py
     (default name used by CLI: axi_lite -> protocols/axi_lite/adapter.py)

IR_backtracking/reports/__init__.py
  -> reports/console_diagnosis.py
  -> reports/backtrack_trace.py
  -> reports/rtl_fix_advisor.py
  -> reports/executive_summary.py
  -> reports/violation_reducer.py
  -> reports/failure_timeline.py
  -> reports/peer_review_defense.py
  -> reports/determinism_scorer.py
  -> reports/evidence_filter.py
  -> reports/deep_appendix.py
  -> reports/tool_differentiator.py
  -> reports/causal_pruner.py
  -> reports/rca_explanation.py
  -> reports/signal_set.py
  -> reports/structural_root_cause.py
  -> reports/llm_rca_prompt.py
```

---

## 4) Line-Anchored References (Entry/Dispatch Points)

- `main.py`
  - `run_stage`: line ~182
  - stage dispatch to `Preprocessing/cli.py`: lines ~316-320
  - stage dispatch to `IR_backtracking/cli.py`: lines ~345-349

- `Preprocessing/cli.py`
  - `run_step`: line ~85
  - call `upload_run_convert_rtl_tb.py`: line ~222
  - call `classify_signals.py`: line ~257 and run at ~265
  - call `classify_system.py`: line ~281 and run at ~295
  - select mapping script: lines ~312-323
  - call mapping script: line ~359
  - call `merge_map_signals.py`: lines ~372 and ~388

- `Preprocessing/vcd/upload_run_convert_rtl_tb.py`
  - imports `file_manager`, `vcd_converter`, `clock_estimation`: lines ~14-16
  - call `run_script.py` via runpy: lines ~237 and ~253

- `Preprocessing/vcd/run_script.py`
  - tool list (`inspect_vcd_structure.py`, `list_vcd_signals.py`, `detect_clocks.py`): lines ~114-117
  - execute each tool: line ~129

- `IR_backtracking/cli.py`
  - imports `ir_builder`, `IR_backtracking`, `true_drivers`, `rca_8`: lines ~89-92
  - `process_rtl_file`: line ~325
  - `run_axil4_checker`: line ~459
  - `run_signal_grouping`: line ~535
  - `run_interactive_analysis`: line ~595
  - `run_fsm_illegal_state_check`: line ~750
  - `run_inter_fsm_analysis`: line ~932
  - `main`: line ~1159
  - direct `run_waveeye_rca(...)`: line ~1317

- `IR_backtracking/rca_8.py`
  - `run_waveeye_rca`: line ~1882
  - `load_protocol(...)`: line ~1954
  - `run_transaction_binding(...)`: line ~1968
  - `resolve_root_cause(...)`: line ~2019
  - `generate_console_diagnosis(...)`: line ~2305

