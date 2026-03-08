# WaveEye — AXI-Lite Protocol Root Cause Analyzer

WaveEye is a deterministic RTL root cause analysis (RCA) tool for AXI4-Lite protocol bugs.
It takes a SystemVerilog/Verilog design and a simulation waveform (VCD), and produces a
structured diagnosis: **what failed, why it failed, and exactly where in the RTL to fix it.**

It does not require formal verification tools, does not need test modifications, and runs
fully offline from a single command.

---

## What It Does

Most protocol checkers tell you *that* a handshake rule was violated. WaveEye tells you
*why* — tracing from the observed protocol symptom back through the RTL datapath to the
structural defect that caused it.

### Two-stage pipeline

```
Stage 1 — Preprocessing
  VCD waveform + RTL  →  clock-aligned signal CSV  →  signal classification

Stage 2 — IR + RCA
  RTL  →  Intermediate Representation (IR)
  IR   →  semantic datapath analysis (width, transport, invertibility, aliasing)
  IR + waveform  →  AXI4-Lite protocol checker (15 rules)
  Protocol findings + datapath violations  →  causal binding  →  root cause verdict
```

### What it detects

**Protocol layer (15 AXI4-Lite rules):**
- VALID persistence violations (WVALID, AWVALID, ARVALID dropped before handshake)
- Response missing / unprompted (BVALID, RVALID not issued after accepted transaction)
- Ready–Valid coupling violations
- Overlapping outstanding transactions

**Structural datapath layer:**
- Width truncation / extension without semantic (`WDATA[7:0]` assigned to a 32-bit register)
- Non-invertible transforms (constant injection, signal duplication in concat)
- Lane bijection violations (loop writes to constant byte slice)
- Byte-lane collapse and write aliasing
- Transport offset / strobe mismatches
- Address monotonicity violations (non-monotone address transforms)

**Temporal / FSM layer:**
- Stuck signals (globally stuck, post-reset, oneshot)
- FSM illegal states and unreachable transitions
- Inter-FSM dependency violations
- Cyclic enable dependencies (forward-progress deadlock)

### Verdict hierarchy

```
TRANSPORT  >  DATAPATH  >  PROTOCOL  >  INCONCLUSIVE
```

When a structural defect is proven to have caused protocol violations it is
classified as DATAPATH, not PROTOCOL — the symptom and the root cause are
reported separately.

---

## Tested Designs

WaveEye has been validated on the following designs with **zero false positives**
on clean waveforms and correct root cause identification on injected bugs.

Example inputs are provided in the `examples/` directory — each folder contains
an `rtl/` subfolder (RTL source) and a `wave/` subfolder (VCD waveform).

### 1. `bvalibug` — BVALID scheduling conflict

| | |
|---|---|
| **RTL** | `axi_lite_fifo_wrapper.sv` + `dut.v` + `fifo.sv` |
| **Bug** | BVALID asserted by `(write_state == RESP)` then immediately cancelled by a more-specific override in the same clock cycle |
| **Protocol violations** | 40 |
| **Structural defects** | 4 patterns — 3× WIDTH_TRUNCATION (RDATA←dout/count/fifo_level) + NON_BIJECTIVE_CAST at lines 172, 181, 186 |
| **Result** | `AXI4L_WRITE_RESPONSE_MISSING` — scheduling conflict at cycle 1312; D3 cancels D2's assertion before BREADY handshake |
| **Execution time** | 3.6 s |

```
Primary Failure    : AXI4L_WRITE_RESPONSE_MISSING  (AXI4-Lite Spec §A3.2.1)
Confirmed Root Cause : BVALID asserted by (write_state == RESP) then cancelled by more-specific override
Severity           : Handshake violation — AXI compliance failure
Transactions Affected : Protocol-visible failures: 2 | Structurally corrupted writes: 0
```

### 2. `arreay_bug` — RVALID asserted without AR handshake

| | |
|---|---|
| **RTL** | `axi_lite_fifo_wrapper.sv` + `dut.v` + `fifo.sv` |
| **Bug** | RVALID driven purely by local FSM state — ARVALID and ARREADY never gated in predicate |
| **Protocol violations** | 1 |
| **Structural defects** | 4 patterns — same WIDTH_TRUNCATION (RDATA←dout/count/fifo_level) detected |
| **Result** | `AXI4L_RVALID_UNPROMPTED` — protocol failure structurally guaranteed; predicate `(ARESETn && read_state == RESP)` contains no path to ARVALID/ARREADY |
| **Execution time** | 1.8 s |

```
Primary Failure    : AXI4L_RVALID_UNPROMPTED  (AXI4-Lite Spec §A3.3.1)
Confirmed Root Cause : RVALID driver predicate missing required dependencies: ARVALID, ARREADY
Severity           : Handshake violation — AXI compliance failure
Transactions Affected : Protocol-visible failures: 1 | Structurally corrupted writes: 0
```

### 3. `axi_lite_slave_v1_0` — RDATA stability violation

| | |
|---|---|
| **RTL** | `axi_lite_slave_v1_0.v` (ARM AXI-Lite slave reference) |
| **Bug** | RDATA mutated during RVALID window — no RREADY gate on the read data driver |
| **Protocol violations** | 1 |
| **Structural defects** | 0 |
| **Result** | `AXI4L_RDATA_STABILITY` — `s_axi_rdata` driven by `if (true)` condition; mutated at cycle 315 (0x22041195 → 0) while RVALID=1, RREADY=0 |
| **Execution time** | 0.2 s |

```
Primary Failure    : AXI4L_RDATA_STABILITY  (AXI4-Lite Spec §A3.3.1)
Confirmed Root Cause : RDATA driver has no RREADY gate — payload advances freely during backpressure
Severity           : Handshake violation — AXI compliance failure
```

### 4–6. Alex Forencich AXI-Lite reference designs (open-source)

Validated on three open-source AXI-Lite implementations from Alex Forencich's
[verilog-axi](https://github.com/alexforencich/verilog-axi) library — both with bugs
introduced and on clean waveforms. **Zero false positives** on clean waveforms.

| Example folder | Design | Violations | Result | Time |
|---|---|---|---|---|
| `axil_adapter/` | `axil_adapter.v` (3-file adapter) | 0 | **PASS** — Protocol compliance verified, structural integrity verified | 8.9 s |
| `axil_ram/` | `axil_ram.v` (single-port AXI-Lite RAM) | 56 | `AXI4L_WRITE_RESPONSE_MISSING` — NBA override cancels BVALID; LANE_COLLAPSE + PARTIAL_ASSIGNMENT on `mem` at lines 108, 138 | 0.3 s |
| `axil_dp_ram/` | `axil_dp_ram.v` (dual-port AXI-Lite RAM) | 100 | `AXI4L_BVALID_PERSISTENCE` — NBA override drops BVALID before BREADY; LANE_COLLAPSE on `mem` at lines 164, 218, 292 | 3.5 s |

**PASS case output (axil_adapter — clean design):**
```
────────────────────────────────────────────────────────────────
WaveEye Result
────────────────────────────────────────────────────────────────
Status                : PASS
Protocol compliance   : Verified
Structural integrity  : Verified
Transactions analyzed : 0
Confidence            : 99%
No defects detected.
────────────────────────────────────────────────────────────────
```

Full diagnosis output for each test case is in `test_results/`.

---

## Installation

### Requirements

- Python 3.10 or newer
- [`pyslang`](https://github.com/MikePopoloski/pyslang) ≥ 5.0 (RTL parser)

```bash
pip install pyslang
```

### Option A — Install from wheel (recommended)

Pre-built wheels for Windows and Linux are available in `dist/`:

```bash
# Windows (Python 3.12)
pip install dist/waveeye_axi_lite-1.0.0-cp312-cp312-win_amd64.whl

# Linux (Python 3.10)
pip install dist/waveeye_axi_lite-1.0.0-cp310-cp310-linux_x86_64.whl
```

After installation, run from anywhere:

```bash
waveeye --rtl path/to/design.sv --vcd path/to/sim.vcd
```

### Option B — Standalone executable (no Python required)

```bash
python build_release.py --standalone
# Output: standalone/waveeye/waveeye.exe  (Windows)
#         standalone/waveeye/waveeye      (Linux)
```

Run on any machine without installing Python:

```bash
./standalone/waveeye/waveeye --rtl design.sv --vcd sim.vcd
```

### Option C — Run from source

```bash
git clone https://github.com/meenalgada142/WaveEye.git
cd WaveEye
pip install pyslang
python main.py --rtl path/to/design.sv --vcd path/to/sim.vcd
```

---

## Usage

WaveEye uses an interactive menu-driven CLI. Point it at a folder containing
`rtl/` and `wave/` subfolders (matching the layout in `examples/`).

```bash
python main.py
```

You will be prompted for:
1. **Mode** — `1` for Automated, `2` for Interactive
2. **Input path** — folder containing `rtl/` and `wave/`
3. **RTL selection** — which RTL file to analyze (usually `1`)
4. **Analysis mode** — `2` for AXI4-Lite protocol RCA (recommended)

### Quick run (non-interactive, piped)

```bash
# Linux / macOS / Git Bash
echo -e "1\nexamples/bvalibug\n1\n2" | python main.py

# Windows CMD
(echo 1 & echo examples\bvalibug & echo 1 & echo 2) | python main.py
```

### Example

```bash
python main.py
# > 1            (Automated mode)
# > examples/bvalibug   (input folder)
# > 1            (select RTL file)
# > 2            (AXI4-Lite protocol RCA)
```

### Output files

All outputs are written to `~/WaveEye/outputs/userN/analysis/`:

| File | Contents |
|---|---|
| `*.proof.json` | Machine-readable root cause verdict + evidence |
| `*.proof.appendix.txt` | Human-readable full analysis report |
| `*.diagnosis.txt` | Console diagnosis summary |
| `*.fix_guidance.txt` | RTL fix recommendations |
| `*.backtracking_trace.txt` | Dependency trace from symptom to root cause |
| `*_ir.json` | Intermediate representation of the RTL |
| `*_ir_datapath_violations.json` | All structural violations found |

---

## Building from Source

### Compile Cython extensions (optional, for distribution)

```bash
pip install cython wheel setuptools
python build_release.py              # compile + wheel
python build_release.py --standalone # compile + standalone exe
python build_release.py --both       # wheel + standalone
```

Linux build via WSL:

```bash
# In WSL (Ubuntu):
cd /mnt/c/path/to/WaveEye
pip install cython wheel setuptools
python build_release.py
```

---

## Architecture

```
main.py
├── Stage 1: Preprocessing/cli.py
│   ├── VCD → clock-aligned CSV (vcd/)
│   ├── RTL signal classification (rtl/)
│   └── Signal mapping (mapping/)
│
└── Stage 2: IR_backtracking/cli.py
    ├── ir_builder.py          — RTL → IR (via pyslang)
    │   ├── semantic_checks/   — datapath / transport / invertibility detectors
    ├── axil4.py               — 15-rule AXI4-Lite protocol checker
    ├── rca_8.py               — RCA orchestrator [closed source]
    │   ├── rca_core/          — causal binding, predicate backtracking [closed source]
    │   ├── rca_resolver.py    — root cause verdict engine [closed source]
    │   └── reports/           — output formatters
    └── protocols/axi_lite/    — AXI-Lite signal mapping and rule adapter
```

The core analysis engine (`rca_core/`, `rca_8.py`, `rca_resolver.py`) is distributed
as compiled Cython extensions. All other modules are open source.

---

## Repository Structure

```
WaveEye/
├── main.py                        # entry point
├── setup_cython.py                # Cython build script
├── build_release.py               # wheel + exe packaging
├── pyproject.toml
├── IR_backtracking/
│   ├── cli.py                     # analysis CLI
│   ├── ir_builder.py              # RTL → IR parser
│   ├── axil4.py                   # AXI4-Lite 15-rule checker
│   ├── protocols/                 # protocol adapters
│   ├── semantic_checks/           # datapath violation detectors
│   │   ├── memory_write_analysis.py
│   │   ├── transport_semantic_analysis.py
│   │   └── invertibility.py
│   └── reports/                   # output report generators
└── Preprocessing/
    ├── vcd/                       # VCD processing pipeline
    ├── rtl/                       # RTL signal classifier
    └── mapping/                   # signal-to-waveform mapper
```

---

## License

The open-source shell (preprocessing, IR builder, AXI checker, reports, CLI) is
released under the MIT License.

The core analysis engine (`rca_core/`, `rca_8.py`, `rca_resolver.py`, and related
analysis modules) is proprietary and distributed only as compiled binaries.
