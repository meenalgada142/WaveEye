# WaveEye

**Automated RTL debugging and root-cause analysis for AXI4-Lite protocol bugs.**

Feed it your SystemVerilog + VCD waveform. Get back the root cause, the causal proof, and exactly where in the RTL to fix it.

```
RTL (.sv/.v)  +  Waveform (.vcd)  →  Root Cause  +  Causal Proof  +  RTL Fix Location
```

No formal verification tools. No test modifications. Fully deterministic, fully offline.

---

## Quick Start

### From Source

```bash
git clone https://github.com/meenalgada142/WaveEye.git
cd WaveEye
pip install -r requirements.txt
python main.py
```

### From Binary (no Python required)

Download from the [Releases page](https://github.com/meenalgada142/WaveEye/releases):

| Platform | File |
|----------|------|
| Windows 64-bit | `WaveEye-windows.zip` |
| Linux x86_64 | `WaveEye-linux.zip` |

```bash
# Linux
unzip WaveEye-linux.zip
chmod +x WaveEye-linux/waveeye
./WaveEye-linux/waveeye

# Windows
# Extract WaveEye-windows.zip, then run:
WaveEye-windows\waveeye.exe
```

---

## Input Format

Point WaveEye at a folder with two subfolders:

```
my_design/
├── rtl/       ← .sv / .v source files
└── wave/      ← simulation waveform (.vcd)
```

Example inputs are in `examples/` — ready to run.

---

## Usage

WaveEye runs an interactive menu. The typical flow:

```
Enter choice (1-3): 1                              ← Automated Mode
Enter path to input folder: /path/to/my_design
Select RTL (<num>, all, quit): all
Select mode (1/2/3): 2                             ← AXI4-Lite protocol RCA
```

### Run on an included example

```bash
python main.py
# Enter choice: 1
# Enter path: examples/bvalibug
# Select RTL: all
# Select mode: 2
```

---

## Output Files

All outputs are written to `~/WaveEye/outputs/userN/analysis/`:

| File | Contents |
|------|----------|
| `*.diagnosis.txt` | Your main result — start here |
| `*.rca_analysis.txt` | Full causal analysis report |
| `*.proof.appendix.txt` | Complete evidence appendix |
| `*.proof.json` | Machine-readable root cause verdict |

---

## What It Actually Outputs

### Bug detected — `bvalibug`

```
────────────────────────────────────────────────────────────────
WaveEye Diagnostic Summary
────────────────────────────────────────────────────────────────
Primary Failure      : AXI4L_WRITE_RESPONSE_MISSING  (AXI4-Lite Spec §A3.2.1)
Confirmed Root Cause : Always-block NBA override on BVALID — asserting
                       assignment overwritten
Severity             : Handshake violation — AXI compliance failure
Transactions Affected: Protocol-visible failures: 2
────────────────────────────────────────────────────────────────
```

With full causal proof:

```
SCHEDULING CONFLICT  [PROOF]
  Cycle 1312: BVALID has 2 simultaneously active drivers
  with conflicting values.

DRIVER CANCELLATION  [PROOF]
  Asserting  (D2): if ((ARESETn) && (write_state == RESP)) → BVALID = 1
  Overwriting (D3): if ((...) && (BREADY)) → BVALID = 0
  → BVALID=1 is overwritten by the more-specific override
    before handshake completes.

ROOT CAUSE
  AWREADY is controlled only by local FSM state
  and ignores required AXI channel coordination.
  AWREADY logic never checks: BVALID, BREADY
```

### Clean design — `axil_adapter` (PASS)

```
────────────────────────────────────────────────────────────────
WaveEye Result
────────────────────────────────────────────────────────────────
Status              : PASS
Protocol compliance : Verified
Structural integrity: Verified
Confidence          : 99%
No defects detected.
────────────────────────────────────────────────────────────────
```

---

## Validated Test Cases

WaveEye has been validated on 7 designs with **zero false positives** on clean waveforms. Full terminal output for each run is in [`test_results/`](test_results/).

| Example | Design | Violations | Result | Confirmed Root Cause | Time |
|---------|--------|-----------|--------|---------------------|------|
| `bvalibug` | axi_lite_fifo_wrapper.sv | 40 | AXI4L_WRITE_RESPONSE_MISSING | Intra-cycle NBA override: BVALID=1 overwritten by more-specific driver [PROOF] | 18.6s |
| `arreay_bug` | axi_lite_fifo_wrapper.sv | 1 | AXI4L_RVALID_UNPROMPTED | FSM_OUTPUT_MASKED on ARREADY — broader condition overwrites state-specific value | 10.5s |
| `axi_lite_slave_v1_0` | axi_lite_slave_v1_0.v | 1 | AXI4L_RDATA_STABILITY | s_axi_rdata driver has no RVALID/RREADY gate — payload advances during backpressure | 1.7s |
| `axil_adapter` | Alex Forencich axil_adapter | 0 | **PASS — 0 false positives** | No protocol violations on clean design | 30.2s |
| `axil_ram` | Alex Forencich axil_ram | 56 | AXI4L_WRITE_RESPONSE_MISSING | Always-block NBA override on RVALID — asserting assignment overwritten | 1.5s |
| `axil_dp_ram` | Alex Forencich axil_dp_ram | 100 | AXI4L_BVALID_PERSISTENCE | Always-block NBA override on BVALID — asserting assignment overwritten | 24.2s |
| `exec_order_bug` | exec_order_wr_fsm.sv | 1 | AXI4L_WRITE_RESPONSE_MISSING | w_state reaches W_IDLE via flush without completing AXI handshake — missing WVALID/BVALID/BREADY guard | 1.3s |

`axil_adapter`, `axil_ram`, and `axil_dp_ram` use the open-source [Alex Forencich verilog-axi](https://github.com/alexforencich/verilog-axi) reference designs. The clean run (`axil_adapter`) confirmed zero false positives.

---

## Detection Capabilities

### Protocol Layer — 15 AXI4-Lite Rules

- VALID persistence violations (WVALID / AWVALID / ARVALID dropped before handshake)
- Response missing or unprompted (BVALID / RVALID not issued correctly)
- Ready-Valid coupling violations
- Overlapping outstanding transactions

### Structural Datapath Layer

- Width truncation / extension without semantic mapping
- Non-invertible transforms (constant injection, signal duplication)
- Byte-lane collapse and write aliasing
- Address monotonicity violations

### Temporal / FSM Layer

- Stuck signals and FSM illegal states
- Inter-FSM dependency violations
- Cyclic enable dependencies (deadlock)

### Verdict Hierarchy

```
TRANSPORT  >  DATAPATH  >  PROTOCOL  >  INCONCLUSIVE
```

When a structural defect is proven to have caused protocol violations, it is reported as **DATAPATH** — symptom and root cause are reported separately.

---

## How It Works

```
RTL (.sv/.v)  +  Waveform (.vcd)
        │
  ┌─────▼──────────────────────────────────┐
  │  Stage 1: Preprocessing                │
  │  VCD → signal value table (every cycle)│
  │  Signal alias resolution               │
  │  Clock domain estimation               │
  └─────┬──────────────────────────────────┘
        │
  ┌─────▼──────────────────────────────────┐
  │  Stage 2: IR Build                     │
  │  Parse RTL → intermediate records      │
  │  Extract true signal drivers           │
  │  Build FSM encoding maps               │
  └─────┬──────────────────────────────────┘
        │
  ┌─────▼──────────────────────────────────┐
  │  Stage 3: Protocol Checking            │
  │  15 AXI4-Lite handshake rules          │
  │  Signal grouping + violation detection │
  └─────┬──────────────────────────────────┘
        │
  ┌─────▼──────────────────────────────────┐
  │  Stage 4: Root Cause Analysis          │
  │  Causal graph construction             │
  │  Predicate backtracking                │
  │  Driver conflict detection             │
  │  Scheduling proof generation           │
  └─────┬──────────────────────────────────┘
        │
  ┌─────▼──────────────────────────────────┐
  │  Stage 5: Report                       │
  │  diagnosis.txt — primary verdict       │
  │  rca_analysis.txt — full causal report │
  │  proof.appendix.txt — evidence chain   │
  │  proof.json — machine-readable output  │
  └────────────────────────────────────────┘
```

---

## What Makes WaveEye Different

**Traditional debug flow:**
```
Simulation fails → Open waveform viewer → Manually trace signals →
Spend hours guessing → Maybe find the bug → No proof it's the root cause
```

**WaveEye flow:**
```
Simulation fails → Run WaveEye → Read diagnosis.txt → Root cause with proof
```

WaveEye doesn't just flag violations — it proves *why* they happen by:

1. **Backtracking through the RTL** — traces from the violation signal through every driver and condition to find the origin, with exact RTL line numbers
2. **Evaluating predicates against waveform data** — checks what every condition actually evaluated to at the failing cycle
3. **Detecting scheduling conflicts** — finds cases where multiple drivers fight over the same signal in the same cycle
4. **Proving driver cancellation** — shows when a correct assignment gets overwritten by a more-specific NBA condition
5. **Identifying missing dependencies** — finds required protocol signals that the FSM logic never checks

---

## Project Structure

```
WaveEye/
├── main.py                          # Entry point
├── Preprocessing/                   # Stage 1: VCD → structured data
│   ├── cli.py                       # Preprocessing orchestrator
│   ├── vcd/                         # VCD parsing, clock detection
│   ├── rtl/                         # Signal classification
│   └── mapping/                     # Signal-to-value mapping
├── IR_backtracking/                 # Stage 2–5: Analysis + RCA
│   ├── cli.py                       # Analysis orchestrator
│   ├── ir_builder.py                # RTL → intermediate representation
│   ├── true_drivers.py              # True driver extraction
│   ├── axil4.py                     # AXI4-Lite protocol checker (15 rules)
│   ├── rca_8.py                     # RCA engine orchestrator
│   ├── fsm_illegal_state.py         # FSM violation detection
│   ├── inter_fsm.py                 # Cross-FSM dependency checks
│   ├── rca_core/                    # Causal graph + analysis engine
│   ├── semantic_checks/             # Transport, memory, invertibility
│   ├── protocols/                   # Protocol adapters
│   └── reports/                     # Report generators
├── examples/                        # 7 validated test cases
│   ├── arreay_bug/
│   ├── axi_lite_slave_v1_0/
│   ├── axil_adapter/
│   ├── axil_dp_ram/
│   ├── axil_ram/
│   ├── bvalibug/
│   └── exec_order_bug/
└── test_results/                    # Full terminal outputs from each test
```

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

If you're a verification engineer and WaveEye catches (or misses) something on your design, I'd love to hear about it.

**Ways to contribute:**
- Try it on your own failing testbenches and file issues
- Add protocol adapters for new bus standards
- Improve the causal graph visualization
- Add more semantic check patterns

---

## Roadmap

- [ ] Multi-module causal graph (cross-module signal tracing)
- [ ] AXI4-Full protocol support
- [ ] CI/CD integration (run WaveEye on every regression failure)
- [ ] Interactive HTML causal graph explorer
- [ ] LLM-powered natural language debug explanations

---

## Author

**Meenal Gada**
- GitHub: [@meenalgada142](https://github.com/meenalgada142)
- Email: meenalgada142@gmail.com

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

---

*WaveEye — Trace every signal to its source.*
