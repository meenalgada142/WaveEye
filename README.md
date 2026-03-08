# WaveEye — AXI-Lite Protocol Root Cause Analyzer

WaveEye is a deterministic RTL root cause analysis (RCA) tool for AXI4-Lite protocol bugs.
It takes a SystemVerilog/Verilog design and a simulation waveform (VCD), and produces a structured diagnosis: **what failed, why it failed, and exactly where in the RTL to fix it.**

No formal verification tools. No test modifications. Runs fully offline from a single executable.

---

## Download

Get the latest release from the [**Releases page**](https://github.com/meenalgada142/WaveEye/releases):

| Platform | File |
|----------|------|
| Windows 64-bit | `WaveEye-windows.exe` |
| Linux x86\_64 | `WaveEye-linux-x64` |

---

## Quick Start

### Windows

Download `WaveEye-windows.exe` and run it:

```
WaveEye-windows.exe
```

### Linux

Download `WaveEye-linux-x64`, make it executable, and run:

```bash
chmod +x WaveEye-linux-x64
./WaveEye-linux-x64
```

No Python installation required on either platform.

---

## Input Format

Point WaveEye at a folder with two subfolders:

```
my_design/
├── rtl/       ← .sv / .v source files
└── wave/      ← simulation waveform (.vcd)
```

Example inputs are in the [`examples/`](examples/) directory — ready to run.

---

## Usage

WaveEye runs an interactive menu. Follow these steps:

```
Enter choice (1-3): 1                                  ← Automated Mode
Enter path to input folder: /path/to/my_design
Select RTL (<num>, all, quit): all
Select mode (1/2/3): 2                                 ← AXI4-Lite protocol RCA
```

### Output Files

All outputs are written to `~/WaveEye/outputs/userN/analysis/`:

| File | Contents |
|------|----------|
| **`*.diagnosis.txt`** | **Your main result — start here** |
| `*.fix_guidance.txt` | RTL fix recommendations |
| `*.backtracking_trace.txt` | Causal trace from symptom to root cause |
| `*.proof.appendix.txt` | Full analysis report |
| `*.proof.json` | Machine-readable root cause verdict |

> **`diagnosis.txt` is your final output summary.** It contains the primary failure, confirmed root cause, severity, and affected transactions.

---

## What It Detects

**Protocol layer — 15 AXI4-Lite rules:**

- VALID persistence violations (WVALID / AWVALID / ARVALID dropped before handshake)
- Response missing or unprompted (BVALID / RVALID not issued correctly)
- Ready–Valid coupling violations
- Overlapping outstanding transactions

**Structural datapath layer:**

- Width truncation / extension without semantic mapping
- Non-invertible transforms (constant injection, signal duplication)
- Byte-lane collapse and write aliasing
- Address monotonicity violations

**Temporal / FSM layer:**

- Stuck signals and FSM illegal states
- Inter-FSM dependency violations
- Cyclic enable dependencies (deadlock)

**Verdict hierarchy:**

```
TRANSPORT  >  DATAPATH  >  PROTOCOL  >  INCONCLUSIVE
```

When a structural defect is proven to have caused protocol violations, it is reported as DATAPATH — symptom and root cause are reported separately.

---

## Validated Test Cases

WaveEye has been validated on 6 designs with **zero false positives** on clean waveforms.
Full diagnosis output for each is in [`test_results/`](test_results/).

| Example | Design | Bug Introduced | Violations | Result | Root Cause | Time |
|---------|--------|----------------|------------|--------|------------|------|
| `bvalibug` | `axi_lite_fifo_wrapper.sv` | BVALID scheduling conflict | 40 | `AXI4L_WRITE_RESPONSE_MISSING` | Always-block NBA override on BVALID | 3.6 s |
| `arreay_bug` | `axi_lite_fifo_wrapper.sv` | RVALID asserted without AR handshake | 1 | `AXI4L_RVALID_UNPROMPTED` | RVALID driver predicate missing ARVALID/ARREADY | 1.8 s |
| `axi_lite_slave_v1_0` | `axi_lite_slave_v1_0.v` | RDATA mutated during RVALID window | 1 | `AXI4L_RDATA_STABILITY` | RDATA driver has no RREADY gate | 0.2 s |
| `axil_adapter` | [Alex Forencich axil\_adapter](https://github.com/alexforencich/verilog-axi) | None — clean baseline | 0 | **0 false positives** — no protocol violations on clean design | Structural pattern detected (data replication in adapter — intentional) | 36 s |
| `axil_ram` | [Alex Forencich axil\_ram](https://github.com/alexforencich/verilog-axi) | NBA override cancels BVALID | 56 | `AXI4L_WRITE_RESPONSE_MISSING` | NBA override on BVALID + WRITE\_ALIASING/LANE\_BIJECTION on `mem` | 0.3 s |
| `axil_dp_ram` | [Alex Forencich axil\_dp\_ram](https://github.com/alexforencich/verilog-axi) | NBA override drops BVALID before BREADY | 100 | `AXI4L_BVALID_PERSISTENCE` | NBA override on RDATA + WRITE\_ALIASING/LANE\_BIJECTION on `mem` | 3.5 s |

> The last three test cases use the open-source [Alex Forencich verilog-axi](https://github.com/alexforencich/verilog-axi) reference designs — production-quality RTL. Each design was tested both clean (no bugs) and with bugs deliberately introduced by us. The clean runs confirmed **zero false positives** on protocol rules. The bug-introduced runs (`axil_ram`, `axil_dp_ram`) were correctly detected.

### Sample `diagnosis.txt` — Bug detected (bvalibug)

```
────────────────────────────────────────────────────────────────
WaveEye Diagnostic Summary
────────────────────────────────────────────────────────────────
Primary Failure      : AXI4L_WRITE_RESPONSE_MISSING  (AXI4-Lite Spec §A3.2.1)
Confirmed Root Cause : Always-block NBA override on BVALID — asserting assignment overwritten
Severity             : Handshake violation — AXI compliance failure
Transactions Affected: Protocol-visible failures: 2
────────────────────────────────────────────────────────────────
```

### Sample `diagnosis.txt` — No bugs (axil\_adapter, PASS)

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

## License

MIT License — see [LICENSE](LICENSE).

The core analysis engine is proprietary and distributed as compiled binaries only.
