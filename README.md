# WaveEye — AXI-Lite Protocol Root Cause Analyzer

WaveEye is a deterministic RTL root cause analysis (RCA) tool for AXI4-Lite protocol bugs.
It takes a SystemVerilog/Verilog design and a simulation waveform (VCD), and produces a
structured diagnosis: **what failed, why it failed, and exactly where in the RTL to fix it.**

No formal verification tools. No test modifications. Runs fully offline from a single executable.

---

## Download

Get the latest release from the [Releases page](https://github.com/meenalgada142/WaveEye/releases):

| Platform | File |
|---|---|
| Windows (64-bit) | `waveeye-windows.zip` |
| Linux (x86_64) | `waveeye-linux.zip` |

---

## Quick Start

### Windows

1. Download and extract `waveeye-windows.zip`
2. Run from a terminal:

```
waveeye.exe
```

### Linux

1. Download and extract `waveeye-linux.zip`
2. Run from a terminal:

```bash
chmod +x waveeye-linux/waveeye
./waveeye-linux/waveeye
```

No Python installation required on either platform.

### Input format

Point WaveEye at a folder containing two subfolders:

```
my_design/
├── rtl/       ← .sv / .v source files
└── wave/      ← simulation waveform (.vcd)
```

Example inputs are provided in the [`examples/`](examples/) directory.

---

## Usage

WaveEye uses an interactive menu:

```
Options:
  1. Automated Mode     ← recommended
  2. Interactive Mode
  3. Exit
```

**Automated mode walkthrough:**

```
Enter choice (1-3): 1
Enter path to input folder (contains rtl/ and wave/): /path/to/my_design
Select RTL (<num>, all, quit): all
Select mode (1/2/3): 2        ← AXI4-Lite protocol RCA
```

### Output files

All outputs are written to `~/WaveEye/outputs/userN/analysis/`:

| File | Contents |
|---|---|
| **`*.diagnosis.txt`** | **Final output summary — start here** |
| `*.fix_guidance.txt` | RTL fix recommendations |
| `*.backtracking_trace.txt` | Causal trace from symptom to root cause |
| `*.proof.appendix.txt` | Full analysis report |
| `*.proof.json` | Machine-readable root cause verdict |

> **The `diagnosis.txt` file is your main result.** It contains the primary failure,
> confirmed root cause, severity, and affected transactions in a concise summary.

---

## What It Detects

**Protocol layer (15 AXI4-Lite rules):**
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

### Verdict hierarchy

```
TRANSPORT  >  DATAPATH  >  PROTOCOL  >  INCONCLUSIVE
```

When a structural defect is proven to have caused protocol violations, it is reported as
DATAPATH — the symptom and the root cause are reported separately.

---

## Validated Test Cases

WaveEye has been validated on 6 designs with **zero false positives** on clean waveforms.
Full diagnosis output for each is in [`test_results/`](test_results/).

| Example | Design | Bug | Violations | Result | Time |
|---|---|---|---|---|---|
| `bvalibug` | `axi_lite_fifo_wrapper.sv` | BVALID scheduling conflict | 40 | `AXI4L_WRITE_RESPONSE_MISSING` | 3.6 s |
| `arreay_bug` | `axi_lite_fifo_wrapper.sv` | RVALID asserted without AR handshake | 1 | `AXI4L_RVALID_UNPROMPTED` | 1.8 s |
| `axi_lite_slave_v1_0` | `axi_lite_slave_v1_0.v` | RDATA mutated during RVALID window | 1 | `AXI4L_RDATA_STABILITY` | 0.2 s |
| `axil_adapter` | [Alex Forencich axil_adapter](https://github.com/alexforencich/verilog-axi) | No bugs introduced (baseline) | 0 | **PASS** | 8.9 s |
| `axil_ram` | [Alex Forencich axil_ram](https://github.com/alexforencich/verilog-axi) | Bug introduced: NBA override cancels BVALID | 56 | `AXI4L_WRITE_RESPONSE_MISSING` | 0.3 s |
| `axil_dp_ram` | [Alex Forencich axil_dp_ram](https://github.com/alexforencich/verilog-axi) | Bug introduced: BVALID dropped before BREADY | 100 | `AXI4L_BVALID_PERSISTENCE` | 3.5 s |

> The last three test cases use the open-source [Alex Forencich verilog-axi](https://github.com/alexforencich/verilog-axi)
> reference designs. These are production-quality designs — bugs were deliberately introduced by us
> to validate WaveEye's detection capability.

### Sample `diagnosis.txt` output (bvalibug)

```
────────────────────────────────────────────────────────────────
WaveEye Diagnostic Summary
────────────────────────────────────────────────────────────────
Primary Failure    : AXI4L_WRITE_RESPONSE_MISSING  (AXI4-Lite Spec §A3.2.1)
Confirmed Root Cause : Always-block NBA override on BVALID — asserting assignment overwritten
Severity           : Handshake violation — AXI compliance failure
Transactions Affected : Protocol-visible failures: 2
────────────────────────────────────────────────────────────────
```

### Sample `diagnosis.txt` output (axil_adapter — clean design, PASS)

```
────────────────────────────────────────────────────────────────
WaveEye Result
────────────────────────────────────────────────────────────────
Status                : PASS
Protocol compliance   : Verified
Structural integrity  : Verified
Confidence            : 99%
No defects detected.
────────────────────────────────────────────────────────────────
```

---

## License

MIT License — see [LICENSE](LICENSE).

The core analysis engine is proprietary and distributed as compiled binaries only.
