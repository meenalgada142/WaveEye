## WaveEye v1.0.0 — AXI-Lite Protocol Root Cause Analyzer

Automated RTL debugging tool. Identifies **why** AXI4-Lite protocol violations occur and **where** in the RTL to fix them. No Python required.

---

### Download

| Platform | File |
|----------|------|
| Windows 64-bit | `WaveEye-windows.exe` |
| Linux x86_64 | `WaveEye-linux-x64` |

---

### Quick Start

**Windows** — run directly:

```
WaveEye-windows.exe
```

**Linux** — make executable and run:

```bash
chmod +x WaveEye-linux-x64
./WaveEye-linux-x64
```

When prompted:

1. Enter `1` — Automated Mode
2. Enter path to folder containing `rtl/` and `wave/` subfolders
3. Enter `all` — analyze all RTL files
4. Enter `2` — AXI4-Lite Protocol RCA

**Your result is in** `~/WaveEye/outputs/userN/analysis/diagnosis.txt`

---

### Validated On 6 Designs

| Design | Result | Violations | Confirmed Root Cause |
|--------|--------|------------|----------------------|
| `axi_lite_fifo_wrapper` (BVALID bug) | `AXI4L_WRITE_RESPONSE_MISSING` | 40 | Always-block NBA override on RDATA |
| `axi_lite_fifo_wrapper` (RVALID bug) | `AXI4L_RVALID_UNPROMPTED` | 1 | Always-block NBA override on RDATA |
| `axi_lite_slave_v1_0` | `AXI4L_RDATA_STABILITY` | 1 | RDATA driver has no RREADY gate |
| Alex Forencich `axil_adapter` — clean baseline | **0 false positives** | 0 | No protocol violations on clean design |
| Alex Forencich `axil_ram` — bug introduced | `AXI4L_WRITE_RESPONSE_MISSING` | 56 | Always-block NBA override on BVALID |
| Alex Forencich `axil_dp_ram` — bug introduced | `AXI4L_BVALID_PERSISTENCE` | 100 | Always-block NBA override on RDATA |

Example inputs are in the [examples/](https://github.com/meenalgada142/WaveEye/tree/main/examples) folder.

> The core analysis engine is proprietary and distributed as compiled binaries only.
