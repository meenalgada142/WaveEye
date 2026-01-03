# WaveEye

**Automated RTL signal backtracking and root cause analysis for hardware verification.**

WaveEye traces every signal in your design back to its RTL drivers, captures the conditions that control each assignment, and explains why signals behave the way they do using waveform data and Verilog scheduling semantics.
Unlike traditional waveform viewers or linters, WaveEye reasons about RTL execution using Verilog scheduling semantics to explain *why* a signal value won.

---

## Quick Start

### Install
```bash
git clone https://github.com/meenalgada142/WaveEye.git
cd WaveEye
pip install pandas pyslang
```

### Run
1. Place your RTL files (`.sv`, `.v`) and VCD waveform in `Preprocessing/user_input/`
2. Run the pipeline:
   ```bash
   python main.py
   ```
3. View results in `outputs/userXX/analysis/`

---

## What You Get

WaveEye automatically generates:

| File | Description |
|------|-------------|
| `*_backtracking.csv` | Every signal mapped to its RTL drivers with conditions |
| `*_true_drivers.csv` | Behavioral drivers (filtered from reset/defaults) |
| `*_edges.csv` | Signal transition timing |
| `*_stuck_signals.csv` | Signals that don't toggle when expected |

Plus **interactive root cause analysis** that explains NBA races, overwrites, and condition conflicts.

---

## Example: Finding an NBA Race

**Your RTL:**
```systemverilog
always_ff @(posedge clk) begin
  if (state == RESP)           tx_done <= 1'b1;
  if (state == RESP && BREADY) tx_done <= 1'b0;
end
```

**WaveEye finds:**
```csv
signal,condition,rhs,assign_type,always_block_id
tx_done,state == RESP,1'b1,nonblocking,42
tx_done,state == RESP && BREADY,1'b0,nonblocking,42
```

**Interactive analysis explains:**
```
[BUG] EXECUTION_ORDER_BUG

Signal: tx_done
Block: 42

Both drivers fire when state==RESP && BREADY==1:
  Driver 0: Schedules tx_done <= 1
  Driver 1: Schedules tx_done <= 0 (WINS - last assignment)

Result: tx_done becomes 0 (Driver 0's update is lost)

ROOT CAUSE: Conditions overlap. Both can be TRUE simultaneously.
The last assignment wins per Verilog NBA scheduling rules.
```

---

## How It Works

### 1. VCD Preprocessing
Converts waveforms to structured CSV with automatic signal classification (clocks, resets, FSMs).

### 2. Signal Backtracking
Parses your RTL and extracts:
- **All signal drivers** with their conditions
- **Assignment types** (blocking vs. non-blocking)
- **Always block IDs** for execution analysis
- **Complete condition expressions** for overlap detection

### 3. Root Cause Analysis
Evaluates driver conditions against waveform data to:
- Detect when multiple drivers fire in the same cycle
- Analyze execution order using Verilog NBA rules
- Identify condition overlaps and races
- Explain unexpected signal behavior

---

## Key Features

✅ **Automated backtracking** - Trace any signal to its RTL drivers  
✅ **Condition capture** - See exactly when each driver fires  
✅ **NBA race detection** - Find overwrites and scheduling conflicts  
✅ **Cross-block analysis** - Detect unsafe multi-block drivers  
✅ **Interactive debugging** - Select signals for detailed root cause explanations  

---

## Use Cases

- **Debug failing assertions** - Understand why signals don't match expected values
- **Find race conditions** - Detect NBA conflicts before they cause problems
- **Trace signal origins** - See all drivers and their firing conditions
- **Learn hardware debugging** - Visualize RTL execution cycle-by-cycle

---

## Architecture

```
WaveEye/
├── main.py                    # Pipeline orchestrator (MIT)
├── Preprocessing/             # VCD → CSV conversion (MIT)
└── IR_backtracking/
    └── ir_engine.exe          # IR backtracking + root cause reasoning engine (proprietary)
```

---

## License

WaveEye is dual-licensed to balance openness with intellectual property protection:

### Open Source Components (MIT License)

The following components are released under the **MIT License**:

- **Pipeline orchestrator** (`main.py`)
- **Preprocessing module** (`Preprocessing/`)
  - VCD parsing and conversion
  - Signal classification
  - Waveform structuring

You are free to:
- ✅ Use, modify, and distribute these components
- ✅ Use commercially without restrictions
- ✅ Create derivative works

See [LICENSE](LICENSE) for full MIT license text.

### Proprietary Components

The **IR Analysis Engine** (`IR_backtracking/ir_engine.exe`) is proprietary software:

- **Distributed as**: Pre-compiled binary only
- **Source code**: Not publicly available
- **Usage rights**: Free for evaluation and non-commercial use
- **Commercial use**: Requires separate licensing


The analysis engine contains:
- IR builder and RTL parser
- Signal backtracking algorithms
- Root cause reasoning engine
- Interactive analysis interface

See [IR_backtracking/README.md](IR_backtracking/README.md) for detailed terms.

### Commercial Licensing

For commercial use of the analysis engine, contact:

**Meenal Gada**  
Email: meenalgada142@gmail.com  
GitHub: [@meenalgada142](https://github.com/meenalgada142)

---

## Requirements

- Python 3.7+
- pandas
- pyslang

---

## Contributing

Contributions to the **open source components** (MIT licensed) are welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes to `main.py` or `Preprocessing/`
4. Submit a pull request

**Note:** The analysis engine (`ir_engine.exe`) is proprietary and not open for contributions.

---

## Contact

**Meenal Gada**  
GitHub: [@meenalgada142](https://github.com/meenalgada142)  
Email: your-email@example.com

For questions or collaboration: Open an issue or reach out via email.

---

**WaveEye** - Trace every signal to its source.

*Copyright © 2025 Meenal Gada. Pipeline components released under MIT License. Analysis engine is proprietary software.*
