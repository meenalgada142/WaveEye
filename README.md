# WaveEye

**Automated RTL signal backtracking and root-cause analysis** for hardware verification.

WaveEye analyzes RTL designs using waveform data to explain **why** signals take specific values. It traces signals back to all RTL drivers, evaluates driver conditions cycle-by-cycle, and detects NBA races, overwrites, and stuck behavior using Verilog scheduling semantics.

**WaveEye is designed as a single-command tool** for verification engineers, with a proprietary analysis engine and open preprocessing pipeline.

---

## How WaveEye Is Distributed (Important)

WaveEye consists of **two parts**:

| Component | Location | License |
|-----------|----------|---------|
| **Open-source** preprocessing & orchestration | GitHub repo | MIT |
| **Proprietary** IR analysis engine | GitHub Releases (binary only) | Proprietary |

**You need both to run WaveEye.**

---

## Quick Start (Recommended)

### 1. Clone the Repository

```bash
git clone https://github.com/meenalgada142/WaveEye.git
cd WaveEye
```

This gives you:

main.py (single entry point)

Preprocessing/ (waveform preprocessing)
### 2. Download the IR Engine (Required)

Download from **GitHub Releases**:
> 👉 **Releases → WaveEye-v0.1-MVP → `ir_engine.exe`**

Place it **exactly here**:
```bash
WaveEye/
└── IR_backtracking/
    └── ir_engine.exe
```


⚠️ The engine is not included in the repository and must be downloaded separately.

### 3. Install Python dependencies
```bash
pip install pandas pyslang
```

Python 3.9+ is recommended.

### 4. Run WaveEye
```bash
python main.py
```
That’s it.

`main.py` will:

- Run preprocessing
- Invoke the IR engine automatically
- Generate analysis outputs

### Expected Inputs

Place your inputs before running main.py:

**RTL files:**
```bash
Preprocessing/user_input/
├── design.sv
└── submodule.sv
```
### Waveform

VCD or simulator-exported CSV

Also placed under Preprocessing/user_input/

### Outputs

Results are written to:
```bash
outputs/
└── userXX/
    ├── preprocessing/
    │   └── all_mapped_values.csv
    └── analysis/
        ├── *_backtracking.csv
        ├── *_true_drivers.csv
        ├── *_edges.csv
        ├── *_stuck_signals.csv
        └── *.json
```

You never need to edit these files manually.

## What WaveEye Detects

- Multiple RTL drivers per signal
- Non-blocking assignment races (NBA overwrites)
- Condition overlaps
- Reset masking issues
- Signals stuck high or low
- Post-reset non-activity
- Execution-order bugs within the same `always` block


### Architecture Overview
```bash
WaveEye/
├── main.py                    ← Single entry point
├── Preprocessing/             ← Open source (MIT)
│   └── cli.py
├── IR_backtracking/
│   └── ir_engine.exe          ← Proprietary (binary only)
└── outputs/
```

`main.py` automatically orchestrates everything.
Users never call `ir_engine.exe` directly.

## Licensing Model

### Open Source (MIT License)

The following components are released under the **MIT License**:

- `main.py`
- `Preprocessing/`
- Pipeline glue and orchestration logic

You are free to:

- Modify
- Redistribute
- Use commercially


### Proprietary Component

The **IR analysis engine**:

- `IR_backtracking/ir_engine.exe`
- Distributed as **binary only**
- Source code is **not public**
- Free for **evaluation and research use**
- **Commercial use requires a license**


## Why This Split Exists

This architecture allows:

- Fast iteration on preprocessing
- A stable, proprietary reasoning engine
- Clean separation of intellectual property
- Easy transition to a SaaS offering later

It also ensures users interact with **one unified tool**, not multiple standalone scripts.


## Troubleshooting

### `ir_engine.exe` not found

Make sure the following file exists and is executable:
```bash
WaveEye/IR_backtracking/ir_engine.exe
```

### No waveform found

Ensure preprocessing inputs exist:
```bash
Preprocessing/user_input/
```
### Engine fails after preprocessing

Do not rename or move:
```bash
outputs/<user>/preprocessing/all_mapped_values.csv
```

### Contact

**Meenal Gada**

**GitHub**: https://github.com/meenalgada142

**Email**: meenalgada142@gmail.com

For licensing, feedback, or collaboration, reach out directly.

WaveEye
Trace every signal to its source.
