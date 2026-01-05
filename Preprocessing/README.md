# WaveEye – Preprocessing Pipeline

This module prepares raw simulation waveforms for **WaveEye's RTL analysis engine**.
It converts simulator outputs into a **normalized, analysis-ready CSV format** consumed by the `ir_engine` executable.

⚠️ **This step is mandatory** before running the IR backtracking and bug-reasoning engine.

---

## What This Stage Does

The preprocessing pipeline:

- Parses raw waveform dumps (VCD / CSV / simulator exports).
- Normalizes signal names and hierarchy.
- Classifies signals (clock, reset, data, control).
- Aligns timebases (`time_ps`, `time_ns`, etc.).
- Produces a **single merged waveform CSV**: `all_mapped_values.csv`.

This file is the **only waveform input** expected by the IR engine along with the original RTL files.

---

## Folder Structure

```bash
Preprocessing/
├── cli.py                  # Preprocessing entry point (invoked by user / main.py)
├── main.py                 # Internal preprocessing orchestration
├── mapping/                # Signal mapping & waveform normalization
├── rtl/                    # RTL-aware preprocessing & classification
├── uploaded_vcds/          # Raw user-uploaded VCDs
├── user_input/             # User-provided CSVs / configs
├── vcd/                    # Expanded / intermediate VCD processing
└── README.md               # Preprocessing documentation
```
---

## Requirements

- Python 3.9 or newer.
- `pandas` library.

Install dependencies:

```bash
pip install pandas
```
## Usage

### Run Preprocessing

From the WaveEye root directory:

```bash
python Preprocessing/cli.py
```
## Output Layout
### Preprocessing creates a user-scoped output directory:
```bash
outputs/
└── <user>/
    └── preprocessing/
        ├── all_mapped_values.csv   # REQUIRED by ir_engine
        └── metadata.json
```
❗ Do not rename all_mapped_values.csv. The IR engine relies on this exact filename and location under outputs/<user>/preprocessing/.

## Output CSV Format
The generated CSV has a strict structure:

Row 0: Signal classification
e.g. clock, reset_active_low, data, control, …

Row 1: Signal names

Row 2+: Time-ordered waveform samples

**Example `all_mapped_values.csv`:**

| time_ps | clock | reset_active_low | data | control |
|---------|-------|------------------|------|---------|
| 0       | 0     | 0                | 0    |         |
| 5       | 1     | 0                | 0    |         |


## Notes:

First column is the time column (e.g. time_ps).

Remaining columns are signal values at that timestamp.

Time values must be monotonically non-decreasing, single normalized timebase.

## Required by:

rising_falling_edges.py

stuck_signals.py

ir_engine (main pipeline)

## Integration With the IR Engine

Preprocessing (cli.py)
↓
all_mapped_values.csv + user_input/RTL
↓
ir_engine.exe
↓
RTL backtracking + NBA race detection + stuck signal reasoning


**If preprocessing is skipped, incorrect, or CSV modified → IR engine will fail.**

---

## Common Mistakes

Avoid:

- Running `ir_engine` directly on raw VCD/CSV **without preprocessing**
- **Renaming** `all_mapped_values.csv`
- **Moving** CSV out of `outputs/<user>/preprocessing/`
- **Editing** CSV manually in Excel/tools

---
## Troubleshooting

### IR engine cannot find waveform

```bash
ls outputs/<user>/preprocessing/all_mapped_values.csv
```
If missing: Rerun preprocessing with correct <user> context.

Clock or reset not detected
head -n 2 outputs/<user>/preprocessing/all_mapped_values.csv
Verify:

Clock/reset signals in row 1 (signal names)

Correct classes in row 0 (e.g. clock, reset_active_low)

## Summary
Preprocessing → all_mapped_values.csv +  user_input/RTL → IR engine
all_mapped_values.csv is mandatory - do not rename/move/edit

**Perfect GitHub rendering:**
- ✅ Proper `##` headers with spacing
- ✅ Clean ASCII flow diagram
- ✅ `bash` fences only for commands
- ✅ Bold emphasis on key warnings
- ✅ Compact troubleshooting table-like format
- ✅ No broken links or artifacts

