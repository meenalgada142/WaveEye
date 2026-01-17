# WaveEye

**Automated RTL signal backtracking and root-cause analysis** for hardware verification.

🎯 **Most tools tell you *what* failed. WaveEye tells you *why*.**

Traditional RTL debug tools stop at detection:
- "Multiple drivers found"
- "Race condition possible"  
- "Signal conflict detected"

**WaveEye goes further:**
- Identifies exactly which drivers conflicted
- Explains **why** they conflicted (subset logic, timing overlap, FSM semantics)
- Shows how Verilog scheduling actually resolved it (NBA ordering, execution order)
- Points to what needs to change in the RTL

---

## What WaveEye Reasons About (Not Just Flags)

### Structural Bugs
- Cross-always-block races
- Mixed blocking / non-blocking assignments

### FSM Semantic Bugs
- FSM output masking (state-specific logic overwritten)

### Execution-Order Bugs
- Superset condition overwrites specific logic
- Sequential assignment masking (NBA source-order effects)

### Verification Gaps
- Conditions that never fire (runtime coverage holes)

---

## Download

Download the standalone executable from [GitHub Releases](https://github.com/meenalgada142/WaveEye/releases):

```
👉 Releases → WaveEye v0.1.0 → WaveEye.exe
```

---

## Quick Start

### 1. Prepare Your Input Directory

**IMPORTANT:** Organize your files with this exact structure:
```
my_project/           ← Input folder
├── rtl/              ← RTL files folder (required)
│   ├── design.sv
│   ├── submodule.sv
│   └── ...
└── wave/             ← Waveform files folder (required)
    ├── simulation.vcd
    ├── (or .csv files)
    └── ...
```

The input folder **must contain** two subdirectories named exactly:
- **`rtl/`** - containing your RTL design files (.sv, .v)
- **`wave/`** - containing your waveform files (.vcd, .csv)

### 2. Run WaveEye

Double-click `WaveEye.exe` or run from command line:
```bash
WaveEye.exe
```

### 3. Follow the Interactive Prompts

**Step 1: Select Analysis Mode**
```
WAVEEYE ANALYSIS PIPELINE

Stage 1: Preprocessing (VCD → CSV)
Stage 2: IR Backtracking & Root Cause Analysis

Options:
  1. Automated Mode
  2. Interactive Mode
  3. Exit

Enter choice (1-3):
```

- **Automated Mode**: Runs full analysis pipeline and displays results
- **Interactive Mode**: Enables multiple analysis sessions with detailed signal-level inspection

**Step 2: Provide Input Path**
```
Enter path to input folder (contains rtl/ and wave/):
> ./my_project

[Processing...]
✓ Preprocessing complete
✓ IR analysis complete
```

### 4. Review Results in Terminal

WaveEye displays analysis results directly in the terminal, allowing you to:
- Review findings immediately
- Run multiple interactive analysis sessions
- Query different signals or conditions

Each issue is shown with:
- **Human-readable explanations**, not cryptic warnings
- The **exact conditions and drivers** involved
- The **Verilog execution semantics** that caused the behavior
- A **clear root cause** and an **actionable fix**

---

## Validation: Real-World Testing

### Production FPGA Libraries
Tested on **68 signals** from Alex Forencich's widely-used FPGA libraries:
- UART RX/TX (24 signals) - Serial protocol FSMs
- Ethernet GMII RX (44 signals) - Complex receive path with CRC

**Results:**
- ✅ **0 false positives** - all correctly identified as intentional design
- ✅ Successfully detected injected bugs (cross-block races)
- ✅ Clear root cause explanations for every finding

### Internal Testing on Real RTL Projects

**1. Mini SoC Peripheral Subsystem**
- **Components tested:** 5+ RTL files
  - Interrupt controller
  - Register file
  - UART TX
  - Timer
  - SoC peripheral top
- **Test cases:** 3+ scenarios covering multiple modules
- **Result:** ✅ Successfully identified and explained all injected bugs

**2. AXI-Lite Interface with FIFO Wrapper**
- **Bug detected:** Non-blocking assignment race causing testbench assertion failure
- **Root cause:** Scheduling conflict where `bvalid` and `bready` were asserted simultaneously due to NBA ordering
- **Result:** ✅ WaveEye identified the exact NBA race condition and explained the Verilog scheduling semantics that caused the conflict

*Most verification tools have 50-80% false positive rates. Engineers ignore warnings they don't trust.*

---

## What Makes WaveEye Different

WaveEye performs **deterministic reasoning** over RTL and waveforms — the same way a verification engineer reasons — but automated.

It runs as a downloadable executable, so your **RTL, testbenches, and proprietary IP never leave your machine**.

**From hours of waveform digging → minutes of reasoning.**

---

## Architecture

```
WaveEye.exe
├── Stage 1: Preprocessing (VCD → CSV)
├── Stage 2: IR Backtracking & Root Cause Analysis
└── Interactive terminal interface
```

WaveEye is a single executable that handles the complete analysis pipeline with interactive terminal output.

---

## Troubleshooting

### "Cannot find rtl/ or wave/ folder"
- Ensure your input folder contains exactly two subdirectories: `rtl/` and `wave/`
- Folder names are case-sensitive on some systems
- Check the structure:
  ```
  my_project/
  ├── rtl/      ← Must be named exactly "rtl"
  └── wave/     ← Must be named exactly "wave"
  ```

### "No RTL files found"
- Ensure `.sv` or `.v` files exist in the `rtl/` folder
- Check file permissions

### "Waveform format not supported"
- Currently supports: `.vcd`, `.csv`
- Ensure waveform files are in the `wave/` folder

### "WaveEye.exe won't launch"
- Windows Defender may block unsigned executables
- Right-click → Properties → Unblock
- Or add an exception for WaveEye.exe

---

## Example Directory Structures

### ✅ CORRECT Structure:
```
verification_project/
├── rtl/
│   ├── cpu.sv
│   ├── alu.sv
│   └── register_file.sv
└── wave/
    └── simulation.vcd

Command: WaveEye.exe
Input: ./verification_project
```

### ❌ INCORRECT Structures:

**Missing subdirectories:**
```
verification_project/
├── cpu.sv           ← RTL files directly in root
├── alu.sv
└── simulation.vcd   ← Wave file directly in root
```

**Wrong folder names:**
```
verification_project/
├── RTL/             ← Wrong (capital letters)
└── waveforms/       ← Wrong (should be "wave")
```

---

## Licensing

WaveEye is distributed as a proprietary binary.

- **Free for evaluation and research use**
- Commercial use requires a license
- Source code is not publicly available at this stage

---

## Contact

**Meenal Gada**  
GitHub: [https://github.com/meenalgada142](https://github.com/meenalgada142)  
Email: meenalgada142@gmail.com

For licensing, feedback, or collaboration, reach out directly.

---

**WaveEye** — *Trace every signal to its source.*

*If you care about understanding RTL behavior — not just spotting warnings — this is for you.*
