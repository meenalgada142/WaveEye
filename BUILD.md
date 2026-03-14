# Building WaveEye Executables

This document explains how to build the standalone WaveEye executables for Windows and Linux from source.

## Prerequisites

Both builds require:

- Python 3.10 or later
- All runtime dependencies installed:

```bash
pip install -r requirements.txt
pip install pyinstaller
```

> **pyslang note:** Install the correct wheel for your platform from [pypi.org/project/pyslang](https://pypi.org/project/pyslang/).

---

## Windows Build

Run from the project root in **Command Prompt** (not PowerShell):

```bat
build_windows.bat
```

Output:
```
standalone/WaveEye-windows/waveeye.exe   ← launch this
standalone/WaveEye-windows.zip           ← distributable archive
```

---

## Linux Build

Run from the project root in a **bash shell** (native Linux or WSL):

```bash
bash build_linux.sh
```

Output:
```
standalone/WaveEye-linux/waveeye    ← launch this
standalone/WaveEye-linux.zip        ← distributable archive
```

> **WSL note:** Build the Linux binary inside WSL — do not use the Windows Python to produce a Linux binary. The two builds must be run separately on their respective platforms.

---

## What Gets Bundled

The spec file (`waveeye.spec`) packages:

| Component | Description |
|-----------|-------------|
| `main.py` | Pipeline entry point |
| `Preprocessing/` | VCD→CSV pipeline, RTL classifier, signal mapper |
| `IR_backtracking/` | Protocol rules, RCA engine, FSM analysis, reports |
| `vcdvcd`, `pandas`, `pyslang` | Third-party runtime libraries |

Build artifacts (`.pyc`, `__pycache__`, `.pyd`, the `build/` work directory) are excluded from the repo by `.gitignore`.

---

## Running the Built Executable

### Windows
```
standalone\WaveEye-windows\waveeye.exe
```

### Linux
```bash
./standalone/WaveEye-linux/waveeye
```

The tool is fully interactive — no command-line flags needed.

---

## Distributing

Upload `WaveEye-windows.zip` and `WaveEye-linux.zip` to the [GitHub Releases page](https://github.com/meenalgada142/WaveEye/releases) as release assets.
