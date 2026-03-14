# Contributing to WaveEye

Thank you for your interest in contributing to WaveEye!

## What You Can Contribute

This repository contains:
- **`examples/`** — RTL designs and waveforms used for testing
- **`test_results/`** — Terminal output and analysis artifacts from validated runs
- **Documentation** — README, this file, and related docs

The core analysis engine is closed-source (distributed as compiled binaries), so code contributions to the engine itself are not accepted here. Contributions to examples, test cases, and documentation are very welcome.

## How to Contribute

### Adding a New Test Case

1. Fork this repository and create a branch: `git checkout -b add-testcase-<name>`

2. Add your design under `examples/<name>/`:
   ```
   examples/<name>/
   ├── rtl/       ← .sv or .v source files
   └── wave/      ← simulation waveform (.vcd)
   ```

3. Run WaveEye on your design (Automated Mode, AXI4-Lite RCA) and capture the terminal output:
   ```bash
   ./WaveEye-linux-x64 > test_results/<name>/terminal_output.txt 2>&1
   ```

4. Add a row to `test_results/README.md` with the result.

5. Open a pull request with a short description of the design and what bug (if any) it demonstrates.

### Reporting Issues

If WaveEye produces an unexpected result (false positive, missed violation, crash), please open a GitHub Issue with:
- The example folder (or a minimal reproducer)
- The terminal output
- What you expected vs. what you got

### Documentation Improvements

Corrections, clarifications, and new examples in the README are welcome. Open a PR with your changes.

## Code of Conduct

Be respectful and constructive. Contributions that are off-topic, offensive, or attempt to reverse-engineer the proprietary engine components will not be accepted.

## License

By submitting a contribution, you agree that your contribution is licensed under the Apache 2.0 License (see [LICENSE](LICENSE)).
