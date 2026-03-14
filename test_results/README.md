# WaveEye — Validated Test Results

All 7 test cases were run using the WaveEye AXI4-Lite Protocol Analyzer (Automated Mode, AXI4-Lite RCA).
Full terminal output for each run is in the corresponding subfolder.

## Results Table

| Example | RTL File(s) | Protocol Violations | Primary Violation | Confirmed Root Cause | Time |
|---------|-------------|--------------------|--------------------|----------------------|------|
| [`bvalibug`](bvalibug/terminal_output.txt) | `axi_lite_fifo_wrapper.sv` | 40 | `AXI4L_WRITE_RESPONSE_MISSING` | Intra-cycle NBA override: BVALID=1 overwritten by more-specific driver (D3) in same cycle — scheduling conflict proven `[PROOF]` | 18.6 s |
| [`arreay_bug`](arreay_bug/terminal_output.txt) | `axi_lite_fifo_wrapper.sv` | 1 | `AXI4L_RVALID_UNPROMPTED` | FSM_OUTPUT_MASKED on ARREADY — broader condition overwrites state-specific assignment; RVALID fires before AR handshake | 10.5 s |
| [`axi_lite_slave_v1_0`](axi_lite_slave_v1_0/terminal_output.txt) | `axi_lite_slave_v1_0.v` | 1 | `AXI4L_RDATA_STABILITY` | `s_axi_rdata` driver condition is `if (true)` — no RVALID/RREADY gate; payload advances freely during backpressure | 1.7 s |
| [`axil_adapter`](axil_adapter/terminal_output.txt) | `axil_adapter.v` / `axil_adapter_wr.v` | **0** | **PASS** | No protocol violations — MASK_CONSERVATION structural defect on `m_axil_wdata_next` is a datapath finding, not a handshake violation | 30.2 s |
| [`axil_ram`](axil_ram/terminal_output.txt) | `axil_ram.v` | 56 | `AXI4L_WRITE_RESPONSE_MISSING` | Always-block NBA override on RVALID — asserting assignment overwritten; 4 violation types detected | 1.5 s |
| [`axil_dp_ram`](axil_dp_ram/terminal_output.txt) | `axil_dp_ram.v` | 100 | `AXI4L_BVALID_PERSISTENCE` | Always-block NBA override on BVALID — asserting assignment overwritten; 4 violation types detected | 24.2 s |
| [`exec_order_bug`](exec_order_bug/terminal_output.txt) | `exec_order_wr_fsm.sv` | 1 | `AXI4L_WRITE_RESPONSE_MISSING` | `w_state` reached W_IDLE via `flush` signal without completing AXI handshake — missing WVALID/BVALID/BREADY dependencies; secondary RESET_VIOLATION | 1.3 s |

## Notes

- **`axil_adapter`** uses the open-source [Alex Forencich verilog-axi](https://github.com/alexforencich/verilog-axi) reference design and is a clean run confirming **zero false positives** on protocol rules.
- **`axil_ram`** and **`axil_dp_ram`** are also from the Alex Forencich library with bugs deliberately introduced; both are correctly detected.
- **`bvalibug`** demonstrates the scheduling conflict proof path: two simultaneous drivers on BVALID with conflicting values are identified and reported with `[PROOF]` tags.
- **`exec_order_bug`** demonstrates execution-order root cause: a `flush` input drives the FSM to W_IDLE before the AXI handshake is complete, so bvalid is never issued.
