// ============================================================
// TEST DESIGN 2 — exec_order_wr_fsm.sv
// ============================================================
// Planted bug:  EXECUTION_ORDER
//
//   Single always_ff block has TWO NBA assignment groups that
//   both target w_state:
//
//     Group 1 (case):  W_ACTIVE → if (beat==7) w_state <= W_RESP;
//     Group 2 (if):    if (flush) w_state <= W_IDLE;
//
//   When beat==7 AND flush==1 simultaneously:
//     NBA schedule:  W_RESP  then  W_IDLE  (source order)
//     After delta:   W_IDLE wins (last write)
//     W_RESP & W_DONE are silently skipped — write response
//     never reaches the bus.
// ============================================================

module exec_order_wr_fsm (
    input  wire        clk,
    input  wire        rst_n,

    // Simplified AXI write signals
    input  wire        awvalid,
    output reg         awready,
    input  wire [31:0] wdata,
    input  wire        wvalid,
    output reg         wready,
    output reg         bvalid,
    input  wire        bready,

    // System flush — held high by error-recovery logic
    input  wire        flush,

    output reg         write_ok
);

    // ── FSM encoding ─────────────────────────────────
    typedef enum logic [2:0] {
        W_IDLE   = 3'd0,
        W_ADDR   = 3'd1,
        W_DATA   = 3'd2,
        W_ACTIVE = 3'd3,
        W_RESP   = 3'd4,
        W_DONE   = 3'd5
    } w_state_t;

    w_state_t w_state;

    reg [3:0] beat_count;

    // ==================================================
    // FSM — single always_ff — BUG is here
    // ==================================================
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            w_state    <= W_IDLE;
            beat_count <= 4'd0;
            awready    <= 1'b0;
            wready     <= 1'b0;
            bvalid     <= 1'b0;
            write_ok   <= 1'b0;
        end else begin

            // ── Group 1: case transitions ────────────
            case (w_state)
                W_IDLE: begin
                    awready  <= 1'b1;
                    bvalid   <= 1'b0;
                    write_ok <= 1'b0;
                    if (awvalid && awready) begin
                        w_state <= W_ADDR;
                        awready <= 1'b0;
                    end
                end

                W_ADDR: begin
                    wready  <= 1'b1;
                    w_state <= W_DATA;
                end

                W_DATA: begin
                    if (wvalid && wready) begin
                        w_state    <= W_ACTIVE;
                        wready     <= 1'b0;
                        beat_count <= 4'd0;
                    end
                end

                W_ACTIVE: begin
                    beat_count <= beat_count + 4'd1;
                    if (beat_count == 4'd7)
                        w_state <= W_RESP;          // ◄─ NBA #1
                end

                W_RESP: begin
                    bvalid <= 1'b1;
                    if (bready) begin
                        bvalid  <= 1'b0;
                        w_state <= W_DONE;
                    end
                end

                W_DONE: begin
                    write_ok <= 1'b1;
                    w_state  <= W_IDLE;
                end

                default: w_state <= W_IDLE;
            endcase

            // ── Group 2: flush override (BUG) ───────
            // Source-order is AFTER the case, so NBA #2
            // overwrites any assignment from Group 1.
            if (flush)
                w_state <= W_IDLE;                  // ◄─ NBA #2  (WINS)

        end
    end

endmodule
