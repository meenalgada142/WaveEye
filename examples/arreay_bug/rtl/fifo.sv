module fifo #(parameter DATA_WIDTH = 8, parameter DEPTH = 16)(
    input  wire                   clk,
    input  wire                   rst,
    input  wire                   wr_en,
    input  wire                   rd_en,
    input  wire [DATA_WIDTH-1:0] din,
    output reg  [DATA_WIDTH-1:0] dout,
    output reg                   full,
    output reg                   empty,
    output wire [4:0]            count
);

    // Calculate pointer width based on DEPTH
    localparam PTR_WIDTH = $clog2(DEPTH);

    // FIFO memory and control signals
    reg [DATA_WIDTH-1:0] mem [0:DEPTH-1];      // FIFO storage array
    reg [PTR_WIDTH-1:0]  wr_ptr, rd_ptr;       // Write and read pointers
    reg [PTR_WIDTH:0]    count_internal;       // Tracks number of valid entries
    reg                  reset_sync;           // Synchronous reset flag for assertions

    // Output assignments
    assign count = count_internal;
    assign dout  = mem[rd_ptr];

    // Delay write enable to detect next-cycle effects
    reg wr_en_d;
    always @(posedge clk) begin
        wr_en_d <= wr_en;
    end

    // Assertion: FIFO became full in the cycle after a write
    always @(posedge clk) begin
        if (!reset_sync) begin
            if (wr_en_d && full) begin
                $error("FIFO became full in the cycle after write");
            end
        end
    end

    // Assertion: Underflow — read attempted when FIFO is empty
    always @(posedge clk) begin
        if (!reset_sync) begin
            if (rd_en && (count_internal == 0)) begin
                $error("FIFO underflow: read attempted when empty");
            end
        end
    end

    // Assertion: Defensive check — count must not exceed DEPTH
    always @(posedge clk) begin
        if (!reset_sync) begin
            if (count_internal > DEPTH) begin
                $error("FIFO count exceeded DEPTH");
            end
        end
    end

    // FIFO logic with asynchronous reset
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            // Reset all internal state
            wr_ptr        <= 0;
            rd_ptr        <= 0;
            count_internal <= 0;
            full          <= 0;
            empty         <= 1;
            reset_sync    <= 1;  // Enable assertion masking during reset
        end else begin
            reset_sync <= 0;     // Enable assertions after reset deasserts

            // Write operation: only if FIFO is not full
            if (wr_en && !full) begin
                mem[wr_ptr]     <= din;
                wr_ptr          <= wr_ptr + 1;
                count_internal  <= count_internal + 1;
            end

            // Read operation: only if FIFO is not empty
            if (rd_en && !empty) begin
                rd_ptr          <= rd_ptr + 1;
                count_internal  <= count_internal - 1;
            end

            // Update status flags
            full  <= (count_internal == DEPTH);
            empty <= (count_internal == 0);
        end
    end

endmodule
