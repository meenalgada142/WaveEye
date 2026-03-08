//============================================================
// Top-Level DUT Module
// Wraps an AXI-Lite FIFO interface and exposes fifo_level
//============================================================
module dut (
    //=======================
    // AXI-Lite Global Signals
    //=======================
    input  wire         ACLK,       // AXI clock
    input  wire         ARESETn,    // Active-low AXI reset

    //=======================
    // AXI-Lite Write Address Channel
    //=======================
    input  wire [31:0]  AWADDR,     // Write address
    input  wire         AWVALID,    // Write address valid
    output wire         AWREADY,    // Write address ready

    //=======================
    // AXI-Lite Write Data Channel
    //=======================
    input  wire [31:0]  WDATA,      // Write data
    input  wire         WVALID,     // Write data valid
    output wire         WREADY,     // Write data ready

    //=======================
    // AXI-Lite Write Response Channel
    //=======================
    output wire [1:0]   BRESP,      // Write response (OKAY, SLVERR, etc.)
    output wire         BVALID,     // Write response valid
    input  wire         BREADY,     // Write response ready

    //=======================
    // AXI-Lite Read Address Channel
    //=======================
    input  wire [31:0]  ARADDR,     // Read address
    input  wire         ARVALID,    // Read address valid
    output wire         ARREADY,    // Read address ready

    //=======================
    // AXI-Lite Read Data Channel
    //=======================
    output wire [31:0]  RDATA,      // Read data
    output wire [1:0]   RRESP,      // Read response (OKAY, SLVERR, etc.)
    output wire         RVALID,     // Read data valid
    input  wire         RREADY,     // Read data ready

    //=======================
    // FIFO Status Output
    //=======================
    output wire [4:0]   fifo_level  // Exposed FIFO occupancy level
);

    //============================================================
    // AXI-Lite FIFO Wrapper Instantiation
    // Connects all AXI-Lite channels and exposes fifo_level
    //============================================================
    axi_lite_fifo_wrapper #(
        .DATA_WIDTH(8),     // FIFO data width
        .DEPTH(16)          // FIFO depth (entries)
    ) u_axi_fifo (
        // Global signals
        .ACLK      (ACLK),
        .ARESETn   (ARESETn),

        // Write address channel
        .AWADDR    (AWADDR),
        .AWVALID   (AWVALID),
        .AWREADY   (AWREADY),

        // Write data channel
        .WDATA     (WDATA),
        .WVALID    (WVALID),
        .WREADY    (WREADY),

        // Write response channel
        .BRESP     (BRESP),
        .BVALID    (BVALID),
        .BREADY    (BREADY),

        // Read address channel
        .ARADDR    (ARADDR),
        .ARVALID   (ARVALID),
        .ARREADY   (ARREADY),

        // Read data channel
        .RDATA     (RDATA),
        .RRESP     (RRESP),
        .RVALID    (RVALID),
        .RREADY    (RREADY),

        // FIFO status output
        .fifo_level(fifo_level)  //Connected cleanly to top-level output
    );

endmodule
