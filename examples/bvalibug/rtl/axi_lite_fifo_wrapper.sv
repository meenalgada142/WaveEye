module axi_lite_fifo_wrapper #(
    parameter DATA_WIDTH = 8,
    parameter DEPTH      = 16
)(
    //=======================
    // AXI-Lite Global Signals
    //=======================
    input  wire                  ACLK,
    input  wire                  ARESETn,

    //=======================
    // AXI-Lite Write Address Channel
    input  wire [31:0]           AWADDR,
    input  wire                  AWVALID,
    output reg                   AWREADY,

    //=======================
    // AXI-Lite Write Data Channel
    input  wire [31:0]           WDATA,
    input  wire                  WVALID,
    output reg                   WREADY,

    //=======================
    // AXI-Lite Write Response Channel
    output reg [1:0]             BRESP,
    output reg                   BVALID,
    input  wire                  BREADY,

    //=======================
    // AXI-Lite Read Address Channel
    input  wire [31:0]           ARADDR,
    input  wire                  ARVALID,
    output reg                   ARREADY,

    //=======================
    // AXI-Lite Read Data Channel
    output reg [31:0]            RDATA,
    output reg [1:0]             RRESP,
    output reg                   RVALID,
    input  wire                  RREADY,

    //=======================
    // FIFO Status Output
    output wire [4:0]            fifo_level
);

    //============================================================
    // Dummy usage to silence Verilator warnings
    //============================================================
    wire unused_awaddr_bits = |AWADDR[31:4];
    wire unused_wdata_bits  = |WDATA[31:8];
    wire unused_araddr_bits = |ARADDR[31:4];

    //============================================================
    // Internal control signals
    //============================================================
    reg wr_en, rd_en;
    wire [DATA_WIDTH-1:0] dout;
    wire full, empty;
    wire [4:0] count;

    //============================================================
    // FIFO Instantiation
    //============================================================
    fifo #(.DATA_WIDTH(DATA_WIDTH), .DEPTH(DEPTH)) u_fifo (
        .clk   (ACLK),
        .rst   (~ARESETn),
        .wr_en (wr_en),
        .rd_en (rd_en),
        .din   (WDATA[DATA_WIDTH-1:0]),
        .dout  (dout),
        .full  (full),
        .empty (empty),
        .count (count)
    );

    assign fifo_level = count;

    //============================================================
    // FSM State Encoding
    //============================================================
    reg [1:0] write_state, read_state;
    localparam IDLE = 2'b00, RESP = 2'b01;

    //============================================================
    // AXI-Lite Write FSM
    //============================================================
    always @(posedge ACLK) begin
        if (!ARESETn) begin
            AWREADY     <= 0;
            WREADY      <= 0;
            BVALID      <= 0;
            BRESP       <= 2'b00;
            wr_en       <= 0;
            write_state <= IDLE;
        end else begin  
            wr_en <= 0;

            case (write_state)
                IDLE: begin
                  

                    if (AWVALID && WVALID) begin
                        // $display("[WRITE FSM] AWVALID && WVALID = %b at time %t", AWVALID && WVALID, $time);
                    AWREADY <= 1;
                    WREADY  <= 1;
                        if (AWADDR[3:0] == 4'h0 && !full) begin
                            // $display("[WRITE FSM] AWADDR = %h, full = %b", AWADDR, full);

                            wr_en  <= 1;
                            BRESP  <= 2'b00;  // OKAY
                        end else begin
                            BRESP  <= 2'b10;  // SLVERR
                        end
                        write_state <= RESP;
                    end
                    else begin
                    AWREADY <= 0;
                    WREADY  <= 0;
                    end
                end

                RESP: begin
                    AWREADY <= 0;
                    WREADY  <= 0;
                    BVALID  <= 1;

                    // $display("[WRITE FSM] BVALID asserted at time %t,BVALID = ", $time,BVALID);

                    if (BREADY) begin
                        BVALID      <= 0;
                        // $display("[WRITE FSM] BVALID asserted at time %t,BVALID = ", $time,BVALID); 
                        write_state <= IDLE;
                    end
                end

                default: begin
                    AWREADY     <= 0;
                    WREADY      <= 0;
                    BVALID      <= 0;
                    BRESP       <= 2'b10;
                    wr_en       <= 0;
                    write_state <= IDLE;
                end
            endcase
        end
    end

    //============================================================
    // AXI-Lite Read FSM
    //============================================================
    always @(posedge ACLK) begin
        if (!ARESETn) begin
            ARREADY    <= 0;
            RVALID     <= 0;
            RDATA      <= 0;
            RRESP      <= 2'b00;
            rd_en      <= 0;
            read_state <= IDLE;
        end else begin
            rd_en <= 0;

            case (read_state)
                IDLE: begin
                    if (ARVALID) begin
                        ARREADY <= 1;
                        read_state <= RESP;
                        case (ARADDR[7:0])
                            8'h10: begin
                                if (!empty) begin
                                    rd_en  <= 1;
                                    RDATA  <= {24'b0, dout};
                                    RRESP  <= 2'b00;
                                end else begin
                                    RDATA  <= 32'hDEAD_BEEF;
                                    RRESP  <= 2'b10;
                                end
                            end

                            8'h20: begin
                                RDATA <= {25'b0, count, full, empty};
                                RRESP <= 2'b00;
                            end

                            8'h80: begin
                                RDATA <= {27'b0, fifo_level};
                                RRESP <= 2'b00;
                            end

                            default: begin
                                RDATA <= 32'hBAD0BAD0;
                                RRESP <= 2'b11;
                            end
                        endcase

                        
                    end
                end

                RESP: begin
                    ARREADY <= 0;
                    RVALID  <= 1;

                    if (RREADY) begin
                        RVALID     <= 0;
                        read_state <= IDLE;
                    end
                end

                default: begin
                    ARREADY    <= 0;
                    RVALID     <= 0;
                    RDATA      <= 32'hBAD0BAD0;
                    RRESP      <= 2'b11;
                    rd_en      <= 0;
                    read_state <= IDLE;
                end
            endcase
        end
    end

endmodule
