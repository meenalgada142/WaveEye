`timescale 1 ns / 1 ps
/* ----------------------------------------- *
 * Title       : Custom AXI Lite Slave v1    *
 * Project     : AXI Lite Slave              *
 * ----------------------------------------- *
 * File        : axi_lite_slave_v1_0.v       *
 * Author      : Yigit Suoglu                *
 * Last Edit   : 18/10/2021                  *
 * Licence     : CERN-OHL-W                  *
 * ----------------------------------------- *
 * Description : AXI Lite slave interface    *
 * ----------------------------------------- *
 * Revisions                                 *
 *     v1      : Inital version              *
 * ----------------------------------------- */

  module axi_lite_slave_v1_0 #
  (
    //Parameters of GP Interface
    parameter GP_ADDR_WIDTH = 6,

    //Parameters of Axi Slave Bus Interface
    parameter integer C_S_AXI_DATA_WIDTH  = 32,
    parameter integer C_S_AXI_ADDR_WIDTH  = 4
  )
  (
    //GP Interface
    //Write Channel
    output write, //New write request
    output [GP_ADDR_WIDTH-1:0] write_addrs, //Address to write
    output [C_S_AXI_DATA_WIDTH-1:0] write_data, //Data to write
    input write_error, //Indicate an error to master
    input write_done, //Indicate to finish write next cycle (ready signal in AXI)
    output [(C_S_AXI_DATA_WIDTH/8)-1 : 0] write_strobe,
    //Read Channel
    output read, //New read request
    output [GP_ADDR_WIDTH-1:0] read_addrs, //Address to read
    input [C_S_AXI_DATA_WIDTH-1:0] read_data, //Read data
    input read_error, //Indicate an error to master
    input read_done, //Indicate to read_data is valid


    //Ports of Axi Slave Bus Interface S_AXI
    input wire  s_axi_aclk,
    input wire  s_axi_aresetn,
    input wire [C_S_AXI_ADDR_WIDTH-1 : 0] s_axi_awaddr,
    input wire [2 : 0] s_axi_awprot, //Not implemented
    input wire  s_axi_awvalid,
    output wire  s_axi_awready,
    input wire [C_S_AXI_DATA_WIDTH-1 : 0] s_axi_wdata,
    input wire [(C_S_AXI_DATA_WIDTH/8)-1 : 0] s_axi_wstrb,
    input wire  s_axi_wvalid,
    output wire  s_axi_wready,
    output wire [1 : 0] s_axi_bresp,
    output wire  s_axi_bvalid,
    input wire  s_axi_bready,
    input wire [C_S_AXI_ADDR_WIDTH-1 : 0] s_axi_araddr,
    input wire [2 : 0] s_axi_arprot,  //Not implemented
    input wire  s_axi_arvalid,
    output wire  s_axi_arready,
    output wire [C_S_AXI_DATA_WIDTH-1 : 0] s_axi_rdata,
    output wire [1 : 0] s_axi_rresp,
    output wire  s_axi_rvalid,
    input wire  s_axi_rready
  );
    localparam ADDR_MASK = {GP_ADDR_WIDTH{1'b1}};
    localparam RES_OKAY = 2'b00,
               RES_ERR  = 2'b10; //Slave error
    //Capture valid Data & Address
    reg got_write_data, got_write_addrs, got_read_addrs;
    always@(posedge s_axi_aclk) begin
      if(~s_axi_aresetn) begin
        got_write_data <= 1'b0;
      end else case(got_write_data)
        1'b0: got_write_data <= s_axi_wvalid & ~(write_done & write);
        1'b1: got_write_data <= ~write_done;
      endcase
    end
    always@(posedge s_axi_aclk) begin
      if(~s_axi_aresetn) begin
        got_write_addrs <= 1'b0;
      end else case(got_write_addrs)
        1'b0: got_write_addrs <= s_axi_awvalid & ~(write_done & write);
        1'b1: got_write_addrs <= ~write_done;
      endcase
    end
    always@(posedge s_axi_aclk) begin
      if(~s_axi_aresetn) begin
        got_read_addrs <= 1'b0;
      end else case(got_read_addrs)
        1'b0: got_read_addrs <= s_axi_arvalid & ~read_done;
        1'b1: got_read_addrs <= ~read_done;
      endcase
    end

    //Ready when we don't already have data/addrs
    assign s_axi_arready = ~got_read_addrs  & ~hold_read_resp;
    assign s_axi_awready = ~got_write_addrs & ~hold_write_resp;
    assign s_axi_wready  = ~got_write_data  & ~hold_write_resp;

    //Store addresses and write data
    reg [GP_ADDR_WIDTH-1:0] write_addrs_hold, read_addrs_hold;
    reg [C_S_AXI_DATA_WIDTH-1:0] write_data_hold;
    reg [(C_S_AXI_DATA_WIDTH/8)-1 : 0] write_strobe_hold;

    always@(posedge s_axi_aclk) begin
      write_addrs_hold <= (got_write_addrs) ? write_addrs_hold : s_axi_awaddr & ADDR_MASK;
      read_addrs_hold  <= (got_read_addrs)  ?  read_addrs_hold : s_axi_araddr & ADDR_MASK;
      write_strobe_hold <= (got_write_data) ? write_strobe_hold : s_axi_wstrb;
      write_data_hold   <= (got_write_data) ? write_data_hold   : s_axi_wdata;
    end

    assign write_addrs  = (got_write_addrs) ? write_addrs_hold : s_axi_awaddr & ADDR_MASK;
    assign read_addrs   = (got_read_addrs)  ?  read_addrs_hold : s_axi_araddr & ADDR_MASK;
    assign write_strobe = (got_write_data) ? write_strobe_hold : s_axi_wstrb;
    assign write_data   = (got_write_data) ? write_data_hold   : s_axi_wdata;

    //Store & hold responses
    reg hold_read_resp, hold_write_resp;
    always@(posedge s_axi_aclk) begin
      if(~s_axi_aresetn) begin
        hold_write_resp <= 1'b0;
      end else case(hold_write_resp)
        1'b0: hold_write_resp <= write & write_done & ~s_axi_bready;
        1'b1: hold_write_resp <= ~s_axi_bready;
      endcase
    end
    always@(posedge s_axi_aclk) begin
      if(~s_axi_aresetn) begin
        hold_read_resp <= 1'b0;
      end else case(hold_read_resp)
        1'b0: hold_read_resp <= read & read_done & ~s_axi_rready;
        1'b1: hold_read_resp <= ~s_axi_rready;
      endcase
    end

    assign s_axi_rvalid = (read & read_done)   | hold_read_resp;
    assign s_axi_bvalid = (write & write_done) | hold_write_resp;


    reg s_axi_bresp_hold, s_axi_rresp_hold;
    reg [C_S_AXI_DATA_WIDTH-1:0] s_axi_rdata_hold;
    always@(posedge s_axi_aclk) begin
      s_axi_bresp_hold <= (hold_write_resp) ? s_axi_bresp_hold : write_error;
      s_axi_rresp_hold <= (hold_read_resp)  ? s_axi_rresp_hold : read_error;
      s_axi_rdata_hold <= (hold_read_resp)  ? s_axi_rdata_hold : read_data;
    end

    assign s_axi_rdata = (hold_read_resp)  ? s_axi_rdata_hold : read_data;
    assign s_axi_bresp[0] = 1'b0;
    assign s_axi_bresp[1] = (hold_write_resp) ? s_axi_bresp_hold : write_error;
    assign s_axi_rresp[0] = 1'b0;
    assign s_axi_rresp[1] = (hold_read_resp)  ? s_axi_rresp_hold : read_error;

    assign read = (got_read_addrs | s_axi_arvalid) & ~hold_read_resp;
    assign write = ((got_write_addrs | s_axi_awvalid) & (got_write_data | s_axi_wvalid)) & ~hold_write_resp;
  endmodule
