`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 08/30/2021 11:11:12 AM
// Design Name: 
// Module Name: tb
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module tb(

  );
  localparam GP_ADDR_WIDTH = 6;
  localparam C_S_AXI_DATA_WIDTH  = 32;
  localparam C_S_AXI_ADDR_WIDTH  = 4;
  reg[20*8:0] step = "init";
  
  // generate clock
  reg s_axi_aclk;
  always begin
      s_axi_aclk = 0;
      forever #5 s_axi_aclk = ~s_axi_aclk; // 10ns -> 100MHz
  end
  reg s_axi_aresetn;
  initial begin
    s_axi_aresetn = 1;
    #1
    s_axi_aresetn = 0;
    @(posedge s_axi_aclk); #1;
    s_axi_aresetn = 1;
  end
  
  // module ports:
  wire rstn;
  wire rst;
  wire write;
  wire[GP_ADDR_WIDTH-1:0] write_addrs;
  wire[C_S_AXI_DATA_WIDTH-1:0] write_data;
  reg write_error;
  reg write_done;
  wire[(C_S_AXI_DATA_WIDTH/8)-1:0] write_strobe;
  wire read;
  wire[GP_ADDR_WIDTH-1:0] read_addrs;
  reg [C_S_AXI_DATA_WIDTH-1:0] read_data;
  reg read_error;
  reg read_done;
  reg [C_S_AXI_ADDR_WIDTH-1:0] s_axi_awaddr;
  reg [2:0] s_axi_awprot = 0;
  reg s_axi_awvalid;
  wire s_axi_awready;
  reg [C_S_AXI_DATA_WIDTH-1:0] s_axi_wdata;
  reg [(C_S_AXI_DATA_WIDTH/8)-1:0] s_axi_wstrb;
  reg s_axi_wvalid;
  wire s_axi_wready;
  wire [1:0] s_axi_bresp;
  wire s_axi_bvalid;
  reg s_axi_bready;
  reg [C_S_AXI_ADDR_WIDTH-1:0] s_axi_araddr;
  reg [2:0] s_axi_arprot = 0;
  reg s_axi_arvalid;
  wire s_axi_arready;
  wire [C_S_AXI_DATA_WIDTH-1:0] s_axi_rdata;
  wire [1:0] s_axi_rresp;
  wire s_axi_rvalid;
  reg s_axi_rready;


  axi_lite_slave_v1_0 uut(
    .write(write),
    .write_addrs(write_addrs),
    .write_data(write_data),
    .write_error(write_error),
    .write_done(write_done),
    .write_strobe(write_strobe),
    .read(read),
    .read_addrs(read_addrs),
    .read_data(read_data),
    .read_error(read_error),
    .read_done(read_done),
    .s_axi_aclk(s_axi_aclk),
    .s_axi_aresetn(s_axi_aresetn),
    .s_axi_awaddr(s_axi_awaddr),
    .s_axi_awprot(s_axi_awprot),
    .s_axi_awvalid(s_axi_awvalid),
    .s_axi_awready(s_axi_awready),
    .s_axi_wdata(s_axi_wdata),
    .s_axi_wstrb(s_axi_wstrb),
    .s_axi_wvalid(s_axi_wvalid),
    .s_axi_wready(s_axi_wready),
    .s_axi_bresp(s_axi_bresp),
    .s_axi_bvalid(s_axi_bvalid),
    .s_axi_bready(s_axi_bready),
    .s_axi_araddr(s_axi_araddr),
    .s_axi_arprot(s_axi_arprot),
    .s_axi_arvalid(s_axi_arvalid),
    .s_axi_arready(s_axi_arready),
    .s_axi_rdata(s_axi_rdata),
    .s_axi_rresp(s_axi_rresp),
    .s_axi_rvalid(s_axi_rvalid),
    .s_axi_rready(s_axi_rready)
  );
  
  initial begin
    $dumpfile("sim.vcd");
    $dumpvars(0,tb);
  end

  initial begin
    step = "Init";
    write_error = 0;
    write_done = 0;
    read_data = 32'hBABA1195;
    s_axi_wdata = 32'h12345678;
    s_axi_awaddr = 32'h2204;
    read_error = 0;
    read_done = 0;
    s_axi_awvalid = 0;
    s_axi_wstrb = 4'hF;
    s_axi_wvalid = 0;
    s_axi_bready = 0;
    s_axi_araddr = 32'h1195;
    s_axi_arvalid = 0;
    s_axi_rready = 0;
    repeat(2) @(posedge s_axi_aclk); #1;
    step = "Both Ready";
    s_axi_bready = 1;
    s_axi_rready = 1;
    write_done = 1;
    read_done = 1;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 1;
    s_axi_arvalid = 1;
    s_axi_wvalid = 1;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 0;
    s_axi_arvalid = 0;
    s_axi_wvalid = 0;
    repeat(2) @(posedge s_axi_aclk); #1;
    step = "GP Waits 1 cycle";
    write_done = 0;
    read_done = 0;
    read_data = 32'hDEADBEEF;
    s_axi_wdata = 32'hDEADBEEF;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 1;
    s_axi_arvalid = 1;
    s_axi_wvalid = 1;
    @(posedge s_axi_aclk); #1;
    write_done = 1;
    read_done = 1;
    s_axi_awvalid = 0;
    s_axi_arvalid = 0;
    s_axi_wvalid = 0;
    repeat(2) @(posedge s_axi_aclk); #1;
    step = "GP Waits 2 cycles";
    write_done = 0;
    read_done = 0;
    read_data = 32'hE11E;
    s_axi_wdata = 32'hE11E;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 1;
    s_axi_arvalid = 1;
    s_axi_wvalid = 1;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 0;
    s_axi_arvalid = 0;
    s_axi_wvalid = 0;
    @(posedge s_axi_aclk); #1;
    write_done = 1;
    read_done = 1;
    repeat(2) @(posedge s_axi_aclk); #1;
    step = "AXI Waits 1 cycle";
    read_data = 32'h12345678;
    s_axi_wdata = 32'h12345678;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 1;
    s_axi_arvalid = 1;
    s_axi_wvalid = 1;
    s_axi_bready = 0;
    s_axi_rready = 0;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 0;
    s_axi_arvalid = 0;
    s_axi_wvalid = 0;
    s_axi_bready = 1;
    s_axi_rready = 1;
    repeat(2) @(posedge s_axi_aclk); #1;
    step = "AXI Waits 2 cycles";
    write_done = 1;
    read_done = 1;
    read_data = 32'h22041195;
    s_axi_wdata = 32'h22041195;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 1;
    s_axi_arvalid = 1;
    s_axi_wvalid = 1;
    s_axi_bready = 0;
    s_axi_rready = 0;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 0;
    s_axi_arvalid = 0;
    s_axi_wvalid = 0;
    @(posedge s_axi_aclk); #1;
    s_axi_bready = 1;
    s_axi_rready = 1;repeat(2) @(posedge s_axi_aclk); #1;
    step = "GP Waits Data ch";
    write_done = 0;
    read_done = 0;
    read_data = 32'h0;
    s_axi_wdata = 32'hE11E;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 1;
    s_axi_arvalid = 1;
    s_axi_wvalid = 1;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 0;
    s_axi_arvalid = 0;
    s_axi_wvalid = 0;
    s_axi_wdata = 32'h0;
    s_axi_araddr = 32'h0;
    @(posedge s_axi_aclk); #1;
    read_data = 32'hE11E;
    write_done = 1;
    read_done = 1;
    repeat(2) @(posedge s_axi_aclk); #1;
    step = "AXI Waits Data ch";
    write_done = 1;
    read_done = 1;
    read_data = 32'h22041195;
    s_axi_wdata = 32'h22041195;
    s_axi_araddr = 32'h3443;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 1;
    s_axi_arvalid = 1;
    s_axi_wvalid = 1;
    s_axi_bready = 0;
    s_axi_rready = 0;
    @(posedge s_axi_aclk); #1;
    s_axi_awvalid = 0;
    s_axi_arvalid = 0;
    s_axi_wvalid = 0;
    read_data = 32'h0;
    s_axi_wdata = 32'h0;
    s_axi_araddr = 32'h0;
    @(posedge s_axi_aclk); #1;
    s_axi_bready = 1;
    s_axi_rready = 1;
    repeat(5) @(posedge s_axi_aclk); #1;
    $finish;
  end
  
endmodule
