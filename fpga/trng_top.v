// PROTOTYPE: This FPGA TRNG design has not been silicon-validated or NIST SP 800-90B assessed.
// Treat as a reference sketch. Entropy output quality must be measured before production use.

/*
 * trng_top.v — TRNG top-level with memory-mapped register interface
 * Hydrogenuine / Project DOCS
 * MIT License
 *
 * Wraps trng_core.v and exposes a simple 32-bit MMIO interface.
 * Compatible with both direct RISC-V MMIO and AXI4-Lite.
 * Clock domain crossing: clk_sys (RISC-V system clock) reads from the
 * FIFO that is written by clk_s (TRNG sampling clock).
 *
 * Register map (byte addresses from TRNG_BASE):
 *   0x00  TRNG_DATA    [31:0]  RO  Read one 32-bit word (auto-drain)
 *   0x04  TRNG_STATUS  [2:0]   RO  bit0=READY, bit1=BIST_PASS, bit2=DEAD
 *   0x08  TRNG_FILL    [7:0]   RO  FIFO fill count in words
 *   0x0C  TRNG_CTRL    [2:0]   RW  bit0=ENABLE, bit1=BIST_START, bit2=FLUSH
 *
 * Clock domain crossing strategy:
 *   - data_valid and fill_count are sampled in clk_sys domain via 2-FF sync.
 *   - data_rd pulse is generated in clk_sys but clk_s samples it via a
 *     handshake (set/clear flip-flops). Simple because reads are infrequent.
 *   - trng_dead is a sticky flag; synchronised to clk_sys via 2-FF.
 */

module trng_top (
    /* System (RISC-V) clock domain */
    input  wire        clk_sys,
    input  wire        rst_n,
    /* MMIO interface (word-addressed) */
    input  wire [1:0]  reg_addr,    /* 2-bit word address (0x00/0x04/0x08/0x0C) */
    input  wire        reg_wr,      /* 1 = write cycle */
    input  wire        reg_rd,      /* 1 = read cycle */
    input  wire [31:0] reg_wdata,
    output reg  [31:0] reg_rdata,
    /* TRNG sampling clock (async — use ECP5 OSCi or PLL output) */
    input  wire        clk_s
);

/* ── Control register ──────────────────────────────────────────── */
reg trng_enable;
reg do_flush;

always @(posedge clk_sys or negedge rst_n) begin
    if (!rst_n) begin
        trng_enable <= 1'b0;
        do_flush    <= 1'b0;
    end else if (reg_wr && reg_addr == 2'b11) begin
        trng_enable <= reg_wdata[0];
        do_flush    <= reg_wdata[2];
    end else begin
        do_flush <= 1'b0; /* Auto-clear flush pulse */
    end
end

/* ── TRNG core instance ────────────────────────────────────────── */
wire [31:0] trng_data;
wire        trng_valid;
wire        trng_dead_raw;
wire [7:0]  trng_fill;

/* data_rd handshake: pulse in clk_sys, sampled in clk_s */
reg  rd_req;       /* set in clk_sys on MMIO read of TRNG_DATA */
reg  rd_ack_s;     /* set in clk_s when consumed */
reg  rd_ack_sys1, rd_ack_sys2; /* synchronise ack back */
wire rd_pulse_s;   /* rd_req edge detected in clk_s */

/* clk_s: detect rd_req rising edge */
reg rd_req_s1, rd_req_s2;
always @(posedge clk_s or negedge rst_n) begin
    if (!rst_n) begin
        rd_req_s1 <= 0; rd_req_s2 <= 0; rd_ack_s <= 0;
    end else begin
        rd_req_s1 <= rd_req;
        rd_req_s2 <= rd_req_s1;
        if (rd_req_s1 & !rd_req_s2) rd_ack_s <= 1; /* rising edge */
        else                          rd_ack_s <= 0;
    end
end
assign rd_pulse_s = rd_ack_s;

/* clk_sys: generate rd_req on MMIO data read, clear on ack */
always @(posedge clk_sys or negedge rst_n) begin
    if (!rst_n) begin
        rd_req <= 0; rd_ack_sys1 <= 0; rd_ack_sys2 <= 0;
    end else begin
        rd_ack_sys1 <= rd_ack_s;
        rd_ack_sys2 <= rd_ack_sys1;
        if (reg_rd && reg_addr == 2'b00 && trng_valid_sys)
            rd_req <= 1;
        else if (rd_ack_sys2)
            rd_req <= 0;
    end
end

trng_core #(.FIFO_DEPTH(16)) core_inst (
    .clk_s      (clk_s),
    .rst_n      (rst_n),
    .enable     (trng_enable),
    .data_out   (trng_data),
    .data_valid (trng_valid),
    .data_rd    (rd_pulse_s),
    .trng_dead  (trng_dead_raw),
    .fill_count (trng_fill)
);

/* ── Synchronise status signals to clk_sys ─────────────────────── */
reg valid_s1, valid_s2;        /* trng_valid -> clk_sys */
reg dead_s1,  dead_s2;         /* trng_dead  -> clk_sys */
reg [7:0] fill_s1, fill_s2;   /* trng_fill  -> clk_sys */

wire trng_valid_sys = valid_s2;
wire trng_dead_sys  = dead_s2;
wire [7:0] trng_fill_sys = fill_s2;

always @(posedge clk_sys or negedge rst_n) begin
    if (!rst_n) begin
        valid_s1 <= 0; valid_s2 <= 0;
        dead_s1  <= 0; dead_s2  <= 0;
        fill_s1  <= 0; fill_s2  <= 0;
    end else begin
        valid_s1 <= trng_valid; valid_s2 <= valid_s1;
        dead_s1  <= trng_dead_raw; dead_s2  <= dead_s1;
        fill_s1  <= trng_fill;  fill_s2  <= fill_s1;
    end
end

/* Latch data word at the moment of read request (before handshake completes) */
reg [31:0] data_latch;
always @(posedge clk_sys) begin
    if (reg_rd && reg_addr == 2'b00 && trng_valid_sys)
        data_latch <= trng_data;
end

/* ── MMIO read mux ─────────────────────────────────────────────── */
always @(*) begin
    case (reg_addr)
    2'b00: reg_rdata = data_latch;                              /* TRNG_DATA   */
    2'b01: reg_rdata = {29'h0,
                        trng_dead_sys,                          /* bit2: DEAD  */
                        1'b1,                                   /* bit1: BIST_PASS (stub) */
                        trng_valid_sys};                        /* bit0: READY */
    2'b10: reg_rdata = {24'h0, trng_fill_sys};                  /* TRNG_FILL   */
    2'b11: reg_rdata = {29'h0, do_flush, 1'b0, trng_enable};   /* TRNG_CTRL   */
    endcase
end

endmodule
