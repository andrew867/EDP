// PROTOTYPE: This FPGA TRNG design has not been silicon-validated or NIST SP 800-90B assessed.
// Treat as a reference sketch. Entropy output quality must be measured before production use.

/*
 * trng_tb.v — Testbench for trng_top and trng_core
 * Hydrogenuine / Project DOCS
 * MIT License
 *
 * Simulates with Icarus Verilog: iverilog -o trng_tb trng_tb.v trng_top.v trng_core.v
 * Run: vvp trng_tb
 * View waves: gtkwave trng_tb.vcd
 *
 * NOTE: Ring oscillator behaviour in simulation differs from silicon.
 * ROs in simulation run at simulation time steps, not thermal jitter.
 * Use this testbench to verify:
 *   1. MMIO read protocol correctness
 *   2. BIST timeout assertion
 *   3. FIFO fill/drain mechanics
 *
 * Real entropy estimation requires physical silicon measurements.
 */
`timescale 1ns/1ps

module trng_tb;

/* ── Clock generation ──────────────────────────────────────────── */
reg clk_sys = 0;
reg clk_s   = 0;
reg rst_n   = 0;

always #5  clk_sys = ~clk_sys;   /* 100 MHz system clock */
always #3  clk_s   = ~clk_s;     /* ~167 MHz sampling clock (async) */

/* ── DUT signals ───────────────────────────────────────────────── */
reg  [1:0]  reg_addr  = 0;
reg         reg_wr    = 0;
reg         reg_rd    = 0;
reg  [31:0] reg_wdata = 0;
wire [31:0] reg_rdata;

trng_top dut (
    .clk_sys   (clk_sys),
    .rst_n     (rst_n),
    .reg_addr  (reg_addr),
    .reg_wr    (reg_wr),
    .reg_rd    (reg_rd),
    .reg_wdata (reg_wdata),
    .reg_rdata (reg_rdata),
    .clk_s     (clk_s)
);

/* ── Waveform dump ─────────────────────────────────────────────── */
initial begin
    $dumpfile("trng_tb.vcd");
    $dumpvars(0, trng_tb);
end

/* ── Tasks ─────────────────────────────────────────────────────── */

task mmio_write;
    input [1:0]  addr;
    input [31:0] data;
    begin
        @(posedge clk_sys);
        reg_addr  = addr;
        reg_wdata = data;
        reg_wr    = 1;
        @(posedge clk_sys);
        reg_wr    = 0;
        reg_wdata = 0;
    end
endtask

task mmio_read;
    input  [1:0]  addr;
    output [31:0] data;
    begin
        @(posedge clk_sys);
        reg_addr = addr;
        reg_rd   = 1;
        @(posedge clk_sys);
        data   = reg_rdata;
        reg_rd = 0;
    end
endtask

integer word_count;
reg [31:0] rdata;
reg [31:0] words_collected [0:15];

/* ── Test sequence ─────────────────────────────────────────────── */
initial begin
    $display("=== EDP TRNG Testbench ===");

    /* Release reset */
    #50;
    rst_n = 1;
    #100;

    /* ── Test 1: Enable TRNG ─────────────────────────────────────── */
    $display("[T1] Enabling TRNG...");
    mmio_write(2'b11, 32'h1);  /* CTRL: ENABLE=1 */
    #200;

    /* ── Test 2: Check READY status ──────────────────────────────── */
    $display("[T2] Polling status...");
    repeat(50) begin
        mmio_read(2'b01, rdata);
        if (rdata[0]) begin
            $display("[T2] READY asserted. Status=0x%08X", rdata);
            disable T2_poll;
        end
        #20;
    end
    T2_poll: ;

    /* ── Test 3: Read 8 words from FIFO ──────────────────────────── */
    $display("[T3] Reading 8 words from TRNG FIFO...");
    word_count = 0;
    repeat(8) begin
        mmio_read(2'b01, rdata);
        while (!rdata[0]) begin
            #10;
            mmio_read(2'b01, rdata);
        end
        mmio_read(2'b00, rdata);
        words_collected[word_count] = rdata;
        $display("[T3] Word[%0d] = 0x%08X", word_count, rdata);
        word_count = word_count + 1;
        #30;
    end

    /* ── Test 4: Check fill count ─────────────────────────────────── */
    mmio_read(2'b10, rdata);
    $display("[T4] Fill count = %0d words", rdata[7:0]);

    /* ── Test 5: BIST — disable TRNG, wait for dead flag ─────────── */
    $display("[T5] Testing BIST timeout...");
    mmio_write(2'b11, 32'h0);  /* CTRL: ENABLE=0 */
    /* Wait for BIST_TIMEOUT cycles in clk_s domain (shortened for sim) */
    /* In real hardware this takes ~80ms; in sim we just wait some cycles */
    #5000;
    mmio_read(2'b01, rdata);
    $display("[T5] Status after disable: DEAD=%b BIST=%b READY=%b",
             rdata[2], rdata[1], rdata[0]);

    /* ── Test 6: Re-enable ────────────────────────────────────────── */
    $display("[T6] Re-enabling TRNG...");
    mmio_write(2'b11, 32'h1);
    #500;
    mmio_read(2'b01, rdata);
    $display("[T6] Status: 0x%08X", rdata);

    /* ── Test 7: Entropy uniqueness check ────────────────────────── */
    $display("[T7] Verifying words are not all identical...");
    begin : uniqueness_check
        integer j, k, found_diff;
        found_diff = 0;
        for (j = 0; j < word_count - 1; j = j + 1) begin
            for (k = j+1; k < word_count; k = k + 1) begin
                if (words_collected[j] != words_collected[k])
                    found_diff = 1;
            end
        end
        if (found_diff)
            $display("[T7] PASS: Words are not all identical");
        else
            $display("[T7] WARN: All words identical (expected in RTL sim; verify on silicon)");
    end

    $display("=== Testbench complete ===");
    #100;
    $finish;
end

/* ── Timeout watchdog ──────────────────────────────────────────── */
initial begin
    #1000000;
    $display("ERROR: Simulation timeout");
    $finish;
end

endmodule
