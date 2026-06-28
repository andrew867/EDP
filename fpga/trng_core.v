// PROTOTYPE: This FPGA TRNG design has not been silicon-validated or NIST SP 800-90B assessed.
// Treat as a reference sketch. Entropy output quality must be measured before production use.

/*
 * trng_core.v — Ring-oscillator TRNG core for Lattice ECP5
 * Hydrogenuine / Project DOCS
 * MIT License
 *
 * Architecture: Two free-running ring oscillators (RO) of different chain
 * lengths (11 and 13 inverter stages). Their XOR is sampled by a third
 * independent sampling clock domain. The phase jitter between the two ROs
 * is the entropy source.
 *
 * Target: Lattice ECP5-25F with Yosys + nextpnr (Project Trellis)
 *
 * Synthesis notes:
 *   - Each inverter stage uses a LUT4 with KEEP constraint to prevent
 *     optimization. In Yosys: (* keep *) attribute on each LUT.
 *   - ROs must be placed in physically separated regions to reduce
 *     correlated noise. Add placement constraints in your .lpf file:
 *       LOCATE COMP "ro_a_chain[0]" SITE "R1C1D";
 *       LOCATE COMP "ro_b_chain[0]" SITE "R10C10D";
 *   - The sampling clock (clk_s) should be asynchronous to both RO
 *     clocks. Use ECP5's internal OSCi (128 MHz) as clk_s, or derive
 *     from a separate PLL output.
 *
 * BIST: The module monitors FIFO fill rate and asserts trng_dead if
 * no new entropy is produced for BIST_TIMEOUT clock cycles.
 *
 * Output interface: 32-bit words written to output FIFO.
 *   Upstream reads via the trng_top.v MMIO wrapper.
 */

/* Number of inverter stages per ring oscillator.
 * Must be odd. Prime lengths reduce correlation. */
`define RO_A_STAGES  11
`define RO_B_STAGES  13
`define BIST_TIMEOUT 32'h0800000  /* ~80ms at 100MHz */

module trng_core #(
    parameter FIFO_DEPTH = 16   /* 32-bit words; keep as power of 2 */
) (
    input  wire       clk_s,     /* sampling clock (async to ROs) */
    input  wire       rst_n,     /* active-low async reset */
    input  wire       enable,    /* 1 = ROs running; 0 = powered down */
    output wire [31:0] data_out, /* FIFO output word */
    output wire        data_valid,/* 1 if data_out is valid */
    input  wire        data_rd,  /* pulse to consume one word from FIFO */
    output reg         trng_dead,/* 1 if BIST timeout expired */
    output wire [7:0]  fill_count /* current FIFO fill level */
);

/* ── Ring oscillator A (11 stages) ────────────────────────────── */
wire [10:0] ro_a_chain;
assign ro_a_chain[0] = ro_a_chain[10]; /* close the ring */

genvar i;
generate
    for (i = 0; i < `RO_A_STAGES; i = i + 1) begin : ro_a_gen
        (* keep *) LUT4 #(.INIT(16'h5555))  /* LUT4 as inverter: A -> ~A */
            ro_a_lut (
                .A(ro_a_chain[i]),
                .B(1'b0), .C(1'b0), .D(1'b0),
                .Z(ro_a_chain[(i+1) % `RO_A_STAGES])
            );
    end
endgenerate

/* ── Ring oscillator B (13 stages) ────────────────────────────── */
wire [12:0] ro_b_chain;
assign ro_b_chain[0] = ro_b_chain[12];

generate
    for (i = 0; i < `RO_B_STAGES; i = i + 1) begin : ro_b_gen
        (* keep *) LUT4 #(.INIT(16'h5555))
            ro_b_lut (
                .A(ro_b_chain[i]),
                .B(1'b0), .C(1'b0), .D(1'b0),
                .Z(ro_b_chain[(i+1) % `RO_B_STAGES])
            );
    end
endgenerate

/* ── XOR combiner + sampling ───────────────────────────────────── */
/*
 * Sample XOR of the two RO outputs using clk_s.
 * The XOR increases entropy density by combining two independent
 * jitter sources. Two synchronisation flip-flops prevent metastability
 * from propagating into the shift register.
 */
wire        ro_xor;
reg         sync_ff1, sync_ff2;   /* metastability resolution */
reg [31:0]  shift_reg;
reg [4:0]   bit_count;            /* count to 32, then write to FIFO */

assign ro_xor = ro_a_chain[5] ^ ro_b_chain[6]; /* tap mid-chain */

always @(posedge clk_s or negedge rst_n) begin
    if (!rst_n) begin
        sync_ff1  <= 1'b0;
        sync_ff2  <= 1'b0;
        shift_reg <= 32'h0;
        bit_count <= 5'h0;
    end else if (enable) begin
        /* Two-stage synchroniser */
        sync_ff1 <= ro_xor;
        sync_ff2 <= sync_ff1;
        /* Shift sampled bit into accumulator */
        shift_reg <= {sync_ff2, shift_reg[31:1]};
        bit_count <= bit_count + 1;
    end
end

/* Write a 32-bit word to FIFO every 32 sample clocks */
wire fifo_wr = (bit_count == 5'h1F) & enable;

/* ── Output FIFO ───────────────────────────────────────────────── */
/*
 * Simple synchronous FIFO. Safe because all read/write happen in
 * clk_s domain; MMIO reads cross domains in trng_top.v.
 */
reg [31:0]  fifo_mem [0:FIFO_DEPTH-1];
reg [$clog2(FIFO_DEPTH):0] fifo_wr_ptr;
reg [$clog2(FIFO_DEPTH):0] fifo_rd_ptr;
wire fifo_full  = (fifo_wr_ptr - fifo_rd_ptr) == FIFO_DEPTH[($clog2(FIFO_DEPTH)):0];
wire fifo_empty = (fifo_wr_ptr == fifo_rd_ptr);

always @(posedge clk_s or negedge rst_n) begin
    if (!rst_n) begin
        fifo_wr_ptr <= 0;
    end else if (fifo_wr && !fifo_full) begin
        fifo_mem[fifo_wr_ptr[$clog2(FIFO_DEPTH)-1:0]] <= shift_reg;
        fifo_wr_ptr <= fifo_wr_ptr + 1;
    end
end

always @(posedge clk_s or negedge rst_n) begin
    if (!rst_n) begin
        fifo_rd_ptr <= 0;
    end else if (data_rd && !fifo_empty) begin
        fifo_rd_ptr <= fifo_rd_ptr + 1;
    end
end

assign data_out   = fifo_mem[fifo_rd_ptr[$clog2(FIFO_DEPTH)-1:0]];
assign data_valid = !fifo_empty;
assign fill_count = (fifo_wr_ptr - fifo_rd_ptr)[$clog2(FIFO_DEPTH):0];

/* ── BIST: monitor fill rate ───────────────────────────────────── */
/*
 * If the FIFO fill count does not increase within BIST_TIMEOUT clk_s
 * cycles, the ROs are likely stuck (power issue, synthesis optimized
 * them out despite KEEP, or hardware fault). Assert trng_dead.
 */
reg [31:0] bist_counter;
reg [$clog2(FIFO_DEPTH):0] last_fill;

always @(posedge clk_s or negedge rst_n) begin
    if (!rst_n) begin
        bist_counter <= 32'h0;
        last_fill    <= 0;
        trng_dead    <= 1'b0;
    end else begin
        if (fill_count != last_fill[$clog2(FIFO_DEPTH):0]) begin
            /* Fill changed: ROs are alive */
            bist_counter <= 32'h0;
            last_fill    <= fill_count;
            trng_dead    <= 1'b0;
        end else begin
            bist_counter <= bist_counter + 1;
            if (bist_counter >= `BIST_TIMEOUT)
                trng_dead <= 1'b1;
        end
    end
end

endmodule
