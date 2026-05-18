// Polymorphic transforms applied to the stub blob at generation time.
//
// 1. Stub-size placeholder is patched (4 bytes, sentinel 0xA5A5A501).
// 2. AES key + XOR mask + IV slots randomized.
// 3. Structural polymorphism: every NOP-region between sentinel pairs
//    [CC CC DE AD <id>] ... [CC CC BE EF <id>] is filled with a fresh
//    random sequence of valid x86/x64 NOP-equivalents whose total length
//    matches exactly. Sentinel markers themselves stay in place so that
//    different regenerations keep the same stub size.
#include "poly.h"
#include "rng.h"

static const uint8_t SENT_KEY[16] = {
    0xC0,0xDE,0xC0,0xDE,0xC0,0xDE,0xC0,0xDE,
    0xC0,0xDE,0xC0,0xDE,0xC0,0xDE,0xC0,0xDE
};
static const uint8_t SENT_IV[16] = {
    0xBA,0xAD,0xF0,0x0D,0xBA,0xAD,0xF0,0x0D,
    0xBA,0xAD,0xF0,0x0D,0xBA,0xAD,0xF0,0x0D
};
static const uint8_t SENT_MASK[16] = {
    0xF0,0x0D,0xBE,0xEF,0xF0,0x0D,0xBE,0xEF,
    0xF0,0x0D,0xBE,0xEF,0xF0,0x0D,0xBE,0xEF
};

static int find_seq(const uint8_t* hay, uint32_t hay_len, uint32_t from,
                    const uint8_t* needle, uint32_t n_len) {
    if (hay_len < n_len) return -1;
    for (uint32_t i = from; i + n_len <= hay_len; ++i) {
        uint32_t j = 0;
        while (j < n_len && hay[i + j] == needle[j]) ++j;
        if (j == n_len) return (int)i;
    }
    return -1;
}

// NOP-equivalent sequences. Indexed by length 1..9. Each variant must be
// architecture-neutral (works under both x86 and x64 in 32-bit/64-bit code
// at .text level — these specific encodings are the recommended NOPs from
// the Intel SDM, and Microsoft's own assembler emits them).
//
// Lengths and encodings:
//  1: 90
//  2: 66 90
//  3: 0F 1F 00
//  4: 0F 1F 40 00
//  5: 0F 1F 44 00 00
//  6: 66 0F 1F 44 00 00
//  7: 0F 1F 80 00 00 00 00
//  8: 0F 1F 84 00 00 00 00 00
//  9: 66 0F 1F 84 00 00 00 00 00
static const uint8_t NOP1[1] = { 0x90 };
static const uint8_t NOP2[2] = { 0x66, 0x90 };
static const uint8_t NOP3[3] = { 0x0F, 0x1F, 0x00 };
static const uint8_t NOP4[4] = { 0x0F, 0x1F, 0x40, 0x00 };
static const uint8_t NOP5[5] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
static const uint8_t NOP6[6] = { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
static const uint8_t NOP7[7] = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t NOP8[8] = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t NOP9[9] = { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const uint8_t* NOPS[10] = { 0, NOP1, NOP2, NOP3, NOP4, NOP5, NOP6, NOP7, NOP8, NOP9 };

// Fills `dst` with a random sequence of NOPs whose total length is exactly
// `len`. Picks lengths 1..9 uniformly except when fewer bytes remain.
static void fill_nop_region(uint8_t* dst, uint32_t len) {
    uint32_t off = 0;
    while (off < len) {
        uint32_t remain = len - off;
        uint32_t max = remain > 9 ? 9 : remain;
        uint32_t pick = (rng_u32() % max) + 1;
        for (uint32_t i = 0; i < pick; ++i) dst[off + i] = NOPS[pick][i];
        off += pick;
    }
}

// Patches every POLY region. A region is bracketed by:
//   begin: CC CC DE AD <id>   (5 bytes)
//   end:   CC CC BE EF <id>   (5 bytes)
// where <id> matches between the pair. Bytes strictly between the two
// markers are overwritten with random NOP-equivalents.
// Begin/end markers are 16 bytes each: a 15-byte unique header (extremely
// unlikely to appear by chance in compiled code) followed by a 1-byte id.
static const uint8_t POLY_BEGIN_HDR[15] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE
};
static const uint8_t POLY_END_HDR[15] = {
    0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,0x77,
    0x66,0x55,0x44,0x33,0x22,0x11,0x00
};

static int matches_hdr(const uint8_t* p, const uint8_t* hdr) {
    for (int i = 0; i < 15; ++i) if (p[i] != hdr[i]) return 0;
    return 1;
}

static void patch_poly_regions(uint8_t* stub, uint32_t stub_size) {
    uint32_t i = 0;
    while (i + 16 <= stub_size) {
        if (matches_hdr(stub + i, POLY_BEGIN_HDR)) {
            uint8_t id = stub[i + 15];
            for (uint32_t j = i + 16; j + 16 <= stub_size; ++j) {
                if (matches_hdr(stub + j, POLY_END_HDR) && stub[j + 15] == id) {
                    uint32_t total_off = i;
                    uint32_t total_len = (j + 16) - i;
                    fill_nop_region(stub + total_off, total_len);
                    i = j + 16;
                    goto next_region;
                }
            }
            break;
        }
        ++i;
        continue;
    next_region:
        continue;
    }
}

int poly_patch_stub(uint8_t* stub, uint32_t buf_len, uint32_t runtime_size,
                    const uint8_t key[16], const uint8_t iv[16]) {
    int found_size = -1;
    for (uint32_t i = 0; i + 4 <= buf_len; ++i) {
        if (stub[i] == 0x01 && stub[i+1] == 0xA5 &&
            stub[i+2] == 0xA5 && stub[i+3] == 0xA5) {
            found_size = (int)i; break;
        }
    }
    if (found_size < 0) return -1;
    stub[found_size + 0] = (uint8_t)(runtime_size       & 0xFF);
    stub[found_size + 1] = (uint8_t)((runtime_size >>  8) & 0xFF);
    stub[found_size + 2] = (uint8_t)((runtime_size >> 16) & 0xFF);
    stub[found_size + 3] = (uint8_t)((runtime_size >> 24) & 0xFF);

    uint8_t mask[16];
    if (rng_fill(mask, 16) != 0) return -10;

    int kp = find_seq(stub, buf_len, 0, SENT_KEY, 16);
    if (kp < 0) return -2;
    for (int i = 0; i < 16; ++i) stub[kp + i] = (uint8_t)(key[i] ^ mask[i]);

    int mp = find_seq(stub, buf_len, 0, SENT_MASK, 16);
    if (mp < 0) return -4;
    for (int i = 0; i < 16; ++i) stub[mp + i] = mask[i];

    int ip = find_seq(stub, buf_len, 0, SENT_IV, 16);
    if (ip < 0) return -3;
    for (int i = 0; i < 16; ++i) stub[ip + i] = iv[i];

    patch_poly_regions(stub, buf_len);
    return 0;
}
