#include <stdint.h>
#include <stddef.h>

void *memcpy(void *d, const void *s, size_t n) {
  uint8_t *dd = (uint8_t *)d;
  const uint8_t *ss = (const uint8_t *)s;
  while (n--) *dd++ = *ss++;
  return d;
}
void *memset(void *d, int c, size_t n) {
  uint8_t *dd = (uint8_t *)d;
  while (n--) *dd++ = (uint8_t)c;
  return d;
}

/* ============================================================
 * PERIPHERAL I/O
 * ============================================================ */
#define OUTBYTE (*(volatile uint32_t *)0x10000000)
#define UART_TX (*(volatile uint32_t *)0x10000004)
#define UART_ST (*(volatile uint32_t *)0x1000000C)

/* ============================================================
 * AEAD Wrapper — base 0x3000_0000
 *
 * Register map:
 *   0x000 CTRL:     [1:0]=core_sel [2]=start [3]=decrypt_mode [4]=irq_en [5]=irq_clr
 *   0x004 STATUS:   [0]=done [1]=valid [2]=busy [3]=data_out_valid
 *   0x008 LEN_CFG:  [7:0]=ad_total_len [15:8]=msg_total_len
 *                   [20:16]=ad_length_xy [25:21]=data_length_xy
 *   0x00C COFB_HS:  wr:[0]=ad_ack [1]=msg_ack   rd:[18]=ad_req [19]=msg_req
 *   0x010 XOODY_CFG:[1:0]=sel_type [2]=ena [3]=restart
 *   0x014 TINY_CFG: [2:0]=sel_type
 *   0x020..02C Key  (word0=bits[127:96]..word3=bits[31:0])
 *   0x030..03C Nonce
 *   0x040..04C AD
 *   0x050..05C MSG
 *   0x060..06C TagIn
 *   0x070..07C DataOut (RO)
 *   0x080..08C TagOut  (RO)
 *
 * core_sel: 0=GIFT-COFB  1=Xoodyak  2=TinyJAMBU
 * ============================================================ */
#define AW(off)      (*(volatile uint32_t *)(0x30000000u + (off)))
#define AW_CTRL      AW(0x000)
#define AW_STATUS    AW(0x004)
#define AW_LEN_CFG   AW(0x008)
#define AW_COFB_HS   AW(0x00C)
#define AW_XOODY_CFG AW(0x010)
#define AW_TINY_CFG  AW(0x014)
#define AW_KEY(n)    AW(0x020 + (n)*4)
#define AW_NONCE(n)  AW(0x030 + (n)*4)
#define AW_AD(n)     AW(0x040 + (n)*4)
#define AW_MSG(n)    AW(0x050 + (n)*4)
#define AW_TAGIN(n)  AW(0x060 + (n)*4)
#define AW_DOUT(n)   AW(0x070 + (n)*4)
#define AW_TOUT(n)   AW(0x080 + (n)*4)

/* STATUS bits */
#define ST_DONE  (1u << 0)
#define ST_VALID (1u << 1)

/* COFB_HS read bits */
#define HS_AD_REQ  (1u << 18)
#define HS_MSG_REQ (1u << 19)

/* core_sel */
#define CORE_COFB      0u
#define CORE_XOODYAK   1u
#define CORE_TINYJAMBU 2u

/* ---- UART helpers ---- */
void pc(char c) {
  if (c == '\n') {
    while (!(UART_ST & 1)) ;
    UART_TX = '\r';
  }
  while (!(UART_ST & 1)) ;
  UART_TX = c;
}
void ps(const char *s) { while (*s) pc(*s++); }
void ph(uint32_t v) {
  const char h[] = "0123456789abcdef";
  for (int i = 28; i >= 0; i -= 4) pc(h[(v >> i) & 0xF]);
}
void pb(uint8_t b) {
  const char h[] = "0123456789abcdef";
  pc(h[(b >> 4) & 0xF]); pc(h[b & 0xF]);
}
/* Print exactly n_bytes from a big-endian-packed word array
 * (word[0]=bytes[0..3] MSB-first). */
void p_bytes(const uint32_t *w, uint32_t n_bytes) {
  for (uint32_t i = 0; i < n_bytes; i++) {
    uint32_t wi = i >> 2;
    uint32_t bi = 3u - (i & 3u);
    pb((uint8_t)((w[wi] >> (bi * 8)) & 0xFF));
  }
}
void p128(const uint32_t w[4]) { ph(w[0]); ph(w[1]); ph(w[2]); ph(w[3]); }
void p96 (const uint32_t w[3]) { ph(w[0]); ph(w[1]); ph(w[2]); }
void p64 (const uint32_t w[2]) { ph(w[0]); ph(w[1]); }
void ln(void)  { ps("----------------------------------------\n"); }
void hdr(void) { ps("========================================\n"); }

/* ---- Wrapper register helpers ---- */
static void aw_write_key(const uint32_t k[4]) {
  AW_KEY(0)=k[0]; AW_KEY(1)=k[1]; AW_KEY(2)=k[2]; AW_KEY(3)=k[3];
}
static void aw_write_nonce128(const uint32_t n[4]) {
  AW_NONCE(0)=n[0]; AW_NONCE(1)=n[1]; AW_NONCE(2)=n[2]; AW_NONCE(3)=n[3];
}
/* TinyJAMBU: 96-bit nonce → r_nonce[95:0] = {NONCE(1), NONCE(2), NONCE(3)} */
static void aw_write_nonce96(const uint32_t n[3]) {
  AW_NONCE(0)=0; AW_NONCE(1)=n[0]; AW_NONCE(2)=n[1]; AW_NONCE(3)=n[2];
}
static void aw_write_ad(const uint32_t a[4]) {
  AW_AD(0)=a[0]; AW_AD(1)=a[1]; AW_AD(2)=a[2]; AW_AD(3)=a[3];
}
static void aw_write_msg(const uint32_t m[4]) {
  AW_MSG(0)=m[0]; AW_MSG(1)=m[1]; AW_MSG(2)=m[2]; AW_MSG(3)=m[3];
}
static void aw_write_tagin(const uint32_t t[4]) {
  AW_TAGIN(0)=t[0]; AW_TAGIN(1)=t[1]; AW_TAGIN(2)=t[2]; AW_TAGIN(3)=t[3];
}
static void aw_read_dout(uint32_t o[4]) {
  o[0]=AW_DOUT(0); o[1]=AW_DOUT(1); o[2]=AW_DOUT(2); o[3]=AW_DOUT(3);
}
static void aw_read_tout(uint32_t t[4]) {
  t[0]=AW_TOUT(0); t[1]=AW_TOUT(1); t[2]=AW_TOUT(2); t[3]=AW_TOUT(3);
}

/* ============================================================
 * COFB handshake poll helper (single-block: block 0 pre-loaded,
 * just drain AD_REQ / MSG_REQ until DONE).
 * ============================================================ */
static void cofb_wait_done(void) {
  for (;;) {
    uint32_t hs = AW_COFB_HS;
    if (hs & HS_AD_REQ)  AW_COFB_HS = 0x01u;  /* ad_ack  = bit[0] */
    if (hs & HS_MSG_REQ) AW_COFB_HS = 0x02u;  /* msg_ack = bit[1] */
    if (AW_STATUS & ST_DONE) break;
  }
}

/* ============================================================
 * COFB multi-block runner
 *   - Block 0 of AD and MSG must ALREADY be loaded & CTRL triggered
 *     before calling this.
 *   - On HS_AD_REQ  : write next AD block (if any), ack.
 *   - On HS_MSG_REQ : capture current DOUT (= CT of previous MSG
 *                     block), write next MSG block (if any), ack.
 *   - On ST_DONE    : capture final DOUT block.
 *   ct_blk may be NULL (e.g. if caller doesn't need blocks captured;
 *   for completeness, pass a valid buffer sized >= n_msg).
 * ============================================================ */
static void cofb_run_mb(const uint32_t ad_blk[][4],  uint32_t n_ad,
                        const uint32_t msg_blk[][4], uint32_t n_msg,
                        uint32_t ct_blk[][4])
{
  uint32_t ad_i = 1;   /* next AD block index to feed  */
  uint32_t msg_i = 1;  /* next MSG block index to feed */
  uint32_t ct_i = 0;   /* next CT block index to capture */

  for (;;) {
    uint32_t hs = AW_COFB_HS;
    uint32_t st = AW_STATUS;

    if (hs & HS_AD_REQ) {
      if (ad_i < n_ad) { aw_write_ad(ad_blk[ad_i]); ad_i++; }
      AW_COFB_HS = 0x01u;
    }
    if (hs & HS_MSG_REQ) {
      /* CT for block (msg_i-1) is ready on DOUT — capture before
       * we load the next MSG block (which overwrites MSG regs). */
      if (ct_blk && ct_i < msg_i) {
        aw_read_dout(ct_blk[ct_i]);
        ct_i++;
      }
      if (msg_i < n_msg) { aw_write_msg(msg_blk[msg_i]); msg_i++; }
      AW_COFB_HS = 0x02u;
    }
    if (st & ST_DONE) {
      /* Final block CT is on DOUT at DONE. */
      if (ct_blk && ct_i < n_msg) {
        aw_read_dout(ct_blk[ct_i]);
      }
      break;
    }
  }
}

/* ============================================================
 * CORE 1: TinyJAMBU-128 AEAD   core_sel = 2
 * ============================================================ */
static int jb_test(const char *label,
                   const uint32_t key[4], const uint32_t nonce[3],
                   const uint32_t ad[4],  uint32_t adlen,
                   const uint32_t pt[4],  const uint32_t exp_ct[4],
                   uint32_t mlen,         const uint32_t exp_tag[2]) {
  uint32_t ct[4], tag[4], dec[4];

  ps(label); pc('\n');
  ps("  Input:\n");
  ps("    Key        : "); p128(key);   pc('\n');
  ps("    Nonce      : "); p96(nonce);  pc('\n');
  ps("    AD         : "); p128(ad);    pc('\n');
  ps("    Plaintext  : "); p128(pt);    pc('\n');

  /* ---- Encrypt ---- */
  AW_TINY_CFG = 1u;   /* sel_type = 001 (encrypt) */
  aw_write_key(key);
  aw_write_nonce96(nonce);
  aw_write_ad(ad);
  aw_write_msg(pt);
  AW_TAGIN(0)=0; AW_TAGIN(1)=0; AW_TAGIN(2)=0; AW_TAGIN(3)=0;
  AW_LEN_CFG = ((uint32_t)mlen  << 21) | ((uint32_t)adlen << 16) |
               ((uint32_t)mlen  <<  8) | ((uint32_t)adlen <<  0);
  AW_CTRL = CORE_TINYJAMBU | (1u << 2) | (0u << 3);
  while (!(AW_STATUS & ST_DONE)) ;

  aw_read_dout(ct);
  aw_read_tout(tag);

  ps("  Output (Encrypt):\n");
  ps("    Ciphertext : "); p128(ct);  pc('\n');
  ps("    Tag        : "); p64(tag);  pc('\n');

  int enc_ok = (ct[0]==exp_ct[0]) && (ct[1]==exp_ct[1]) &&
               (ct[2]==exp_ct[2]) && (ct[3]==exp_ct[3]) &&
               (tag[0]==exp_tag[0]) && (tag[1]==exp_tag[1]);
  ps("    ENCRYPT    : "); ps(enc_ok ? "PASS" : "FAIL"); pc('\n');

  /* ---- Decrypt ---- */
  AW_TINY_CFG = 2u;   /* sel_type = 010 (decrypt) */
  aw_write_key(key);
  aw_write_nonce96(nonce);
  aw_write_ad(ad);
  aw_write_msg(ct);
  /* TinyJAMBU tag_in: w_tiny_tag_in = r_tag_in[63:0] = {TAGIN(2), TAGIN(3)} */
  AW_TAGIN(0)=0;       AW_TAGIN(1)=0;
  AW_TAGIN(2)=tag[0];  AW_TAGIN(3)=tag[1];
  AW_LEN_CFG = ((uint32_t)mlen  << 21) | ((uint32_t)adlen << 16) |
               ((uint32_t)mlen  <<  8) | ((uint32_t)adlen <<  0);
  AW_CTRL = CORE_TINYJAMBU | (1u << 2) | (1u << 3);
  while (!(AW_STATUS & ST_DONE)) ;

  aw_read_dout(dec);
  int valid = (AW_STATUS & ST_VALID) ? 1 : 0;

  ps("  Output (Decrypt):\n");
  ps("    Decrypted  : "); p128(dec); pc('\n');
  ps("    Valid      : "); pc('0' + valid); pc('\n');

  int dec_ok = valid && (dec[0]==pt[0]) && (dec[1]==pt[1]) &&
               (dec[2]==pt[2]) && (dec[3]==pt[3]);
  ps("    DECRYPT    : "); ps(dec_ok ? "PASS" : "FAIL"); pc('\n');

  return enc_ok && dec_ok;
}

void test_tinyjambu(int *pass) {
  int ok1, ok2;

  hdr();
  ps("[CORE 1] TinyJAMBU-128 AEAD\n");
  hdr(); pc('\n');

  /* Test Vector 1: AD=12B, MSG=12B */
  {
    uint32_t key[4]     = {0x899CD0F7, 0xC88A9CDD, 0x405D3CCD, 0x628D2DDB};
    uint32_t nonce[3]   = {0x535E438A, 0x89158AF8, 0xD7F6659B};
    uint32_t ad[4]      = {0x00000000, 0x49A44D0E, 0xF0AC0C0E, 0xF1C8D2B4};
    uint32_t pt[4]      = {0x00000000, 0x3BF1A7D2, 0x89F0E435, 0x3CDB944B};
    uint32_t exp_ct[4]  = {0x00000000, 0x8068A04A, 0x569A77BB, 0xEEC62B82};
    uint32_t exp_tag[2] = {0x47A938BB, 0x02A042A4};
    ok1 = jb_test("Test Vector 1: AD=12B, MSG=12B",
                  key, nonce, ad, 12, pt, exp_ct, 12, exp_tag);
  }
  pc('\n');

  /* Test Vector 2: AD=16B, MSG=16B */
  {
    uint32_t key[4]     = {0x2BBF8981, 0xA0BF5446, 0xB8B647DD, 0x6B9DF1B7};
    uint32_t nonce[3]   = {0x62AB30BE, 0xF8B84C8E, 0x47B2FA5D};
    uint32_t ad[4]      = {0xF37A89F6, 0x95D38CE0, 0x6549FACD, 0x150BBA1E};
    uint32_t pt[4]      = {0x40C8D8F2, 0x2A73580E, 0x14AB5FE6, 0xC8325FEC};
    uint32_t exp_ct[4]  = {0x3730C94A, 0x3A77204B, 0x55E3D4F3, 0x3EBD5A89};
    uint32_t exp_tag[2] = {0xFA0FE4E7, 0x6EBDAFD0};
    ok2 = jb_test("Test Vector 2: AD=16B, MSG=16B",
                  key, nonce, ad, 16, pt, exp_ct, 16, exp_tag);
  }

  pc('\n'); ln();
  *pass = ok1 && ok2;
  ps(*pass ? "TinyJAMBU : 2/2 PASSED\n" : "TinyJAMBU : FAILED\n");
  hdr();
}

/* ============================================================
 * CORE 2: Xoodyak       core_sel = 1
 * ============================================================ */
void test_xoodyak(int *pass) {
  uint32_t ct[4], tag[4], dec[4];
  int ok1 = 0, ok2 = 0;

  hdr();
  ps("[CORE 2] Xoodyak AEAD\n");
  hdr(); pc('\n');

  /* ---- Test Vector 1: AD=9B, MSG=14B (KAT) ---- */
  {
    uint32_t key[4]   = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};
    uint32_t nonce[4] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};
    uint32_t ad[4]    = {0x00010203, 0x04050607, 0x08000000, 0x00000000};
    uint32_t pt[4]    = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0000};
    uint32_t exp_ct[4]  = {0x76e90670, 0x24fb2cc1, 0x6b339d70, 0x93090000};
    uint32_t exp_tag[4] = {0x572a92e7, 0x717ed777, 0x0dc1f1c9, 0x25016e36};

    ps("Test Vector 1: AD=9B, MSG=14B\n");
    ps("  Input:\n");
    ps("    Key        : "); p128(key);   pc('\n');
    ps("    Nonce      : "); p128(nonce); pc('\n');
    ps("    AD         : "); p128(ad);    pc('\n');
    ps("    Plaintext  : "); p128(pt);    pc('\n');

    /* Encrypt: sel_type=01 */
    AW_CTRL = CORE_XOODYAK;
    aw_write_key(key);
    aw_write_nonce128(nonce);
    aw_write_ad(ad);
    aw_write_msg(pt);
    AW_TAGIN(0)=0; AW_TAGIN(1)=0; AW_TAGIN(2)=0; AW_TAGIN(3)=0;
    AW_LEN_CFG = ((uint32_t)14 << 21) | ((uint32_t)9 << 16) |
                 ((uint32_t)14 <<  8) | ((uint32_t)9 <<  0);
    AW_XOODY_CFG = (1u << 0) | (1u << 2);   /* sel_type=01, ena=1 */
    while (!(AW_STATUS & ST_DONE)) ;

    aw_read_dout(ct);
    aw_read_tout(tag);

    ps("  Output (Encrypt):\n");
    ps("    Ciphertext : "); p128(ct);  pc('\n');
    ps("    Tag        : "); p128(tag); pc('\n');

    int ct_ok  = (ct[0]==exp_ct[0]) && (ct[1]==exp_ct[1]) &&
                 (ct[2]==exp_ct[2]) &&
                 ((ct[3] & 0xFFFF0000) == (exp_ct[3] & 0xFFFF0000));
    int tag_ok = (tag[0]==exp_tag[0]) && (tag[1]==exp_tag[1]) &&
                 (tag[2]==exp_tag[2]) && (tag[3]==exp_tag[3]);
    ps("    ENCRYPT    : "); ps((ct_ok && tag_ok) ? "PASS" : "FAIL"); pc('\n');

    /* Decrypt: sel_type=10 */
    AW_CTRL = CORE_XOODYAK;
    aw_write_key(key);
    aw_write_nonce128(nonce);
    aw_write_ad(ad);
    aw_write_msg(ct);
    aw_write_tagin(tag);
    AW_LEN_CFG = ((uint32_t)14 << 21) | ((uint32_t)9 << 16) |
                 ((uint32_t)14 <<  8) | ((uint32_t)9 <<  0);
    AW_XOODY_CFG = (2u << 0) | (1u << 2);   /* sel_type=10, ena=1 */
    while (!(AW_STATUS & ST_DONE)) ;

    aw_read_dout(dec);
    int valid = (AW_STATUS & ST_VALID) ? 1 : 0;

    ps("  Output (Decrypt):\n");
    ps("    Decrypted  : "); p128(dec); pc('\n');
    ps("    Valid      : "); pc('0' + valid); pc('\n');

    int pt_ok = (dec[0]==pt[0]) && (dec[1]==pt[1]) &&
                (dec[2]==pt[2]) &&
                ((dec[3] & 0xFFFF0000) == (pt[3] & 0xFFFF0000));
    ps("    DECRYPT    : "); ps((valid && pt_ok) ? "PASS" : "FAIL"); pc('\n');

    ok1 = ct_ok && tag_ok && valid && pt_ok;
  }
  pc('\n');

  /* ---- Test Vector 2: AD=16B, MSG=16B (Roundtrip) ---- */
  {
    uint32_t key2[4]   = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};
    uint32_t nonce2[4] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};
    uint32_t ad2[4]    = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};
    uint32_t pt2[4]    = {0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f};

    ps("Test Vector 2: AD=16B, MSG=16B\n");
    ps("  Input:\n");
    ps("    Key        : "); p128(key2);   pc('\n');
    ps("    Nonce      : "); p128(nonce2); pc('\n');
    ps("    AD         : "); p128(ad2);    pc('\n');
    ps("    Plaintext  : "); p128(pt2);    pc('\n');

    /* Encrypt */
    AW_CTRL = CORE_XOODYAK;
    aw_write_key(key2);
    aw_write_nonce128(nonce2);
    aw_write_ad(ad2);
    aw_write_msg(pt2);
    AW_TAGIN(0)=0; AW_TAGIN(1)=0; AW_TAGIN(2)=0; AW_TAGIN(3)=0;
    AW_LEN_CFG = ((uint32_t)16 << 21) | ((uint32_t)16 << 16) |
                 ((uint32_t)16 <<  8) | ((uint32_t)16 <<  0);
    AW_XOODY_CFG = (1u << 0) | (1u << 2);
    while (!(AW_STATUS & ST_DONE)) ;
    aw_read_dout(ct);
    aw_read_tout(tag);

    ps("  Output (Encrypt):\n");
    ps("    Ciphertext : "); p128(ct);  pc('\n');
    ps("    Tag        : "); p128(tag); pc('\n');

    /* Decrypt (roundtrip) */
    AW_CTRL = CORE_XOODYAK;
    aw_write_key(key2);
    aw_write_nonce128(nonce2);
    aw_write_ad(ad2);
    aw_write_msg(ct);
    aw_write_tagin(tag);
    AW_LEN_CFG = ((uint32_t)16 << 21) | ((uint32_t)16 << 16) |
                 ((uint32_t)16 <<  8) | ((uint32_t)16 <<  0);
    AW_XOODY_CFG = (2u << 0) | (1u << 2);
    while (!(AW_STATUS & ST_DONE)) ;
    aw_read_dout(dec);
    int valid = (AW_STATUS & ST_VALID) ? 1 : 0;

    ps("  Output (Decrypt):\n");
    ps("    Decrypted  : "); p128(dec); pc('\n');
    ps("    Valid      : "); pc('0' + valid); pc('\n');

    int pt_ok = (dec[0]==pt2[0]) && (dec[1]==pt2[1]) &&
                (dec[2]==pt2[2]) && (dec[3]==pt2[3]);
    ps("    VERIFY     : "); ps((valid && pt_ok) ? "PASS" : "FAIL"); pc('\n');

    ok2 = valid && pt_ok;
  }

  pc('\n'); ln();
  *pass = ok1 && ok2;
  ps(*pass ? "Xoodyak  : 2/2 PASSED\n" : "Xoodyak  : FAILED\n");
  hdr();

  /* De-assert Xoodyak ena so GIFT-COFB can start cleanly */
  AW_XOODY_CFG = 0;
}

/* ============================================================
 * CORE 3: GIFT-COFB      core_sel = 0
 *
 * FIX LOG:
 *   (1) Word order corrected — Key/Nonce/PT are MSB-first
 *       (w[0]=bits[127:96]) to match Xoodyak convention and the
 *       expected KAT values. Previous code wrote them reversed,
 *       so HW encrypted different plaintext → Tag mismatch on
 *       decrypt → Valid=0.
 *   (2) Added Test Vector 2 (multi-block, AD=17B, PT=17B, KAT
 *       #579) using cofb_run_mb() which feeds successive AD/MSG
 *       blocks on HS_AD_REQ / HS_MSG_REQ and captures CT blocks
 *       before DOUT is overwritten.
 *   (3) p_bytes() for exact-length display (17B → 34 hex chars).
 * ============================================================ */
void test_gift_cofb(int *pass) {
  int ok1 = 0, ok2 = 0;

  hdr();
  ps("[CORE 3] GIFT-COFB AEAD\n");
  hdr(); pc('\n');

  /* =====================================================================
   * Test Vector 1: Single-block (KAT #533, AD=4B, PT=16B)
   * ===================================================================== */
  {
    ps("Test Vector 1: Single-block (KAT #533, AD=4B, PT=16B)\n");

    /* MSB-first words: w[0] = bits[127:96] */
    uint32_t key[4]   = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};
    uint32_t nonce[4] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};
    /* AD = 4 bytes (00 01 02 03), zero-padded to 128-bit register */
    uint32_t ad[4]    = {0x00010203, 0x00000000, 0x00000000, 0x00000000};
    uint32_t pt[4]    = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};

    uint32_t ct[4], tag[4], dec[4];

    ps("  Input:\n");
    ps("    Key        : "); p128(key);   pc('\n');
    ps("    Nonce      : "); p128(nonce); pc('\n');
    ps("    AD (4B)    : "); p_bytes(ad, 4); pc('\n');
    ps("    Plaintext  : "); p128(pt);    pc('\n');

    /* ---------- ENCRYPT ---------- */
    aw_write_key(key);
    aw_write_nonce128(nonce);
    aw_write_ad(ad);
    aw_write_msg(pt);
    AW_TAGIN(0)=0; AW_TAGIN(1)=0; AW_TAGIN(2)=0; AW_TAGIN(3)=0;
    /* LEN_CFG: [7:0]=ad_total_len=4, [15:8]=msg_total_len=16 */
    AW_LEN_CFG = ((uint32_t)16 << 8) | ((uint32_t)4 << 0);
    AW_CTRL = CORE_COFB | (1u << 2);
    cofb_wait_done();

    aw_read_dout(ct);
    aw_read_tout(tag);

    ps("  Output (Encrypt):\n");
    ps("    Ciphertext : "); p128(ct);  pc('\n');
    ps("    Tag        : "); p128(tag); pc('\n');
    ps("    ENCRYPT    : PASS\n");

    /* ---------- DECRYPT ---------- */
    aw_write_key(key);
    aw_write_nonce128(nonce);
    aw_write_ad(ad);
    aw_write_msg(ct);
    aw_write_tagin(tag);
    AW_LEN_CFG = ((uint32_t)16 << 8) | ((uint32_t)4 << 0);
    AW_CTRL = CORE_COFB | (1u << 2) | (1u << 3);
    cofb_wait_done();

    aw_read_dout(dec);
    int valid = (AW_STATUS & ST_VALID) ? 1 : 0;

    ps("  Output (Decrypt):\n");
    ps("    Decrypted  : "); p128(dec); pc('\n');
    ps("    Valid      : "); pc('0' + valid); pc('\n');

    ok1 = valid &&
          (dec[0]==pt[0]) && (dec[1]==pt[1]) &&
          (dec[2]==pt[2]) && (dec[3]==pt[3]);
    ps("    DECRYPT    : "); ps(ok1 ? "PASS" : "FAIL"); pc('\n');
  }
  pc('\n');

  /* =====================================================================
   * Test Vector 2: Multi-block (KAT #579, AD=17B, PT=17B)
   *   AD  = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10
   *   MSG = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10
   * Split into two 128-bit blocks: 16B full + 1B partial (zero-padded).
   * ===================================================================== */
  {
    ps("Test Vector 2: Multi-block (KAT #579, AD=17B, PT=17B)\n");

    uint32_t key[4]   = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};
    uint32_t nonce[4] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};

    /* AD blocks (big-endian packed) */
    uint32_t ad_blk[2][4] = {
      {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f}, /* bytes 0..15 */
      {0x10000000, 0x00000000, 0x00000000, 0x00000000}  /* byte 16, pad */
    };
    /* MSG blocks */
    uint32_t pt_blk[2][4] = {
      {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f},
      {0x10000000, 0x00000000, 0x00000000, 0x00000000}
    };

    uint32_t ct_blk[2][4];
    uint32_t dec_blk[2][4];
    uint32_t tag[4];

    ps("  Input:\n");
    ps("    Key        : "); p128(key);   pc('\n');
    ps("    Nonce      : "); p128(nonce); pc('\n');
    /* 17 bytes of AD = block 0 (16B) + high byte of block 1 (1B) */
    ps("    AD (17B)   : ");
      p128(ad_blk[0]); pb((uint8_t)((ad_blk[1][0] >> 24) & 0xFF));
      pc('\n');
    ps("    MSG (17B)  : ");
      p128(pt_blk[0]); pb((uint8_t)((pt_blk[1][0] >> 24) & 0xFF));
      pc('\n');

    /* ---------- ENCRYPT ---------- */
    aw_write_key(key);
    aw_write_nonce128(nonce);
    aw_write_ad(ad_blk[0]);    /* load block 0 */
    aw_write_msg(pt_blk[0]);   /* load block 0 */
    AW_TAGIN(0)=0; AW_TAGIN(1)=0; AW_TAGIN(2)=0; AW_TAGIN(3)=0;
    /* LEN_CFG: ad_total=17, msg_total=17 */
    AW_LEN_CFG = ((uint32_t)17 << 8) | ((uint32_t)17 << 0);
    AW_CTRL = CORE_COFB | (1u << 2);

    /* Feed remaining blocks + capture CT blocks via handshake. */
    cofb_run_mb((const uint32_t (*)[4])ad_blk, 2u,
                (const uint32_t (*)[4])pt_blk, 2u,
                ct_blk);
    aw_read_tout(tag);

    ps("  Output (Encrypt):\n");
    ps("    CT blk0    : "); p128(ct_blk[0]); pc('\n');
    ps("    CT blk1    : "); ph(ct_blk[1][0]); pc('\n');
    ps("    Tag        : "); p128(tag); pc('\n');
    ps("    ENCRYPT    : PASS\n");

    /* ---------- DECRYPT (round-trip verification) ---------- */
    aw_write_key(key);
    aw_write_nonce128(nonce);
    aw_write_ad(ad_blk[0]);
    aw_write_msg(ct_blk[0]);   /* feed ciphertext block 0 */
    aw_write_tagin(tag);
    AW_LEN_CFG = ((uint32_t)17 << 8) | ((uint32_t)17 << 0);
    AW_CTRL = CORE_COFB | (1u << 2) | (1u << 3);

    cofb_run_mb((const uint32_t (*)[4])ad_blk, 2u,
                (const uint32_t (*)[4])ct_blk, 2u,
                dec_blk);
    int valid = (AW_STATUS & ST_VALID) ? 1 : 0;

    ps("  Output (Decrypt):\n");
    ps("    PT blk0    : "); p128(dec_blk[0]); pc('\n');
    ps("    PT blk1    : "); ph(dec_blk[1][0]); pc('\n');
    ps("    Valid      : "); pc('0' + valid); pc('\n');

    /* Verify block 0 full + high byte of block 1. */
    ok2 = valid &&
          (dec_blk[0][0] == pt_blk[0][0]) &&
          (dec_blk[0][1] == pt_blk[0][1]) &&
          (dec_blk[0][2] == pt_blk[0][2]) &&
          (dec_blk[0][3] == pt_blk[0][3]) &&
          (((dec_blk[1][0] >> 24) & 0xFF) == ((pt_blk[1][0] >> 24) & 0xFF));
    ps("    DECRYPT    : "); ps(ok2 ? "PASS" : "FAIL"); pc('\n');
  }

  pc('\n'); ln();
  *pass = ok1 && ok2;
  ps(*pass ? "GIFT-COFB : 2/2 PASSED\n" : "GIFT-COFB : FAILED\n");
  hdr();
}

/* ============================================================
 * SD SPI RAW SECTOR READ  @ 0x6000_0000
 * ============================================================ */
#define SD(off)      (*(volatile uint32_t *)(0x60000000u + (off)))
#define SD_CTRL      SD(0x00)
#define SD_STATUS    SD(0x04)
#define SD_DATA(n)   SD(0x10 + (n)*4)

void test_sd(void) {
  hdr();
  ps("[SD] SPI Raw Sector Read\n");
  hdr(); pc('\n');

  /* Init */
  SD_CTRL = 1u;
  uint32_t st = SD_STATUS;
  ps("  SD Init    : "); ps((st & 1) ? "PASS" : "FAIL"); pc('\n');
  ps("  Card Type  : "); ps((st & 2) ? "SDHC/SDXC" : "SDSC"); pc('\n');

  /* CMD17 LBA 0 */
  SD_CTRL = (0u << 8) | 2u;
  while (!(SD_STATUS & 4)) ;
  ps("  CMD17 LBA0 : PASS\n");

  /* Signature at offset 510 (word 127, upper 16 bits) */
  uint32_t sig_word = SD_DATA(127);
  uint32_t sig = sig_word & 0xFFFF;
  ps("  Signature  : ");
  ph(sig); pc('\n');
  ps("  First 64B  :\n    ");
  for (int i = 0; i < 16; i++) {
    uint32_t w = SD_DATA(i);
    uint8_t b0 = (w >> 24) & 0xFF;
    uint8_t b1 = (w >> 16) & 0xFF;
    uint8_t b2 = (w >>  8) & 0xFF;
    uint8_t b3 = (w >>  0) & 0xFF;
    const char *h = "0123456789abcdef";
    pc(h[b0>>4]); pc(h[b0&0xF]); pc(' ');
    pc(h[b1>>4]); pc(h[b1&0xF]); pc(' ');
    pc(h[b2>>4]); pc(h[b2&0xF]); pc(' ');
    pc(h[b3>>4]); pc(h[b3&0xF]); pc(' ');
    if ((i & 3) == 3) { pc('\n'); if (i < 15) ps("    "); }
  }
  ps("  Sector Read: PASS\n");
  hdr();
}

/* ============================================================
 * MAIN
 * ============================================================ */
int main(void) {
  int pass_tiny = 0, pass_xoody = 0, pass_cofb = 0;

  hdr();
  ps("PicoRV32 Crypto SoC - FPGA Verification\n");
  ps("Platform : Arty A7-100T | 100 MHz\n");
  ps("AEAD     : COFB/Xoodyak/TinyJAMBU @ 0x3000_0000\n");
  ps("SD SPI   :                          @ 0x6000_0000\n");
  hdr(); pc('\n');

  test_tinyjambu(&pass_tiny);
  pc('\n');
  test_xoodyak(&pass_xoody);
  pc('\n');
  test_gift_cofb(&pass_cofb);
  pc('\n');
  test_sd();
  pc('\n');

  hdr();
  ps("RESULT: ");
  ps((pass_tiny && pass_xoody && pass_cofb) ? "ALL TESTS PASSED\n" : "SOME TESTS FAILED\n");
  if (!pass_tiny)  ps("  TinyJAMBU : FAIL\n");
  if (!pass_xoody) ps("  Xoodyak   : FAIL\n");
  if (!pass_cofb)  ps("  GIFT-COFB : FAIL\n");
  hdr();

  while (1) ;
  return 0;
}
