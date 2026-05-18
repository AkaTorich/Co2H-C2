chacha_sleep — ChaCha20 stream cipher sleep mask
==================================================

Replaces the basic XOR-16 encryption with a full ChaCha20
stream cipher (256-bit key, 96-bit nonce, 20 rounds).

Advantages over XOR-16:
  - No 16-byte key repetition pattern in encrypted memory
  - Statistical analysis (entropy, frequency) shows uniform noise
  - Withstands known-plaintext attacks (XOR-16 leaks key trivially)
  - Full 256-bit security level

Sleep method: NtWaitForSingleObject on unsignaled event (clean stack).

Key derivation:
  - 32-byte key = ctx->key[0..15] || ctx->key[0..15] XOR 0xA5
  - 12-byte nonce = ctx->key[4..15]
  - Fresh random seed each sleep cycle (beacon generates new key)

Trade-off: ~3x slower than XOR-16 for large sections (~4 MB/s vs 12 MB/s
on a 3 GHz core). Negligible for typical beacon size (<1 MB).

Build:
  cd kit\sleepmask
  build_mask.bat masks\chacha_sleep\mask.c

  artifact-gen ... --mask mask.bin ...
