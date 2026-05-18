ekko_timer — Ekko-style sleep mask
====================================

Thread blocks on NtWaitForSingleObject with an unsignaled event.
Memory is encrypted (XOR-16) and marked PAGE_READWRITE during sleep.

Stack at scan time:
  ntdll!NtWaitForSingleObject
  (no beacon frames visible)

Detection surface:
  - Unsignaled event with timeout = sleep_ms
  - Thread blocked in NtWaitForSingleObject outside main module

Build:
  cd kit\sleepmask
  build_mask.bat masks\ekko_timer\mask.c

  artifact-gen ... --mask mask.bin ...
