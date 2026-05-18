foliage_apc — Foliage-style APC sleep mask
=============================================

Similar to ekko_timer but designed around APC queue concept.
Thread blocks on NtWaitForSingleObject (clean ntdll stack).
Memory encrypted with XOR-16, permissions set to RW.

Difference from ekko_timer:
  - Resolves NtQueueApcThread (future: full APC chain)
  - Falls back to NtWaitForSingleObject-based wait
  - Different code structure (split protect/encrypt helpers)

Build:
  cd kit\sleepmask
  build_mask.bat masks\foliage_apc\mask.c

  artifact-gen ... --mask mask.bin ...
