no_mask — transparent sleep (no obfuscation)
==============================================

Does NOT encrypt beacon memory. Simply calls NtDelayExecution.

Use cases:
  - Debugging: beacon stays readable in WinDbg/x64dbg
  - Lab/CTF: no EDR to evade
  - Performance baseline
  - Verifying mask kit infrastructure

WARNING: in-memory scanners will match beacon signatures during sleep.
Do NOT use in any environment with active endpoint protection.

Build:
  cd kit\sleepmask
  build_mask.bat masks\no_mask\mask.c

  artifact-gen ... --mask mask.bin ...
