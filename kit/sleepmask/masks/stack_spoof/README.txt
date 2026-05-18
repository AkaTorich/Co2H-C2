stack_spoof — Return-address spoofing sleep mask
==================================================

Before entering wait, overwrites the thread's return address
with a RET gadget address inside ntdll.dll. When a stack-walking
tool inspects the sleeping thread:

  Visible stack:
    ntdll!NtWaitForSingleObject
    ntdll!.text+0xNNN  (RET gadget)

  Instead of:
    ntdll!NtWaitForSingleObject
    beacon!.slpmsk+0xNN  (suspicious private module)

After waking, the real return address is restored before return.

Combines: XOR-16 encryption + stack forgery + NtWaitForSingleObject.

Limitations:
  - x64 only (_AddressOfReturnAddress intrinsic)
  - Simple single-frame spoof (not a full synthetic stack)
  - CET/Shadow Stack environments may detect the mismatch

Build:
  cd kit\sleepmask
  build_mask.bat masks\stack_spoof\mask.c

  artifact-gen ... --mask mask.bin ...
