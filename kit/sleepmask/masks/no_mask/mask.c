// no_mask — transparent sleep without any obfuscation.
//
// This mask does NOT encrypt beacon memory during sleep.
// Useful for:
//   - Debugging (beacon stays readable in memory)
//   - Environments without EDR/AV (lab, CTF)
//   - Performance testing (no crypto overhead)
//   - Verifying that the sleep mask infrastructure works
//
// The beacon simply sleeps via NtDelayExecution.
// Memory permissions are NOT changed.
//
// WARNING: beacon code stays RX and unencrypted — any in-memory
// scanner will trivially match signatures during sleep.

#include "../../sleep_mask_api.h"

void __cdecl sleep_mask_entry(SleepMaskCtx* ctx) {
    LARGE_INTEGER delay;
    delay.QuadPart = -(LONGLONG)ctx->sleep_ms * 10000LL;
    ctx->NtDelayExecution(FALSE, &delay);
}
